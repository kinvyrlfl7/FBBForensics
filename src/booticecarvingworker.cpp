#include "booticecarvingworker.h"

#include "imagereader.h"
#include "signaturecarver.h"
#include "showcaseanalyzer.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QSet>
#include <QVariant>

#include <algorithm>
#include <optional>

namespace
{
constexpr qint64 CarvingScanWindowBytes = qint64(256) * 1024 * 1024;
constexpr qint64 CarvingScanOverlapBytes = qint64(16) * 1024 * 1024;

struct BooticeFat32Layout
{
    quint64 volumeStartLba = 0;
    quint64 dataStartLba = 0;
    quint16 bytesPerSector = 512;
    quint8 sectorsPerCluster = 1;
};

struct BooticeCarveRange
{
    quint64 startCluster = 0;
    quint64 endCluster = 0;
    quint64 startLba = 0;
    quint64 endLba = 0;
};

struct DeletedBooticeEntry
{
    QString name;
    quint64 startCluster = 0;
    quint64 fileSize = 0;
};

struct SqlConnectionCleanup
{
    QString name;

    ~SqlConnectionCleanup()
    {
        if (!name.isEmpty() && QSqlDatabase::contains(name)) {
            QSqlDatabase::removeDatabase(name);
        }
    }
};

QString sanitizedFileName(QString name)
{
    name = name.trimmed();
    if (name.isEmpty()) {
        name = QStringLiteral("bootice_deleted_file");
    }
    name.replace(QLatin1Char('?'), QLatin1Char('_'));
    const QString invalid = QStringLiteral("<>:\"/\\|?*");
    for (const QChar ch : invalid) {
        name.replace(ch, QLatin1Char('_'));
    }
    while (name.endsWith(QLatin1Char('.')) || name.endsWith(QLatin1Char(' '))) {
        name.chop(1);
    }
    return name.isEmpty() ? QStringLiteral("bootice_deleted_file") : name;
}

QString uniqueOutputPath(const QString &directory, const QString &fileName)
{
    QDir dir(directory);
    const QFileInfo info(sanitizedFileName(fileName));
    const QString completeSuffix = info.completeSuffix();
    const QString baseName = info.completeBaseName().isEmpty() ? info.baseName() : info.completeBaseName();
    const QString cleanBase = baseName.isEmpty() ? QStringLiteral("bootice_deleted_file") : baseName;
    const QString suffixPart = completeSuffix.isEmpty() ? QString() : QStringLiteral(".%1").arg(completeSuffix);

    QString candidate = dir.filePath(cleanBase + suffixPart);
    int index = 1;
    while (QFileInfo::exists(candidate)) {
        candidate = dir.filePath(QStringLiteral("%1_%2%3").arg(cleanBase).arg(index++, 3, 10, QLatin1Char('0')).arg(suffixPart));
    }
    return candidate;
}

QString sha256ForFile(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);
    while (!file.atEnd()) {
        hash.addData(file.read(1024 * 1024));
    }
    return QString::fromLatin1(hash.result().toHex());
}

QString formatMiB(quint64 bytes)
{
    return QString::number(double(bytes) / (1024.0 * 1024.0), 'f', 1);
}

int rangeProgress(int startProgress, int endProgress, int rangeIndex, int rangeCount, double fraction)
{
    if (rangeCount <= 0) {
        return startProgress;
    }
    const double clamped = std::max(0.0, std::min(1.0, fraction));
    const double perRange = double(endProgress - startProgress) / double(rangeCount);
    const double value = double(startProgress) + perRange * double(rangeIndex - 1) + perRange * clamped;
    return qBound(startProgress, int(value), endProgress);
}

int carvingConfidenceRank(const QString &confidence)
{
    if (confidence.compare(QStringLiteral("High"), Qt::CaseInsensitive) == 0) {
        return 3;
    }
    if (confidence.compare(QStringLiteral("Medium"), Qt::CaseInsensitive) == 0) {
        return 2;
    }
    if (confidence.compare(QStringLiteral("Low"), Qt::CaseInsensitive) == 0) {
        return 1;
    }
    return 0;
}

void appendCarvedNonOverlapping(QVector<CarvedFile> *target, QVector<CarvedFile> source)
{
    std::sort(source.begin(), source.end(), [](const CarvedFile &left, const CarvedFile &right) {
        if (left.logicalStart == right.logicalStart) {
            const int leftRank = carvingConfidenceRank(left.confidence);
            const int rightRank = carvingConfidenceRank(right.confidence);
            if (leftRank != rightRank) {
                return leftRank > rightRank;
            }
            return left.logicalEnd > right.logicalEnd;
        }
        return left.logicalStart < right.logicalStart;
    });

    for (const CarvedFile &file : source) {
        if (!target->isEmpty() && file.logicalStart <= target->last().logicalEnd) {
            const int fileRank = carvingConfidenceRank(file.confidence);
            const CarvedFile &last = target->last();
            const int lastRank = carvingConfidenceRank(last.confidence);
            const quint64 fileSize = file.logicalEnd >= file.logicalStart ? file.logicalEnd - file.logicalStart : 0;
            const quint64 lastSize = last.logicalEnd >= last.logicalStart ? last.logicalEnd - last.logicalStart : 0;
            if (fileRank > lastRank || (file.logicalStart == last.logicalStart && fileRank == lastRank && fileSize > lastSize)) {
                target->last() = file;
            }
            continue;
        }
        target->append(file);
    }
}

QString rangeName(const BooticeCarveRange &range)
{
    return QStringLiteral("Bootice_%1_%2")
        .arg(range.startCluster, 10, 10, QLatin1Char('0'))
        .arg(range.endCluster, 10, 10, QLatin1Char('0'));
}

QList<BooticeCarveRange> subtractCoveredClusters(QList<BooticeCarveRange> ranges, const QList<BooticeCarveRange> &covered)
{
    for (const BooticeCarveRange &used : covered) {
        QList<BooticeCarveRange> nextRanges;
        for (const BooticeCarveRange &range : ranges) {
            if (used.endCluster < range.startCluster || used.startCluster > range.endCluster) {
                nextRanges.append(range);
                continue;
            }

            if (used.startCluster > range.startCluster) {
                BooticeCarveRange left = range;
                left.endCluster = used.startCluster - 1;
                const quint64 leftClusters = left.endCluster - left.startCluster + 1ULL;
                left.endLba = left.startLba + leftClusters * (range.endLba - range.startLba + 1ULL) / (range.endCluster - range.startCluster + 1ULL) - 1ULL;
                nextRanges.append(left);
            }
            if (used.endCluster < range.endCluster) {
                BooticeCarveRange right = range;
                right.startCluster = used.endCluster + 1;
                const quint64 sectorsPerCluster = (range.endLba - range.startLba + 1ULL) / (range.endCluster - range.startCluster + 1ULL);
                right.startLba = range.startLba + (right.startCluster - range.startCluster) * sectorsPerCluster;
                nextRanges.append(right);
            }
        }
        ranges = nextRanges;
    }
    return ranges;
}

bool ensureCarvedTable(QSqlDatabase &db, QString *errorMessage)
{
    QSqlQuery create(db);
    if (!create.exec(QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Bootice_Carved_Files ("
            "Id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "Source_Start_Cluster INTEGER,"
            "Source_End_Cluster INTEGER,"
            "Source_Start_LBA INTEGER,"
            "Source_End_LBA INTEGER,"
            "Logical_Image_Path TEXT,"
            "Logical_Start_Offset INTEGER,"
            "Logical_End_Offset INTEGER,"
            "File_Name TEXT,"
            "File_Extension TEXT,"
            "File_Size INTEGER,"
            "Sha256 TEXT,"
            "Output_Path TEXT,"
            "Carver TEXT,"
            "Validation_Result TEXT,"
            "Confidence TEXT,"
            "Status TEXT,"
            "Notes TEXT)"))) {
        if (errorMessage) {
            *errorMessage = create.lastError().text();
        }
        return false;
    }
    const QSqlRecord carvedSchema = db.record(QStringLiteral("Bootice_Carved_Files"));
    if (carvedSchema.indexOf(QStringLiteral("Logical_Image_Path")) < 0) {
        QSqlQuery alter(db);
        if (!alter.exec(QStringLiteral("ALTER TABLE Bootice_Carved_Files ADD COLUMN Logical_Image_Path TEXT"))) {
            if (errorMessage) {
                *errorMessage = alter.lastError().text();
            }
            return false;
        }
    }
    return true;
}

bool ensureCandidateTable(QSqlDatabase &db, QString *errorMessage)
{
    QSqlQuery create(db);
    if (!create.exec(QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Bootice_Carving_Candidates ("
            "Id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "Source_Start_Cluster INTEGER,"
            "Source_End_Cluster INTEGER,"
            "Source_Start_LBA INTEGER,"
            "Source_End_LBA INTEGER,"
            "Logical_Image_Path TEXT,"
            "Logical_Offset INTEGER,"
            "Signature_Family TEXT,"
            "Signature_Hex TEXT,"
            "Expected_Extension TEXT,"
            "Expected_Type TEXT,"
            "Candidate_Status TEXT,"
            "Parser_Result TEXT,"
            "Carved_File_Id INTEGER,"
            "Attempted_Methods TEXT,"
            "Selected_Method TEXT,"
            "Reject_Reason TEXT,"
            "Notes TEXT)"))) {
        if (errorMessage) {
            *errorMessage = create.lastError().text();
        }
        return false;
    }
    QSqlQuery index(db);
    index.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS idx_bootice_carving_candidates_offset ON Bootice_Carving_Candidates(Logical_Image_Path, Logical_Offset, Signature_Family)"));
    return true;
}

qint64 insertCandidateRow(QSqlDatabase &db,
                          const BooticeCarveRange &range,
                          const QString &logicalImage,
                          quint64 logicalOffset,
                          const QString &family,
                          const QString &signatureHex,
                          const QString &expectedExtension,
                          const QString &expectedType,
                          const QString &status,
                          const QString &parserResult,
                          const QString &notes)
{
    QSqlQuery insert(db);
    insert.prepare(QStringLiteral(
        "INSERT INTO Bootice_Carving_Candidates("
        "Source_Start_Cluster, Source_End_Cluster, Source_Start_LBA, Source_End_LBA, Logical_Image_Path, Logical_Offset, "
        "Signature_Family, Signature_Hex, Expected_Extension, Expected_Type, Candidate_Status, Parser_Result, Notes"
        ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"));
    insert.addBindValue(range.startCluster);
    insert.addBindValue(range.endCluster);
    insert.addBindValue(range.startLba);
    insert.addBindValue(range.endLba);
    insert.addBindValue(logicalImage);
    insert.addBindValue(logicalOffset);
    insert.addBindValue(family);
    insert.addBindValue(signatureHex);
    insert.addBindValue(expectedExtension);
    insert.addBindValue(expectedType);
    insert.addBindValue(status);
    insert.addBindValue(parserResult);
    insert.addBindValue(notes);
    if (!insert.exec()) {
        return -1;
    }
    return insert.lastInsertId().toLongLong();
}

void updateCandidateRow(QSqlDatabase &db,
                        qint64 candidateId,
                        const QString &status,
                        const QString &parserResult,
                        qint64 carvedFileId,
                        const QString &attemptedMethods,
                        const QString &selectedMethod,
                        const QString &rejectReason,
                        const QString &notes)
{
    if (candidateId < 0) {
        return;
    }
    QSqlQuery update(db);
    update.prepare(QStringLiteral(
        "UPDATE Bootice_Carving_Candidates "
        "SET Candidate_Status=?, Parser_Result=?, Carved_File_Id=?, Attempted_Methods=?, Selected_Method=?, Reject_Reason=?, Notes=? "
        "WHERE Id=?"));
    update.addBindValue(status);
    update.addBindValue(parserResult);
    update.addBindValue(carvedFileId > 0 ? QVariant(carvedFileId) : QVariant());
    update.addBindValue(attemptedMethods);
    update.addBindValue(selectedMethod);
    update.addBindValue(rejectReason);
    update.addBindValue(notes);
    update.addBindValue(candidateId);
    update.exec();
}

qint64 insertCarvedRow(QSqlDatabase &db,
                       const BooticeCarveRange &range,
                       const QString &logicalImage,
                       const QFileInfo &fileInfo,
                       quint64 logicalStart,
                       quint64 logicalEnd,
                       const QString &carver,
                       const QString &validationResult,
                       const QString &confidence,
                       const QString &status,
                       const QString &notes,
                       QString *errorMessage)
{
    QSqlQuery insert(db);
    insert.prepare(QStringLiteral(
        "INSERT INTO Bootice_Carved_Files("
        "Source_Start_Cluster, Source_End_Cluster, Source_Start_LBA, Source_End_LBA, Logical_Image_Path, Logical_Start_Offset, Logical_End_Offset, "
        "File_Name, File_Extension, File_Size, Sha256, Output_Path, Carver, Validation_Result, Confidence, Status, Notes"
        ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"));
    insert.addBindValue(range.startCluster);
    insert.addBindValue(range.endCluster);
    insert.addBindValue(range.startLba);
    insert.addBindValue(range.endLba);
    insert.addBindValue(logicalImage);
    insert.addBindValue(logicalStart);
    insert.addBindValue(logicalEnd);
    insert.addBindValue(fileInfo.exists() ? fileInfo.fileName() : QString());
    insert.addBindValue(fileInfo.exists() ? fileInfo.suffix().toLower() : QString());
    insert.addBindValue(fileInfo.exists() ? fileInfo.size() : 0);
    insert.addBindValue(fileInfo.exists() ? sha256ForFile(fileInfo.absoluteFilePath()) : QString());
    insert.addBindValue(fileInfo.exists() ? fileInfo.absoluteFilePath() : QString());
    insert.addBindValue(carver);
    insert.addBindValue(validationResult);
    insert.addBindValue(confidence);
    insert.addBindValue(status);
    insert.addBindValue(notes);
    if (!insert.exec()) {
        if (errorMessage) {
            *errorMessage = insert.lastError().text();
        }
        return -1;
    }
    return insert.lastInsertId().toLongLong();
}

bool copySourceRangeToFile(ImageReader &reader,
                           quint64 physicalStart,
                           quint64 byteCount,
                           const QString &outputPath,
                           const std::shared_ptr<std::atomic_bool> &cancelRequested,
                           QString *errorMessage)
{
    QFile output(outputPath);
    if (!output.open(QIODevice::WriteOnly)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to create carved file: %1").arg(output.errorString());
        }
        return false;
    }

    constexpr quint64 CopyChunkBytes = 8ULL * 1024ULL * 1024ULL;
    quint64 copied = 0;
    while (copied < byteCount) {
        if (cancelRequested && cancelRequested->load()) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Carving cancelled while writing carved file.");
            }
            return false;
        }
        const quint64 bytesToRead = qMin<quint64>(CopyChunkBytes, byteCount - copied);
        const QByteArray chunk = reader.read(physicalStart + copied, bytesToRead, errorMessage);
        if (quint64(chunk.size()) != bytesToRead) {
            return false;
        }
        if (output.write(chunk) != chunk.size()) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Unable to write carved file: %1").arg(output.errorString());
            }
            return false;
        }
        copied += bytesToRead;
    }
    return true;
}

QString detectFastExtension(const QByteArray &data)
{
    if (data.startsWith(QByteArray::fromHex("FFD8FF"))) return QStringLiteral("jpg");
    if (data.startsWith(QByteArray::fromHex("89504E470D0A1A0A"))) return QStringLiteral("png");
    if (data.startsWith(QByteArrayLiteral("GIF87a")) || data.startsWith(QByteArrayLiteral("GIF89a"))) return QStringLiteral("gif");
    if (data.startsWith(QByteArrayLiteral("BM"))) return QStringLiteral("bmp");
    if (data.startsWith(QByteArrayLiteral("II*\0")) || data.startsWith(QByteArrayLiteral("MM\0*"))) return QStringLiteral("tif");
    if (data.size() >= 3 && static_cast<uchar>(data[0]) == 0x0A && static_cast<uchar>(data[2]) == 0x01) return QStringLiteral("pcx");
    if (data.startsWith(QByteArrayLiteral("%PDF"))) return QStringLiteral("pdf");
    if (data.startsWith(QByteArray::fromHex("377ABCAF271C"))) return QStringLiteral("7z");
    if (data.startsWith(QByteArrayLiteral("BZh"))) return QStringLiteral("bz2");
    if (data.startsWith(QByteArray::fromHex("1F8B08"))) return QStringLiteral("gz");
    if (data.startsWith(QByteArrayLiteral("Rar!\x1A\x07"))) return QStringLiteral("rar");
    if (data.size() >= 262 && data.mid(257, 5) == QByteArrayLiteral("ustar")) return QStringLiteral("tar");
    if (data.startsWith(QByteArrayLiteral("MSWIM\0\0\0"))) return QStringLiteral("wim");
    if (data.startsWith(QByteArrayLiteral("ID3"))) return QStringLiteral("mp3");
    if (data.startsWith(QByteArray::fromHex("000001BA"))) return QStringLiteral("mpg");
    if (data.startsWith(QByteArrayLiteral(".snd"))) return QStringLiteral("au");
    if (data.size() >= 12 && data.startsWith(QByteArrayLiteral("RIFF")) && data.mid(8, 4) == QByteArrayLiteral("WAVE")) return QStringLiteral("wav");
    if (data.size() >= 12 && data.startsWith(QByteArrayLiteral("RIFF")) && data.mid(8, 4) == QByteArrayLiteral("AVI ")) return QStringLiteral("avi");
    if (data.startsWith(QByteArrayLiteral("FLV"))) return QStringLiteral("flv");
    if (data.size() >= 12 && data.mid(4, 4) == QByteArrayLiteral("ftyp")) {
        return data.mid(8, 4) == QByteArrayLiteral("qt  ") ? QStringLiteral("mov") : QStringLiteral("mp4");
    }
    if (data.startsWith(QByteArray::fromHex("3026B2758E66CF11A6D900AA0062CE6C"))) {
        return data.contains(QByteArray::fromHex("9107DCB7B7A9CF118EE600C00C205365"))
            ? QStringLiteral("wmv")
            : QStringLiteral("wma");
    }
    if (data.startsWith(QByteArray::fromHex("504B0304"))) {
        if (data.contains(QByteArrayLiteral("word/"))) return QStringLiteral("docx");
        if (data.contains(QByteArrayLiteral("xl/"))) return QStringLiteral("xlsx");
        if (data.contains(QByteArrayLiteral("ppt/"))) return QStringLiteral("pptx");
        return QStringLiteral("zip");
    }
    return {};
}

QFileInfo normalizeRecoveredExtension(const QString &path, quint64 scanLimitBytes)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return QFileInfo(path);
    }
    const qint64 bytesToRead = qint64(qMin<quint64>(scanLimitBytes, quint64(file.size())));
    const QByteArray data = file.read(bytesToRead);
    file.close();

    const QString extension = detectFastExtension(data);
    if (extension.isEmpty()) {
        return QFileInfo(path);
    }

    QFileInfo current(path);
    const QString currentSuffix = current.suffix().toLower();
    if ((currentSuffix == QStringLiteral("wma") || currentSuffix == QStringLiteral("wmv"))
        && (extension == QStringLiteral("wma") || extension == QStringLiteral("wmv"))) {
        return current;
    }
    if (current.suffix().compare(extension, Qt::CaseInsensitive) == 0) {
        return current;
    }

    const QString renamed = uniqueOutputPath(
        current.absolutePath(),
        QStringLiteral("%1.%2").arg(current.completeBaseName(), extension));
    if (QFile::rename(path, renamed)) {
        return QFileInfo(renamed);
    }
    return current;
}
}

BooticeCarvingWorker::BooticeCarvingWorker(Params params)
    : m_params(std::move(params))
{
}

BooticeCarvingWorker::Result BooticeCarvingWorker::run(const ProgressCallback &progressCallback, const LogCallback &logCallback)
{
    Result result;
    QString errorMessage;

    auto progress = [&](int value, const QString &message) {
        if (progressCallback) {
            progressCallback(value, message);
        }
    };
    auto log = [&](const QString &message) {
        if (logCallback) {
            logCallback(message);
        }
    };
    auto cancelled = [&]() {
        return m_params.cancelRequested && m_params.cancelRequested->load();
    };

    const QString connectionName = QStringLiteral("bootice_carving_worker_%1").arg(reinterpret_cast<quintptr>(this));
    SqlConnectionCleanup cleanup{connectionName};
    {
        QSqlDatabase db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), connectionName);
        db.setDatabaseName(m_params.booticeDbPath);
        if (!db.open()) {
            result.message = QStringLiteral("Unable to open bootice.db: %1").arg(db.lastError().text());
            return result;
        }
        QSqlQuery pragma(db);
        pragma.exec(QStringLiteral("PRAGMA busy_timeout=30000"));
        pragma.exec(QStringLiteral("PRAGMA journal_mode=WAL"));

        if (!ensureCarvedTable(db, &errorMessage) || !ensureCandidateTable(db, &errorMessage)) {
            result.message = QStringLiteral("Unable to prepare Bootice_Carved_Files: %1").arg(errorMessage);
            db.close();
            return result;
        }
        QSqlQuery clear(db);
        if (!clear.exec(QStringLiteral("DELETE FROM Bootice_Carved_Files"))) {
            result.message = QStringLiteral("Unable to clear Bootice_Carved_Files: %1").arg(clear.lastError().text());
            db.close();
            return result;
        }
        QSqlQuery clearCandidates(db);
        if (!clearCandidates.exec(QStringLiteral("DELETE FROM Bootice_Carving_Candidates"))) {
            result.message = QStringLiteral("Unable to clear Bootice_Carving_Candidates: %1").arg(clearCandidates.lastError().text());
            db.close();
            return result;
        }

        QSqlQuery layoutQuery(db);
        if (!layoutQuery.exec(QStringLiteral(
                "SELECT Volume_Start_LBA, Data_Start_LBA, Bytes_Per_Sector, Sectors_Per_Cluster "
                "FROM Bootice_Fat32_Info LIMIT 1"))
            || !layoutQuery.next()) {
            result.message = QStringLiteral("Bootice FAT32 layout is missing.");
            db.close();
            return result;
        }

        BooticeFat32Layout layout;
        layout.volumeStartLba = layoutQuery.value(0).toULongLong();
        layout.dataStartLba = layoutQuery.value(1).toULongLong();
        layout.bytesPerSector = static_cast<quint16>(layoutQuery.value(2).toUInt());
        layout.sectorsPerCluster = static_cast<quint8>(layoutQuery.value(3).toUInt());
        const quint64 clusterBytes = quint64(layout.bytesPerSector) * layout.sectorsPerCluster;
        if (clusterBytes == 0) {
            result.message = QStringLiteral("Bootice FAT32 cluster size is invalid.");
            db.close();
            return result;
        }

        QList<BooticeCarveRange> ranges;
        QSqlQuery rangeQuery(db);
        if (!rangeQuery.exec(QStringLiteral(
                "SELECT Start_Cluster, End_Cluster, Start_LBA, End_LBA "
                "FROM Bootice_Remaining_Clusters ORDER BY Start_Cluster"))) {
            result.message = QStringLiteral("Unable to query Bootice_Remaining_Clusters: %1").arg(rangeQuery.lastError().text());
            db.close();
            return result;
        }
        while (rangeQuery.next()) {
            ranges.append(BooticeCarveRange{
                rangeQuery.value(0).toULongLong(),
                rangeQuery.value(1).toULongLong(),
                rangeQuery.value(2).toULongLong(),
                rangeQuery.value(3).toULongLong()
            });
        }

        QList<DeletedBooticeEntry> deletedEntries;
        QSqlQuery deletedQuery(db);
        if (deletedQuery.exec(QStringLiteral(
                "SELECT Name_83, Start_Cluster, File_Size "
                "FROM Bootice_Deleted_Files "
                "WHERE Validation_Status='Candidate' AND File_Size > 0 "
                "ORDER BY Start_Cluster"))) {
            while (deletedQuery.next()) {
                deletedEntries.append(DeletedBooticeEntry{
                    deletedQuery.value(0).toString(),
                    deletedQuery.value(1).toULongLong(),
                    deletedQuery.value(2).toULongLong()
                });
            }
        }

        result.rangeCount = ranges.size();
        if (ranges.isEmpty()) {
            result.ok = true;
            result.message = QStringLiteral("No remaining Bootice FAT32 clusters were found.");
            db.close();
            return result;
        }

        std::unique_ptr<ImageReader> reader = ImageReader::create(m_params.sourcePath);
        QString readerError;
        if (!reader || !reader->open(&readerError)) {
            result.message = QStringLiteral("Unable to open source image: %1").arg(readerError);
            db.close();
            return result;
        }

        const QString baseDir = QDir(m_params.outputDir).filePath(QStringLiteral("bootice_carving"));
        const QString runName = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"));
        const QString recoveryDir = QDir(baseDir).filePath(QStringLiteral("fat32_remaining/%1").arg(runName));
        const QString deletedRecoveryDir = QDir(baseDir).filePath(QStringLiteral("deleted_entries/%1").arg(runName));
        QDir().mkpath(recoveryDir);
        QDir().mkpath(deletedRecoveryDir);

        log(QStringLiteral("Bootice FAT32 carving enabled: scanning free cluster ranges only; stride is one FAT32 cluster (%1 bytes).").arg(clusterBytes));
        log(QStringLiteral("Bootice deleted-entry recovery enabled: %1 deleted file entries will be recovered by exact FAT32 metadata before remaining-cluster carving.").arg(deletedEntries.size()));

        SignatureCarver carver;
        QSet<QString> recoveredFingerprints;
        int recoveredCount = 0;
        QList<BooticeCarveRange> deletedCoverage;

        int deletedIndex = 0;
        for (const DeletedBooticeEntry &entry : deletedEntries) {
            if (cancelled()) {
                result.cancelled = true;
                result.message = QStringLiteral("Bootice FAT32 carving cancelled.");
                db.close();
                return result;
            }
            ++deletedIndex;
            const quint64 clusterCount = (entry.fileSize + clusterBytes - 1ULL) / clusterBytes;
            if (entry.startCluster < 2 || clusterCount == 0) {
                continue;
            }
            const quint64 endCluster = entry.startCluster + clusterCount - 1ULL;
            const quint64 startLba = layout.dataStartLba + (entry.startCluster - 2ULL) * layout.sectorsPerCluster;
            const quint64 endLba = layout.dataStartLba + (endCluster - 1ULL) * layout.sectorsPerCluster - 1ULL;
            const BooticeCarveRange entryRange{entry.startCluster, endCluster, startLba, endLba};
            deletedCoverage.append(entryRange);
            const QString deletedLogicalSource = QStringLiteral("FAT32DeletedEntry:%1").arg(entry.name);
            const qint64 candidateId = insertCandidateRow(db,
                entryRange,
                deletedLogicalSource,
                0,
                QStringLiteral("FAT32DeletedEntry"),
                QStringLiteral("FAT32 metadata"),
                QFileInfo(entry.name).suffix().toLower(),
                QStringLiteral("Deleted directory entry"),
                QStringLiteral("Detected"),
                QStringLiteral("FAT32 deleted directory entry queued for exact-size recovery"),
                QStringLiteral("Start cluster and file size were recovered from the FAT32 directory entry."));

            progress(rangeProgress(0, 15, deletedIndex, qMax(1, deletedEntries.size()), 0.0),
                QStringLiteral("Recovering Bootice deleted file %1/%2: %3")
                    .arg(deletedIndex)
                    .arg(deletedEntries.size())
                    .arg(entry.name));
            const QString outputPath = uniqueOutputPath(deletedRecoveryDir, entry.name);
            const quint64 physicalStart = startLba * layout.bytesPerSector;
            if (!copySourceRangeToFile(*reader, physicalStart, entry.fileSize, outputPath, m_params.cancelRequested, &errorMessage)) {
                const qint64 carvedId = insertCarvedRow(db, entryRange, deletedLogicalSource, QFileInfo(), 0, entry.fileSize > 0 ? entry.fileSize - 1ULL : 0, QStringLiteral("FAT32DeletedEntry"), QStringLiteral("Source read/write failed"), QStringLiteral("None"), QStringLiteral("Failed"), errorMessage, nullptr);
                updateCandidateRow(db, candidateId, QStringLiteral("Failed"), QStringLiteral("Source read/write failed"), carvedId, QStringLiteral("FAT32DeletedEntry"), QStringLiteral("FAT32DeletedEntry+ExactSize"), errorMessage, errorMessage);
                continue;
            }
            const QFileInfo fileInfo = normalizeRecoveredExtension(outputPath, qMin<quint64>(entry.fileSize, 2ULL * 1024ULL * 1024ULL));
            const QString fingerprint = QStringLiteral("%1:%2").arg(fileInfo.size()).arg(sha256ForFile(fileInfo.absoluteFilePath()));
            if (recoveredFingerprints.contains(fingerprint)) {
                QFile::remove(fileInfo.absoluteFilePath());
                updateCandidateRow(db, candidateId, QStringLiteral("DuplicateSkipped"), QStringLiteral("Duplicate recovered file"), -1, QStringLiteral("FAT32DeletedEntry"), QStringLiteral("FAT32DeletedEntry+ExactSize"), QString(), QStringLiteral("Skipped duplicate recovered file with identical size and SHA-256."));
                continue;
            }
            recoveredFingerprints.insert(fingerprint);
            const qint64 carvedId = insertCarvedRow(db, entryRange, deletedLogicalSource, fileInfo, 0, entry.fileSize > 0 ? entry.fileSize - 1ULL : 0, QStringLiteral("FAT32DeletedEntry+ExactSize"), QStringLiteral("Recovered by deleted FAT32 directory entry start cluster and file size"), QStringLiteral("High"), QStringLiteral("Recovered"), QStringLiteral("Exact-size deleted-entry recovery performed before remaining-cluster carving."), nullptr);
            updateCandidateRow(db, candidateId, QStringLiteral("Recovered"), QStringLiteral("Recovered by FAT32 deleted directory entry"), carvedId, QStringLiteral("FAT32DeletedEntry"), QStringLiteral("FAT32DeletedEntry+ExactSize"), QString(), QStringLiteral("Extracted to %1").arg(fileInfo.absoluteFilePath()));
            ++recoveredCount;
        }

        ranges = subtractCoveredClusters(ranges, deletedCoverage);
        log(QStringLiteral("Bootice carving ranges after deleting-entry coverage subtraction: %1 contiguous free-cluster ranges remain.").arg(ranges.size()));

        int processedRanges = 0;

        for (const BooticeCarveRange &range : ranges) {
            if (cancelled()) {
                result.cancelled = true;
                result.message = QStringLiteral("Bootice FAT32 carving cancelled.");
                db.close();
                return result;
            }

            ++processedRanges;
            const QString name = rangeName(range);
            const quint64 rangeBytes = (range.endLba - range.startLba + 1ULL) * layout.bytesPerSector;
            const quint64 rangePhysicalStart = range.startLba * layout.bytesPerSector;
            log(QStringLiteral("Scanning Bootice free-cluster range %1: clusters %2-%3, LBA %4-%5, %6 MiB.")
                .arg(name)
                .arg(range.startCluster)
                .arg(range.endCluster)
                .arg(range.startLba)
                .arg(range.endLba)
                .arg(formatMiB(rangeBytes)));

            QVector<CarvedFile> carvedFiles;
            const int totalWindows = qMax(1, int((qint64(rangeBytes) + CarvingScanWindowBytes - 1) / CarvingScanWindowBytes));
            int windowNumber = 0;
            for (quint64 readOffset = 0; readOffset < rangeBytes; readOffset += quint64(CarvingScanWindowBytes)) {
                if (cancelled()) {
                    result.cancelled = true;
                    result.message = QStringLiteral("Bootice FAT32 carving cancelled.");
                    db.close();
                    return result;
                }
                ++windowNumber;
                const quint64 primaryBytes = qMin<quint64>(quint64(CarvingScanWindowBytes), rangeBytes - readOffset);
                const quint64 bytesToRead = qMin<quint64>(primaryBytes + quint64(CarvingScanOverlapBytes), rangeBytes - readOffset);
                progress(rangeProgress(0, 95, processedRanges, ranges.size(), rangeBytes == 0 ? 1.0 : double(readOffset) / double(rangeBytes)),
                    QStringLiteral("Bootice carving %1: window %2/%3, %4/%5 MiB")
                        .arg(name)
                        .arg(windowNumber)
                        .arg(totalWindows)
                        .arg(formatMiB(readOffset))
                        .arg(formatMiB(rangeBytes)));

                const QByteArray windowData = reader->read(rangePhysicalStart + readOffset, bytesToRead, &errorMessage);
                if (quint64(windowData.size()) != bytesToRead) {
                    log(QStringLiteral("Bootice range read failed for %1 at logical offset %2: %3").arg(name).arg(readOffset).arg(errorMessage));
                    break;
                }

                const QVector<CarveCandidateInfo> candidates = carver.scan(windowData, qsizetype(clusterBytes), readOffset);
                log(QStringLiteral("Bootice candidate scan: range=%1 window=%2/%3 candidates=%4 stride=%5 bytes")
                    .arg(name)
                    .arg(windowNumber)
                    .arg(totalWindows)
                    .arg(candidates.size())
                    .arg(clusterBytes));

                QVector<CarvedFile> windowFiles;
                for (const CarveCandidateInfo &candidate : candidates) {
                    const QString logicalSource = QStringLiteral("BooticeRange:%1").arg(name);
                    const qint64 candidateId = insertCandidateRow(db,
                        range,
                        logicalSource,
                        candidate.logicalOffset,
                        candidate.family,
                        candidate.signatureHex,
                        candidate.expectedExtension,
                        candidate.expectedType,
                        QStringLiteral("Detected"),
                        QStringLiteral("Queued for format validator"),
                        QStringLiteral("Signature candidate indexed from Bootice FAT32 free-cluster range."));
                    CarveCandidateInfo localCandidate = candidate;
                    localCandidate.logicalOffset -= readOffset;
                    std::optional<CarvedFile> carved = carver.validate(windowData, localCandidate);
                    if (!carved.has_value()) {
                        updateCandidateRow(db, candidateId, QStringLiteral("Rejected"), QStringLiteral("Format validator rejected candidate"), -1, QStringLiteral("H/Len -> H/F -> H/Max -> FSB"), QString(), QStringLiteral("No strategy validated this candidate"), QStringLiteral("Signature was detected but did not pass parser validation."));
                        continue;
                    }
                    carved->logicalStart += readOffset;
                    carved->logicalEnd += readOffset;
                    carved->candidateId = candidateId;
                    if (carved->logicalStart < readOffset + primaryBytes) {
                        updateCandidateRow(db, candidateId, QStringLiteral("Validated"), carved->validationResult, -1, carved->attemptedMethods, carved->selectedMethod, QString(), QStringLiteral("Candidate validated as .%1 using %2.").arg(carved->extension, carved->carvingMethod));
                        windowFiles.append(*carved);
                    } else {
                        updateCandidateRow(db, candidateId, QStringLiteral("Rejected"), QStringLiteral("Candidate belongs to overlap tail"), -1, carved->attemptedMethods, carved->selectedMethod, QStringLiteral("Overlap tail candidate"), QStringLiteral("Candidate was validated but skipped because it starts in the overlap region."));
                    }
                }
                appendCarvedNonOverlapping(&carvedFiles, windowFiles);
            }

            int rangeRecovered = 0;
            int fileIndex = 0;
            const QString rangeDir = QDir(recoveryDir).filePath(name);
            QDir().mkpath(rangeDir);
            for (const CarvedFile &carvedFile : carvedFiles) {
                if (cancelled()) {
                    result.cancelled = true;
                    result.message = QStringLiteral("Bootice FAT32 carving cancelled.");
                    db.close();
                    return result;
                }
                const quint64 fileSize = carvedFile.logicalEnd >= carvedFile.logicalStart
                    ? carvedFile.logicalEnd - carvedFile.logicalStart + 1ULL
                    : 0;
                if (fileSize == 0) {
                    continue;
                }
                progress(rangeProgress(95, 99, processedRanges, ranges.size(), carvedFiles.isEmpty() ? 1.0 : double(fileIndex) / double(carvedFiles.size())),
                    QStringLiteral("Writing Bootice carved files for %1: %2/%3").arg(name).arg(fileIndex).arg(carvedFiles.size()));
                const QString fileName = QStringLiteral("%1_%2_%3.%4")
                    .arg(name)
                    .arg(fileIndex++, 4, 10, QLatin1Char('0'))
                    .arg(carvedFile.logicalStart, 10, 10, QLatin1Char('0'))
                    .arg(carvedFile.extension);
                const QString outputPath = QDir(rangeDir).filePath(fileName);
                if (!copySourceRangeToFile(*reader, rangePhysicalStart + carvedFile.logicalStart, fileSize, outputPath, m_params.cancelRequested, &errorMessage)) {
                    const QString logicalSource = QStringLiteral("BooticeRange:%1").arg(name);
                    const qint64 carvedId = insertCarvedRow(db, range, logicalSource, QFileInfo(), carvedFile.logicalStart, carvedFile.logicalEnd, carvedFile.carvingMethod, carvedFile.validationResult, carvedFile.confidence, QStringLiteral("Failed"), errorMessage, nullptr);
                    updateCandidateRow(db, carvedFile.candidateId, QStringLiteral("Failed"), carvedFile.validationResult, carvedId, carvedFile.attemptedMethods, carvedFile.selectedMethod, errorMessage, errorMessage);
                    continue;
                }
                const QFileInfo fileInfo(outputPath);
                const QString fingerprint = QStringLiteral("%1:%2").arg(fileInfo.size()).arg(sha256ForFile(fileInfo.absoluteFilePath()));
                if (recoveredFingerprints.contains(fingerprint)) {
                    QFile::remove(outputPath);
                    updateCandidateRow(db, carvedFile.candidateId, QStringLiteral("DuplicateSkipped"), carvedFile.validationResult, -1, carvedFile.attemptedMethods, carvedFile.selectedMethod, QString(), QStringLiteral("Skipped duplicate recovered file with identical size and SHA-256."));
                    continue;
                }
                recoveredFingerprints.insert(fingerprint);
                const QString logicalSource = QStringLiteral("BooticeRange:%1").arg(name);
                const qint64 carvedId = insertCarvedRow(db, range, logicalSource, fileInfo, carvedFile.logicalStart, carvedFile.logicalEnd, carvedFile.carvingMethod, carvedFile.validationResult, carvedFile.confidence, QStringLiteral("Recovered"), carvedFile.notes, nullptr);
                updateCandidateRow(db, carvedFile.candidateId, QStringLiteral("Recovered"), carvedFile.validationResult, carvedId, carvedFile.attemptedMethods, carvedFile.selectedMethod, QString(), QStringLiteral("Extracted to %1").arg(fileInfo.absoluteFilePath()));
                ++rangeRecovered;
                ++recoveredCount;
            }
            if (rangeRecovered == 0) {
                const QString logicalSource = QStringLiteral("BooticeRange:%1").arg(name);
                insertCarvedRow(db, range, logicalSource, QFileInfo(), 0, 0, QStringLiteral("CandidateScanner"), QStringLiteral("No validated candidates"), QStringLiteral("None"), QStringLiteral("No files recovered"), QStringLiteral("No supported candidate was validated from this free-cluster range."), nullptr);
            }
            log(QStringLiteral("Bootice carving completed for %1: %2 files recovered.").arg(name).arg(rangeRecovered));
        }

        reader->close();
        result.ok = true;
        result.recoveredCount = recoveredCount;
        result.message = QStringLiteral("Bootice FAT32 carving complete. %1 files recovered from %2 free-cluster ranges.").arg(recoveredCount).arg(ranges.size());
        db.close();
    }
    progress(100, QStringLiteral("Bootice FAT32 carving complete"));
    return result;
}
