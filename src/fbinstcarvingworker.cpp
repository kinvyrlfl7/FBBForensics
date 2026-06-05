#include "fbinstcarvingworker.h"

#include "benchmarkrecorder.h"
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
#include <QVector>

#include <algorithm>
#include <optional>

namespace
{
constexpr quint64 CarvingChunkSectors = 8192;
constexpr qint64 CarvingScanWindowBytes = qint64(256) * 1024 * 1024;
constexpr qint64 CarvingScanOverlapBytes = qint64(16) * 1024 * 1024;
constexpr quint64 CrossAreaPrimaryTailSectors = 131072;
constexpr quint64 CrossAreaExtendedHeadSectors = 262144;

struct BenchmarkRunFinishGuard
{
    BenchmarkRecorder *recorder = nullptr;
    QString status = QStringLiteral("Failed");
    QString notes;

    ~BenchmarkRunFinishGuard()
    {
        if (recorder) {
            recorder->finishRun(status, notes);
        }
    }
};

struct FbinstCarveRange
{
    QString areaType;
    quint64 startSector = 0;
    quint64 endSector = 0;
    quint64 primarySectorCount = 0;
    QString signatureHint;
};

QString rangeName(const FbinstCarveRange &range)
{
    const QString suffix = range.signatureHint.isEmpty() ? QStringLiteral("range") : range.signatureHint;
    return QStringLiteral("%1_%2_%3_%4")
        .arg(range.areaType)
        .arg(range.startSector, 10, 10, QLatin1Char('0'))
        .arg(range.endSector, 10, 10, QLatin1Char('0'))
        .arg(suffix);
}

QString rangeAddressSummary(const FbinstCarveRange &range)
{
    return QStringLiteral("Fbinst sectors %1-%2")
        .arg(range.startSector)
        .arg(range.endSector);
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

bool copyLogicalRangeToFile(const QString &logicalImage,
                            quint64 logicalStart,
                            quint64 byteCount,
                            const QString &outputPath,
                            const std::shared_ptr<std::atomic_bool> &cancelRequested,
                            QString *errorMessage)
{
    QFile input(logicalImage);
    if (!input.open(QIODevice::ReadOnly)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to open logical carving image: %1").arg(input.errorString());
        }
        return false;
    }
    if (!input.seek(qint64(logicalStart))) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to seek logical carving image to %1: %2").arg(logicalStart).arg(input.errorString());
        }
        return false;
    }

    QFile output(outputPath);
    if (!output.open(QIODevice::WriteOnly)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to create carved file: %1").arg(output.errorString());
        }
        return false;
    }

    constexpr qint64 CopyBufferBytes = 1024 * 1024;
    quint64 remaining = byteCount;
    while (remaining > 0) {
        if (cancelRequested && cancelRequested->load()) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Carving cancelled while writing carved file.");
            }
            return false;
        }
        const qint64 toRead = qint64(qMin<quint64>(remaining, CopyBufferBytes));
        const QByteArray chunk = input.read(toRead);
        if (chunk.size() != toRead) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Unable to read carved byte range at %1: %2")
                    .arg(logicalStart + (byteCount - remaining))
                    .arg(input.errorString());
            }
            return false;
        }
        if (output.write(chunk) != chunk.size()) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Unable to write carved file: %1").arg(output.errorString());
            }
            return false;
        }
        remaining -= quint64(chunk.size());
    }
    return true;
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

bool ensureCarvedTable(QSqlDatabase &db, QString *errorMessage)
{
    QSqlQuery create(db);
    if (!create.exec(QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Fbinst_Carved_Files ("
            "Id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "Area_Type TEXT,"
            "Source_Start_Sector INTEGER,"
            "Source_End_Sector INTEGER,"
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

    const QStringList requiredColumns{
        QStringLiteral("Logical_Start_Offset"),
        QStringLiteral("Logical_End_Offset"),
        QStringLiteral("Carver"),
        QStringLiteral("Validation_Result"),
        QStringLiteral("Confidence"),
        QStringLiteral("Output_Path")
    };
    const QSqlRecord carvedSchema = db.record(QStringLiteral("Fbinst_Carved_Files"));
    for (const QString &column : requiredColumns) {
        if (carvedSchema.indexOf(column) >= 0) {
            continue;
        }
        const QString type = column == QStringLiteral("Logical_Start_Offset") || column == QStringLiteral("Logical_End_Offset")
            ? QStringLiteral("INTEGER")
            : QStringLiteral("TEXT");
        QSqlQuery alter(db);
        if (!alter.exec(QStringLiteral("ALTER TABLE Fbinst_Carved_Files ADD COLUMN %1 %2").arg(column, type))) {
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
            "CREATE TABLE IF NOT EXISTS Fbinst_Carving_Candidates ("
            "Id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "Area_Type TEXT,"
            "Source_Start_Sector INTEGER,"
            "Source_End_Sector INTEGER,"
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
    const QStringList requiredColumns{
        QStringLiteral("Attempted_Methods"),
        QStringLiteral("Selected_Method"),
        QStringLiteral("Reject_Reason")
    };
    const QSqlRecord candidateSchema = db.record(QStringLiteral("Fbinst_Carving_Candidates"));
    for (const QString &column : requiredColumns) {
        if (candidateSchema.indexOf(column) >= 0) {
            continue;
        }
        QSqlQuery alter(db);
        if (!alter.exec(QStringLiteral("ALTER TABLE Fbinst_Carving_Candidates ADD COLUMN %1 TEXT").arg(column))) {
            if (errorMessage) {
                *errorMessage = alter.lastError().text();
            }
            return false;
        }
    }
    QSqlQuery index(db);
    index.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS idx_fbinst_carving_candidates_offset ON Fbinst_Carving_Candidates(Logical_Image_Path, Logical_Offset, Signature_Family)"));
    return true;
}

qint64 insertCandidateRow(QSqlDatabase &db,
                          const FbinstCarveRange &range,
                          const QString &logicalImage,
                          const CarveCandidateInfo &candidate,
                          const QString &status,
                          const QString &parserResult,
                          const QString &notes)
{
    QSqlQuery insert(db);
    insert.prepare(QStringLiteral(
        "INSERT INTO Fbinst_Carving_Candidates("
        "Area_Type, Source_Start_Sector, Source_End_Sector, Logical_Image_Path, Logical_Offset, "
        "Signature_Family, Signature_Hex, Expected_Extension, Expected_Type, Candidate_Status, Parser_Result, Notes"
        ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"));
    insert.addBindValue(range.areaType);
    insert.addBindValue(range.startSector);
    insert.addBindValue(range.endSector);
    insert.addBindValue(QFileInfo(logicalImage).absoluteFilePath());
    insert.addBindValue(candidate.logicalOffset);
    insert.addBindValue(candidate.family);
    insert.addBindValue(candidate.signatureHex);
    insert.addBindValue(candidate.expectedExtension);
    insert.addBindValue(candidate.expectedType);
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
        "UPDATE Fbinst_Carving_Candidates "
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

bool insertCarvedRow(QSqlDatabase &db,
                     const FbinstCarveRange &range,
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
        "INSERT INTO Fbinst_Carved_Files("
        "Area_Type, Source_Start_Sector, Source_End_Sector, Logical_Image_Path, Logical_Start_Offset, Logical_End_Offset, "
        "File_Name, File_Extension, File_Size, Sha256, Output_Path, Carver, Validation_Result, Confidence, Status, Notes"
        ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"));
    insert.addBindValue(range.areaType);
    insert.addBindValue(range.startSector);
    insert.addBindValue(range.endSector);
    insert.addBindValue(QFileInfo(logicalImage).absoluteFilePath());
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
        return false;
    }
    return true;
}

bool buildLogicalImage(const FbinstCarveRange &range,
                       const QString &logicalImage,
                       int rangeIndex,
                       int rangeCount,
                       ImageReader *reader,
                       const std::shared_ptr<std::atomic_bool> &cancelRequested,
                       const FbinstCarvingWorker::ProgressCallback &progress,
                       QString *errorMessage)
{
    QFile output(logicalImage);
    if (!output.open(QIODevice::WriteOnly)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to create logical carving image: %1").arg(output.errorString());
        }
        return false;
    }

    const quint64 totalSectors = range.endSector >= range.startSector ? range.endSector - range.startSector + 1 : 0;
    quint64 builtSectors = 0;
    for (quint64 chunkStart = range.startSector; chunkStart <= range.endSector;) {
        if (cancelRequested && cancelRequested->load()) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Carving cancelled while building logical image.");
            }
            return false;
        }
        const quint64 sectorsToRead = qMin<quint64>(CarvingChunkSectors, range.endSector - chunkStart + 1);
        const quint64 physicalChunkStart = chunkStart;
        const QByteArray chunkData = reader->read(physicalChunkStart * ShowcaseAnalyzer::SectorSize, sectorsToRead * ShowcaseAnalyzer::SectorSize, errorMessage);
        if (quint64(chunkData.size()) != sectorsToRead * ShowcaseAnalyzer::SectorSize) {
            if (errorMessage && errorMessage->isEmpty()) {
                *errorMessage = QStringLiteral("Unable to read source sectors %1-%2 (relative %3-%4).")
                    .arg(physicalChunkStart)
                    .arg(physicalChunkStart + sectorsToRead - 1)
                    .arg(chunkStart)
                    .arg(chunkStart + sectorsToRead - 1);
            }
            return false;
        }

        if (range.areaType == QStringLiteral("Primary") || range.areaType == QStringLiteral("Combined")) {
            for (quint64 index = 0; index < sectorsToRead; ++index) {
                const char *sectorPtr = chunkData.constData() + qsizetype(index * ShowcaseAnalyzer::SectorSize);
                const quint64 relativeSector = chunkStart + index;
                const qint64 logicalSectorBytes = (range.areaType == QStringLiteral("Primary") || relativeSector < range.primarySectorCount)
                    ? 510
                    : qint64(ShowcaseAnalyzer::SectorSize);
                if (output.write(sectorPtr, logicalSectorBytes) != logicalSectorBytes) {
                    if (errorMessage) {
                        *errorMessage = QStringLiteral("Unable to write logical carving image: %1").arg(output.errorString());
                    }
                    return false;
                }
            }
        } else if (output.write(chunkData) != chunkData.size()) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Unable to write logical carving image: %1").arg(output.errorString());
            }
            return false;
        }
        chunkStart += sectorsToRead;
        builtSectors += sectorsToRead;

        const quint64 builtBytes = builtSectors * ShowcaseAnalyzer::SectorSize;
        const quint64 totalBytes = totalSectors * ShowcaseAnalyzer::SectorSize;
        if (progress) {
            progress(rangeProgress(0, 35, rangeIndex, rangeCount, totalSectors == 0 ? 1.0 : double(builtSectors) / double(totalSectors)),
                QStringLiteral("Building %1 carving image: %2/%3 MiB")
                    .arg(rangeName(range), formatMiB(builtBytes), formatMiB(totalBytes)));
        }
    }
    return true;
}
}

FbinstCarvingWorker::FbinstCarvingWorker(Params params)
    : m_params(std::move(params))
{
}

FbinstCarvingWorker::Result FbinstCarvingWorker::run(const ProgressCallback &progressCallback, const LogCallback &logCallback)
{
    auto log = [&](const QString &message) {
        if (logCallback) {
            logCallback(message);
        }
    };
    auto progress = [&](int value, const QString &message) {
        if (progressCallback) {
            progressCallback(value, message);
        }
    };
    auto cancelled = [&]() {
        return m_params.cancelRequested && m_params.cancelRequested->load();
    };

    BenchmarkRecorder benchmark(m_params.benchmarkDbPath);
    benchmark.beginRun(BenchmarkRecorder::RunConfig{
        QStringLiteral("FbinstTool Remaining Sector Carving"),
        m_params.sourcePath,
        QStringLiteral("FbinstTool"),
        QStringLiteral("Carving"),
        QStringLiteral("Build logical Primary/Extended remaining-sector streams, scan signatures, validate file structure, and write recovered files.")
    });
    BenchmarkRunFinishGuard benchmarkGuard{&benchmark, QStringLiteral("Failed"), QString()};
    BenchmarkStageScope carvingStage(&benchmark, QStringLiteral("Fbinst Remaining Sector Carving"));
    quint64 benchmarkBytesRead = 0;
    quint64 benchmarkBytesWritten = 0;
    quint64 benchmarkItems = 0;
    auto completeBenchmark = [&](const QString &status, const QString &message) {
        carvingStage.addBytesRead(benchmarkBytesRead);
        carvingStage.addBytesWritten(benchmarkBytesWritten);
        carvingStage.addItems(benchmarkItems);
        carvingStage.setStatus(status);
        carvingStage.setNotes(message);
        benchmarkGuard.status = status;
        benchmarkGuard.notes = message;
    };
    auto benchmarkProgress = [&](int value, const QString &message) {
        benchmark.sample(QStringLiteral("Fbinst Remaining Sector Carving"), value, message);
        progress(value, message);
    };

    Result result;
    benchmarkProgress(0, QStringLiteral("Preparing internal signature carving..."));
    log(QStringLiteral("Internal signature carver enabled in background worker thread."));

    const QString connectionName = QStringLiteral("fbinst_carving_worker_%1").arg(reinterpret_cast<quintptr>(this));
    struct ConnectionGuard
    {
        QString name;
        ~ConnectionGuard()
        {
            QSqlDatabase::removeDatabase(name);
        }
    } connectionGuard{connectionName};
    {
        QSqlDatabase db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), connectionName);
        db.setDatabaseName(m_params.fbinstDbPath);
        if (!db.open()) {
            result.message = QStringLiteral("Unable to open fbinsttool.db in worker: %1").arg(db.lastError().text());
            completeBenchmark(QStringLiteral("Failed"), result.message);
            return result;
        }
        QSqlQuery(db).exec(QStringLiteral("PRAGMA busy_timeout=10000"));
        QSqlQuery(db).exec(QStringLiteral("PRAGMA journal_mode=WAL"));

        QString errorMessage;
        if (!ensureCarvedTable(db, &errorMessage) || !ensureCandidateTable(db, &errorMessage)) {
            result.message = QStringLiteral("Unable to prepare Fbinst_Carved_Files: %1").arg(errorMessage);
            db.close();
            completeBenchmark(QStringLiteral("Failed"), result.message);
            return result;
        }

        QSqlQuery clear(db);
        if (!clear.exec(QStringLiteral("DELETE FROM Fbinst_Carved_Files"))) {
            result.message = QStringLiteral("Unable to clear Fbinst_Carved_Files: %1").arg(clear.lastError().text());
            db.close();
            completeBenchmark(QStringLiteral("Failed"), result.message);
            return result;
        }
        QSqlQuery clearCandidates(db);
        if (!clearCandidates.exec(QStringLiteral("DELETE FROM Fbinst_Carving_Candidates"))) {
            result.message = QStringLiteral("Unable to clear Fbinst_Carving_Candidates: %1").arg(clearCandidates.lastError().text());
            db.close();
            completeBenchmark(QStringLiteral("Failed"), result.message);
            return result;
        }

        quint64 primaryDataStartSector = 0;
        quint64 primarySectorCount = 0;
        QSqlQuery metaQuery(db);
        if (!metaQuery.exec(QStringLiteral("SELECT List_Size, Primary_Size FROM Fbinst LIMIT 1")) || !metaQuery.next()) {
            result.message = QStringLiteral("Unable to query Fbinst metadata for data-area base: %1").arg(metaQuery.lastError().text());
            db.close();
            completeBenchmark(QStringLiteral("Failed"), result.message);
            return result;
        }
        primaryDataStartSector = 68ULL + metaQuery.value(0).toULongLong();
        primarySectorCount = metaQuery.value(1).toULongLong();
        log(QStringLiteral("Fbinst data-area layout resolved: Primary data sectors %1-%2, Extended starts at sector %3.")
            .arg(primaryDataStartSector)
            .arg(primarySectorCount > 0 ? primarySectorCount - 1 : 0)
            .arg(primarySectorCount));

        QList<FbinstCarveRange> ranges;
        QSqlQuery query(db);
        if (!query.exec(QStringLiteral(
                "SELECT Area_Type, Sector_Number FROM Fbinst_Remaining_Sectors "
                "ORDER BY CASE Area_Type WHEN 'Primary' THEN 0 WHEN 'Extended' THEN 1 ELSE 2 END, Sector_Number"))) {
            result.message = QStringLiteral("Unable to query Fbinst_Remaining_Sectors: %1").arg(query.lastError().text());
            db.close();
            completeBenchmark(QStringLiteral("Failed"), result.message);
            return result;
        }

        QString currentArea;
        quint64 rangeStart = 0;
        quint64 rangeEnd = 0;
        bool haveRange = false;
        auto flushRange = [&]() {
            if (haveRange) {
                quint64 effectiveStart = rangeStart;
                if (currentArea == QStringLiteral("Primary")) {
                    if (rangeEnd < primaryDataStartSector) {
                        return;
                    }
                    effectiveStart = qMax(rangeStart, primaryDataStartSector);
                }
                if (effectiveStart <= rangeEnd) {
                    ranges.append(FbinstCarveRange{currentArea, effectiveStart, rangeEnd, primarySectorCount});
                }
            }
        };

        while (query.next()) {
            const QString area = query.value(0).toString();
            const quint64 sector = query.value(1).toULongLong();
            if (!haveRange) {
                currentArea = area;
                rangeStart = sector;
                rangeEnd = sector;
                haveRange = true;
                continue;
            }
            if (area == currentArea && sector == rangeEnd + 1) {
                rangeEnd = sector;
                continue;
            }
            flushRange();
            currentArea = area;
            rangeStart = sector;
            rangeEnd = sector;
            haveRange = true;
        }
        flushRange();

        const auto primaryTailIt = std::find_if(ranges.cbegin(), ranges.cend(), [&](const FbinstCarveRange &range) {
            return range.areaType == QStringLiteral("Primary") && primarySectorCount > 0 && range.endSector + 1 == primarySectorCount;
        });
        const auto extendedHeadIt = std::find_if(ranges.cbegin(), ranges.cend(), [&](const FbinstCarveRange &range) {
            return range.areaType == QStringLiteral("Extended") && range.startSector == primarySectorCount;
        });
        if (primaryTailIt != ranges.cend() && extendedHeadIt != ranges.cend()) {
            const quint64 combinedStart = primaryTailIt->endSector >= CrossAreaPrimaryTailSectors
                ? primaryTailIt->endSector - CrossAreaPrimaryTailSectors + 1
                : primaryTailIt->startSector;
            const quint64 combinedEnd = qMin<quint64>(extendedHeadIt->endSector, primarySectorCount + CrossAreaExtendedHeadSectors - 1);
            if (combinedStart < primarySectorCount && combinedEnd >= primarySectorCount) {
                ranges.append(FbinstCarveRange{
                    QStringLiteral("Combined"),
                    combinedStart,
                    combinedEnd,
                    primarySectorCount,
                    QStringLiteral("primary_extended_boundary")
                });
                log(QStringLiteral("Added combined Primary/Extended boundary carving range: %1.")
                    .arg(rangeAddressSummary(ranges.last())));
                log(QStringLiteral("Combined stream layout: Primary sectors emit 510 bytes each; Extended sectors emit 512 bytes each."));
                log(QStringLiteral("Primary/Extended split occurs at Fbinst sector %1.")
                    .arg(primarySectorCount));
                log(QStringLiteral("Combined candidate source range selected from Fbinst sectors %1-%2.")
                    .arg(combinedStart)
                    .arg(combinedEnd));
            }
        }

        result.rangeCount = ranges.size();
        if (ranges.isEmpty()) {
            result.ok = true;
            result.message = QStringLiteral("No remaining Fbinst sectors were found.");
            db.close();
            completeBenchmark(QStringLiteral("Completed"), result.message);
            return result;
        }

        std::unique_ptr<ImageReader> reader = ImageReader::create(m_params.sourcePath);
        QString readerError;
        if (!reader || !reader->open(&readerError)) {
            result.message = QStringLiteral("Unable to open source image: %1").arg(readerError);
            db.close();
            completeBenchmark(QStringLiteral("Failed"), result.message);
            return result;
        }

        log(QStringLiteral("Structure-aware carving enabled: signatures identify candidates, then H/Len-first format validators determine file boundaries before H/F, H/Max, and FSB fallbacks."));
        log(QStringLiteral("Fbinst carving ranges: %1 contiguous remaining ranges will be scanned internally.").arg(ranges.size()));

        const QString baseDir = QDir(m_params.outputDir).filePath(QStringLiteral("fbinsttool_carving"));
        const QString runName = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"));
        const QString logicalDir = QDir(baseDir).filePath(QStringLiteral("logical_images/%1").arg(runName));
        const QString recoveryDir = QDir(baseDir).filePath(QStringLiteral("internal/%1").arg(runName));
        QDir().mkpath(logicalDir);
        QDir().mkpath(recoveryDir);

        int recoveredCount = 0;
        int processedRanges = 0;
        QSet<QString> recoveredFingerprints;
        SignatureCarver carver;
        for (const FbinstCarveRange &range : ranges) {
            if (cancelled()) {
                result.cancelled = true;
                result.message = QStringLiteral("Internal signature carving cancelled.");
                db.close();
                completeBenchmark(QStringLiteral("Cancelled"), result.message);
                return result;
            }
            ++processedRanges;
            const QString name = rangeName(range);
            log(QStringLiteral("Preparing carving range %1: %2.").arg(name, rangeAddressSummary(range)));
            const QString logicalImage = QDir(logicalDir).filePath(QStringLiteral("%1.dd").arg(name));
            const QString rangeRecoveryDir = QDir(recoveryDir).filePath(name);
            QDir().mkpath(rangeRecoveryDir);

            benchmarkProgress(rangeProgress(0, 35, processedRanges, int(ranges.size()), 0.0), QStringLiteral("Building %1 carving image...").arg(name));
            if (!buildLogicalImage(range, logicalImage, processedRanges, int(ranges.size()), reader.get(), m_params.cancelRequested, benchmarkProgress, &errorMessage)) {
                if (cancelled()) {
                    result.cancelled = true;
                    result.message = QStringLiteral("Internal signature carving cancelled.");
                    db.close();
                    completeBenchmark(QStringLiteral("Cancelled"), result.message);
                    return result;
                }
                log(QStringLiteral("Carving image failed for %1: %2").arg(name, errorMessage));
                insertCarvedRow(db, range, logicalImage, QFileInfo(), 0, 0, QStringLiteral("LogicalImageBuild"), QStringLiteral("Source read/write failed"), QStringLiteral("None"), QStringLiteral("Failed"), errorMessage, nullptr);
                continue;
            }

            QFile logical(logicalImage);
            if (!logical.open(QIODevice::ReadOnly)) {
                errorMessage = QStringLiteral("Unable to read logical carving image: %1").arg(logical.errorString());
                log(errorMessage);
                insertCarvedRow(db, range, logicalImage, QFileInfo(), 0, 0, QStringLiteral("LogicalImageRead"), QStringLiteral("Logical image unavailable"), QStringLiteral("None"), QStringLiteral("Failed"), errorMessage, nullptr);
                continue;
            }
            benchmarkBytesWritten += quint64(qMax<qint64>(0, QFileInfo(logicalImage).size()));

            const qsizetype scanStride = (range.areaType == QStringLiteral("Primary") || range.areaType == QStringLiteral("Combined"))
                ? 510
                : qsizetype(ShowcaseAnalyzer::SectorSize);
            QVector<CarvedFile> carvedFiles;
            const qint64 logicalSize = logical.size();
            const int totalWindows = qMax(1, int((logicalSize + CarvingScanWindowBytes - 1) / CarvingScanWindowBytes));
            int windowNumber = 0;
            for (qint64 readOffset = 0; readOffset < logicalSize; readOffset += CarvingScanWindowBytes) {
                if (cancelled()) {
                    result.cancelled = true;
                    result.message = QStringLiteral("Internal signature carving cancelled.");
                    db.close();
                    completeBenchmark(QStringLiteral("Cancelled"), result.message);
                    return result;
                }
                ++windowNumber;
                const qint64 primaryBytes = qMin(CarvingScanWindowBytes, logicalSize - readOffset);
                const qint64 bytesToRead = qMin(primaryBytes + CarvingScanOverlapBytes, logicalSize - readOffset);
                if (!logical.seek(readOffset)) {
                    errorMessage = QStringLiteral("Unable to seek logical carving image to %1: %2").arg(readOffset).arg(logical.errorString());
                    log(errorMessage);
                    break;
                }

                benchmarkProgress(rangeProgress(35, 95, processedRanges, int(ranges.size()), double(readOffset) / double(qMax<qint64>(1, logicalSize))),
                    QStringLiteral("Scanning %1: window %2/%3, %4/%5 MiB")
                        .arg(name)
                        .arg(windowNumber)
                        .arg(totalWindows)
                        .arg(formatMiB(quint64(readOffset)))
                        .arg(formatMiB(quint64(logicalSize))));

                const QByteArray windowData = logical.read(bytesToRead);
                if (windowData.size() != bytesToRead) {
                    errorMessage = QStringLiteral("Unable to read logical carving window at %1: %2").arg(readOffset).arg(logical.errorString());
                    log(errorMessage);
                    break;
                }
                benchmarkBytesRead += quint64(bytesToRead);

                log(QStringLiteral("Scanning window detail: range=%1 window=%2/%3 logical_offset=%4 bytes=%5 stride=%6 overlap=%7")
                    .arg(name)
                    .arg(windowNumber)
                    .arg(totalWindows)
                    .arg(readOffset)
                    .arg(windowData.size())
                    .arg(scanStride)
                    .arg(qMax<qint64>(0, bytesToRead - primaryBytes)));
                QVector<CarvedFile> windowFiles;
                const QVector<CarveCandidateInfo> candidates = carver.scan(windowData, scanStride, quint64(readOffset));
                benchmarkItems += quint64(candidates.size());
                log(QStringLiteral("Candidate index complete: range=%1 window=%2/%3 candidates=%4")
                    .arg(name)
                    .arg(windowNumber)
                    .arg(totalWindows)
                    .arg(candidates.size()));
                for (const CarveCandidateInfo &candidate : candidates) {
                    if (cancelled()) {
                        result.cancelled = true;
                        result.message = QStringLiteral("Internal signature carving cancelled.");
                        db.close();
                        completeBenchmark(QStringLiteral("Cancelled"), result.message);
                        return result;
                    }
                    const qint64 candidateId = insertCandidateRow(db,
                        range,
                        logicalImage,
                        candidate,
                        QStringLiteral("Detected"),
                        QStringLiteral("Queued for format validator"),
                        QStringLiteral("Signature candidate indexed before validation."));

                    const quint64 absoluteCandidateOffset = candidate.logicalOffset;
                    CarveCandidateInfo localCandidate = candidate;
                    if (localCandidate.logicalOffset < quint64(readOffset)) {
                        updateCandidateRow(db, candidateId, QStringLiteral("Rejected"), QStringLiteral("Candidate offset before current window"), -1, QString(), QString(), QStringLiteral("Window offset mismatch"), QStringLiteral("Window offset mismatch."));
                        continue;
                    }
                    localCandidate.logicalOffset -= quint64(readOffset);
                    std::optional<CarvedFile> carved = carver.validate(windowData, localCandidate);
                    qint64 validationBaseOffset = readOffset;
                    const quint64 localOffset = localCandidate.logicalOffset;
                    const bool candidateNearWindowTail = localOffset + quint64(CarvingScanOverlapBytes) >= quint64(windowData.size());
                    const bool carvedTouchesWindowTail = carved.has_value()
                        && carved->logicalEnd + 1 >= quint64(qMax<qsizetype>(0, windowData.size() - 1024 * 1024));
                    if ((candidateNearWindowTail || carvedTouchesWindowTail)
                        && absoluteCandidateOffset < quint64(logicalSize)
                        && bytesToRead < logicalSize - readOffset) {
                        const qint64 retryOffset = qint64(absoluteCandidateOffset);
                        const qint64 retryBytes = qMin(CarvingScanWindowBytes, logicalSize - retryOffset);
                        if (retryBytes > bytesToRead - qint64(localOffset) && logical.seek(retryOffset)) {
                            const QByteArray retryData = logical.read(retryBytes);
                            if (retryData.size() == retryBytes) {
                                CarveCandidateInfo retryCandidate = localCandidate;
                                retryCandidate.logicalOffset = 0;
                                std::optional<CarvedFile> retryCarved = carver.validate(retryData, retryCandidate);
                                if (retryCarved.has_value()) {
                                    carved = retryCarved;
                                    validationBaseOffset = retryOffset;
                                    log(QStringLiteral("Candidate revalidated with expanded window: range=%1 offset=%2 bytes=%3 ext=%4")
                                        .arg(name)
                                        .arg(absoluteCandidateOffset)
                                        .arg(retryBytes)
                                        .arg(carved->extension));
                                }
                            }
                        }
                    }
                    if (!carved.has_value()) {
                        updateCandidateRow(db, candidateId, QStringLiteral("Rejected"), QStringLiteral("Format validator rejected candidate"), -1, QStringLiteral("H/Len -> H/F -> H/Max -> FSB"), QString(), QStringLiteral("No strategy validated this candidate"), QStringLiteral("Signature was detected but did not pass parser validation."));
                        continue;
                    }
                    carved->logicalStart += quint64(validationBaseOffset);
                    carved->logicalEnd += quint64(validationBaseOffset);
                    carved->candidateId = candidateId;
                    updateCandidateRow(db,
                        candidateId,
                        QStringLiteral("Validated"),
                        carved->validationResult,
                        -1,
                        carved->attemptedMethods,
                        carved->selectedMethod,
                        QString(),
                        QStringLiteral("Candidate validated as .%1 using %2.").arg(carved->extension, carved->carvingMethod));
                    windowFiles.append(*carved);
                }
                const quint64 primaryEnd = quint64(readOffset + primaryBytes);
                const int beforeTrimCount = windowFiles.size();
                for (int i = windowFiles.size() - 1; i >= 0; --i) {
                    if (windowFiles[i].logicalStart >= primaryEnd) {
                        windowFiles.removeAt(i);
                    }
                }
                log(QStringLiteral("Window scan complete: range=%1 window=%2/%3 recovered_candidates=%4 retained_in_primary_window=%5")
                    .arg(name)
                    .arg(windowNumber)
                    .arg(totalWindows)
                    .arg(beforeTrimCount)
                    .arg(windowFiles.size()));
                appendCarvedNonOverlapping(&carvedFiles, windowFiles);
            }
            logical.close();

            if (carvedFiles.isEmpty()) {
                insertCarvedRow(db, range, logicalImage, QFileInfo(), 0, 0, QStringLiteral("CandidateScanner"), QStringLiteral("No validated candidates"), QStringLiteral("None"), QStringLiteral("No files recovered"), QStringLiteral("No supported candidate was validated from this range."), nullptr);
                log(QStringLiteral("Internal carving completed for %1: no files recovered.").arg(name));
                continue;
            }

            int index = 0;
            int rangeRecoveredCount = 0;
            int rangeDuplicateCount = 0;
            for (const CarvedFile &carvedFile : carvedFiles) {
                if (cancelled()) {
                    result.cancelled = true;
                    result.message = QStringLiteral("Internal signature carving cancelled.");
                    db.close();
                    completeBenchmark(QStringLiteral("Cancelled"), result.message);
                    return result;
                }
                benchmarkProgress(rangeProgress(95, 99, processedRanges, int(ranges.size()), carvedFiles.isEmpty() ? 1.0 : double(index) / double(carvedFiles.size())),
                    QStringLiteral("Writing carved files for %1: %2/%3").arg(name).arg(index).arg(carvedFiles.size()));
                const QString fileName = QStringLiteral("%1_%2_%3.%4")
                    .arg(name)
                    .arg(index++, 4, 10, QLatin1Char('0'))
                    .arg(carvedFile.logicalStart, 10, 10, QLatin1Char('0'))
                    .arg(carvedFile.extension);
                const QString outputPath = QDir(rangeRecoveryDir).filePath(fileName);
                const quint64 fileSize = carvedFile.logicalEnd >= carvedFile.logicalStart
                    ? carvedFile.logicalEnd - carvedFile.logicalStart + 1
                    : 0;
                if (fileSize == 0 || !copyLogicalRangeToFile(logicalImage, carvedFile.logicalStart, fileSize, outputPath, m_params.cancelRequested, &errorMessage)) {
                    insertCarvedRow(db, range, logicalImage, QFileInfo(), carvedFile.logicalStart, carvedFile.logicalEnd, carvedFile.carvingMethod, carvedFile.validationResult, carvedFile.confidence, QStringLiteral("Failed"), errorMessage, nullptr);
                    updateCandidateRow(db, carvedFile.candidateId, QStringLiteral("Failed"), carvedFile.validationResult, -1, carvedFile.attemptedMethods, carvedFile.selectedMethod, errorMessage, errorMessage);
                    continue;
                }
                const QFileInfo fileInfo(outputPath);
                const QString fileSha256 = sha256ForFile(fileInfo.absoluteFilePath());
                const QString fingerprint = QStringLiteral("%1:%2").arg(fileInfo.size()).arg(fileSha256);
                if (recoveredFingerprints.contains(fingerprint)) {
                    QFile::remove(outputPath);
                    ++rangeDuplicateCount;
                    updateCandidateRow(db,
                        carvedFile.candidateId,
                        QStringLiteral("DuplicateSkipped"),
                        carvedFile.validationResult,
                        -1,
                        carvedFile.attemptedMethods,
                        carvedFile.selectedMethod,
                        QString(),
                        QStringLiteral("Skipped duplicate recovered file with identical size and SHA-256."));
                    continue;
                }
                recoveredFingerprints.insert(fingerprint);
                benchmarkBytesWritten += quint64(fileInfo.size());
                insertCarvedRow(db, range, logicalImage, fileInfo, carvedFile.logicalStart, carvedFile.logicalEnd, carvedFile.carvingMethod, carvedFile.validationResult, carvedFile.confidence, QStringLiteral("Recovered"), carvedFile.notes, nullptr);
                updateCandidateRow(db,
                    carvedFile.candidateId,
                    QStringLiteral("Recovered"),
                    carvedFile.validationResult,
                    -1,
                    carvedFile.attemptedMethods,
                    carvedFile.selectedMethod,
                    QString(),
                    QStringLiteral("Extracted to %1").arg(fileInfo.absoluteFilePath()));
                ++recoveredCount;
                ++rangeRecoveredCount;
            }
            log(QStringLiteral("Internal carving completed for %1: %2 files recovered, %3 duplicates skipped.")
                    .arg(name)
                    .arg(rangeRecoveredCount)
                    .arg(rangeDuplicateCount));
        }

        reader->close();
        result.ok = true;
        result.recoveredCount = recoveredCount;
        result.message = QStringLiteral("Internal signature carving complete. %1 files recovered from %2 ranges.").arg(recoveredCount).arg(ranges.size());
        db.close();
    }
    benchmarkProgress(100, QStringLiteral("Internal signature carving complete"));
    completeBenchmark(result.ok ? QStringLiteral("Completed") : QStringLiteral("Failed"), result.message);
    return result;
}
