#include "showcaseanalyzer.h"

#include <QDir>
#include <QFileInfo>
#include <QMap>
#include <QSet>
#include <QSqlError>
#include <QSqlQuery>
#include <QTemporaryFile>
#include <QVariantList>
#include <tsk/libtsk.h>

#include <algorithm>

namespace
{
bool execQuery(QSqlQuery &query, QString *errorMessage)
{
    if (query.exec()) {
        return true;
    }

    if (errorMessage) {
        *errorMessage = query.lastError().text();
    }
    return false;
}

bool execSql(QSqlDatabase &database, const QString &sql, QString *errorMessage)
{
    QSqlQuery query(database);
    if (query.exec(sql)) {
        return true;
    }

    if (errorMessage) {
        *errorMessage = query.lastError().text();
    }
    return false;
}

QString formatSignatureBytes(const QByteArray &bytes)
{
    if (bytes.isEmpty()) {
        return QString();
    }

    bool printable = true;
    for (const char ch : bytes) {
        const uchar value = static_cast<uchar>(ch);
        if (value < 0x20 || value > 0x7E) {
            printable = false;
            break;
        }
    }

    if (printable) {
        return QString::fromLatin1(bytes);
    }

    return QStringLiteral("0x%1").arg(QString::fromLatin1(bytes.toHex().toUpper()));
}

QString formatPartitionSize(quint64 bytes)
{
    constexpr double BytesPerMb = 1024.0 * 1024.0;
    constexpr double BytesPerGb = 1024.0 * 1024.0 * 1024.0;
    return QStringLiteral("%1 MB / %2 GB")
        .arg(double(bytes) / BytesPerMb, 0, 'f', 2)
        .arg(double(bytes) / BytesPerGb, 0, 'f', 2);
}

bool isZeroGuid(const QByteArray &data, int offset)
{
    for (int index = 0; index < 16; ++index) {
        if (static_cast<uchar>(data[offset + index]) != 0) {
            return false;
        }
    }
    return true;
}

QString readGptName(const QByteArray &entry)
{
    QString name;
    for (int offset = 56; offset + 1 < entry.size(); offset += 2) {
        const ushort codeUnit = ushort(static_cast<uchar>(entry[offset]))
            | (ushort(static_cast<uchar>(entry[offset + 1])) << 8);
        if (codeUnit == 0) {
            break;
        }
        name.append(QChar(codeUnit));
    }
    return name.trimmed();
}

bool materializeReaderToRawFile(ImageReader &reader, QTemporaryFile &rawFile, QString *errorMessage)
{
    rawFile.setFileTemplate(QDir::tempPath() + QStringLiteral("/FBBForensics_E01_XXXXXX.raw"));
    rawFile.setAutoRemove(true);
    if (!rawFile.open()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to create temporary raw image for E01 processing: %1").arg(rawFile.errorString());
        }
        return false;
    }

    constexpr quint64 ChunkSize = 16ULL * 1024ULL * 1024ULL;
    const quint64 imageSize = reader.size();
    for (quint64 offset = 0; offset < imageSize; offset += ChunkSize) {
        const quint64 bytesToRead = qMin<quint64>(ChunkSize, imageSize - offset);
        const QByteArray chunk = reader.read(offset, bytesToRead, errorMessage);
        if (quint64(chunk.size()) != bytesToRead) {
            return false;
        }
        if (rawFile.write(chunk) != chunk.size()) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Unable to write temporary raw image for E01 processing: %1").arg(rawFile.errorString());
            }
            return false;
        }
    }
    rawFile.flush();
    return true;
}
}

ShowcaseAnalyzer::ShowcaseAnalyzer(const QString &sourcePath)
    : m_sourcePath(sourcePath)
{
}

void ShowcaseAnalyzer::setProgressCallback(std::function<void(int, const QString &)> callback)
{
    m_progressCallback = std::move(callback);
}

void ShowcaseAnalyzer::reportProgress(int value, const QString &message) const
{
    if (m_progressCallback) {
        m_progressCallback(value, message);
    }
}

bool ShowcaseAnalyzer::analyze(QSqlDatabase &partitionDb, QSqlDatabase &booticeDb, QSqlDatabase &fbinstDb, QString *errorMessage)
{
    reportProgress(5, QStringLiteral("Resetting analysis state..."));
    m_primarySectors.clear();
    m_extendedSectors.clear();

    reportProgress(12, QStringLiteral("Resetting database schema..."));
    if (!resetPartitionSchema(partitionDb, errorMessage)
        || !resetBooticeSchema(booticeDb, errorMessage)
        || !resetFbinstSchema(fbinstDb, errorMessage)) {
        return false;
    }

    reportProgress(24, QStringLiteral("Creating analysis tables..."));
    if (!createPartitionTables(partitionDb, errorMessage)
        || !createBooticeTables(booticeDb, errorMessage)
        || !createFbinstTables(fbinstDb, errorMessage)) {
        return false;
    }

    reportProgress(32, QStringLiteral("Recording source metadata..."));
    if (!recordSummary(partitionDb, QStringLiteral("source_path"), QFileInfo(m_sourcePath).absoluteFilePath(), errorMessage)) {
        return false;
    }

    reportProgress(38, QStringLiteral("Opening evidence image reader..."));
    m_reader = ImageReader::create(m_sourcePath);
    if (!m_reader || !m_reader->open(errorMessage)) {
        return false;
    }
    if (!recordSummary(partitionDb, QStringLiteral("image_reader"), m_reader->backendName(), errorMessage)) {
        return false;
    }

    reportProgress(45, QStringLiteral("Enumerating partitions..."));
    if (!enumeratePartitions(partitionDb, errorMessage)) {
        return false;
    }

    reportProgress(62, QStringLiteral("Inspecting master boot record..."));
    const bool ok = readMbr(partitionDb, booticeDb, fbinstDb, errorMessage);
    if (ok) {
        reportProgress(100, QStringLiteral("Analysis data has been recorded."));
    }
    return ok;
}

bool ShowcaseAnalyzer::resetPartitionSchema(QSqlDatabase &database, QString *errorMessage) const
{
    const QStringList drops{
        QStringLiteral("DROP TABLE IF EXISTS Partitions"),
        QStringLiteral("DROP TABLE IF EXISTS AnalysisSummary")
    };
    for (const QString &sql : drops) {
        if (!execSql(database, sql, errorMessage)) {
            return false;
        }
    }
    return true;
}

bool ShowcaseAnalyzer::resetBooticeSchema(QSqlDatabase &database, QString *errorMessage) const
{
    const QStringList drops{
        QStringLiteral("DROP TABLE IF EXISTS Bootice"),
        QStringLiteral("DROP TABLE IF EXISTS Bootice_List"),
        QStringLiteral("DROP TABLE IF EXISTS Bootice_Signatures")
    };
    for (const QString &sql : drops) {
        if (!execSql(database, sql, errorMessage)) {
            return false;
        }
    }
    return true;
}

bool ShowcaseAnalyzer::resetFbinstSchema(QSqlDatabase &database, QString *errorMessage) const
{
    const QStringList drops{
        QStringLiteral("DROP TABLE IF EXISTS Fbinst"),
        QStringLiteral("DROP TABLE IF EXISTS Fbinst_List"),
        QStringLiteral("DROP TABLE IF EXISTS Fbinst_Sectors"),
        QStringLiteral("DROP TABLE IF EXISTS Fbinst_Remaining_Sectors"),
        QStringLiteral("DROP TABLE IF EXISTS Fbinst_Carving_Candidates"),
        QStringLiteral("DROP TABLE IF EXISTS Fbinst_Carved_Files")
    };
    for (const QString &sql : drops) {
        if (!execSql(database, sql, errorMessage)) {
            return false;
        }
    }
    return true;
}

bool ShowcaseAnalyzer::createPartitionTables(QSqlDatabase &database, QString *errorMessage) const
{
    const QStringList creates{
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Partitions ("
            "Number INTEGER,"
            "Type TEXT,"
            "Start_LBA_Address INTEGER,"
            "Total_Sector_Count INTEGER,"
            "Partition_Size INTEGER,"
            "Partition_Size_MB_GB TEXT)"),
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS AnalysisSummary ("
            "Summary_Key TEXT PRIMARY KEY,"
            "Summary_Value TEXT)")
    };
    for (const QString &sql : creates) {
        if (!execSql(database, sql, errorMessage)) {
            return false;
        }
    }
    return true;
}

bool ShowcaseAnalyzer::createBooticeTables(QSqlDatabase &database, QString *errorMessage) const
{
    const QStringList creates{
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Bootice ("
            "Type TEXT,"
            "Start_LBA_Address INTEGER,"
            "Total_Sector_Count INTEGER,"
            "Partition_Size INTEGER)"),
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Bootice_List ("
            "Name TEXT,"
            "Type TEXT,"
            "Size INTEGER,"
            "Create_Date TEXT,"
            "Modify_Date TEXT)"),
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Bootice_Signatures ("
            "Bootice_Signature TEXT,"
            "EasyBoot_Signature TEXT,"
            "Classification TEXT)")
    };
    for (const QString &sql : creates) {
        if (!execSql(database, sql, errorMessage)) {
            return false;
        }
    }
    return true;
}

bool ShowcaseAnalyzer::createFbinstTables(QSqlDatabase &database, QString *errorMessage) const
{
    const QStringList creates{
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Fbinst ("
            "Fbinst_Version TEXT,"
            "List_Used INTEGER,"
            "List_Size INTEGER,"
            "Primary_Size INTEGER,"
            "Extended_Size INTEGER)"),
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Fbinst_List ("
            "File_Names TEXT,"
            "Type_Of_DataArea TEXT,"
            "File_Start INTEGER,"
            "File_Size INTEGER,"
            "Modified_Time TEXT)"),
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Fbinst_Sectors ("
            "Area_Type TEXT,"
            "Sector_Number INTEGER)"),
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Fbinst_Remaining_Sectors ("
            "Area_Type TEXT,"
            "Sector_Number INTEGER)"),
        QStringLiteral(
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
            "Notes TEXT)"),
        QStringLiteral(
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
            "Notes TEXT)")
    };
    for (const QString &sql : creates) {
        if (!execSql(database, sql, errorMessage)) {
            return false;
        }
    }
    return true;
}

bool ShowcaseAnalyzer::recordSummary(QSqlDatabase &database, const QString &key, const QString &value, QString *errorMessage) const
{
    QSqlQuery query(database);
    query.prepare(QStringLiteral("INSERT OR REPLACE INTO AnalysisSummary(Summary_Key, Summary_Value) VALUES(?, ?)"));
    query.addBindValue(key);
    query.addBindValue(value);
    return execQuery(query, errorMessage);
}

QByteArray ShowcaseAnalyzer::readBytes(ImageReader &reader, quint64 offset, quint64 size, QString *errorMessage) const
{
    return reader.read(offset, size, errorMessage);
}

quint16 ShowcaseAnalyzer::readLe16(const QByteArray &data, int offset)
{
    const uchar *base = reinterpret_cast<const uchar *>(data.constData()) + offset;
    return quint16(base[0]) | (quint16(base[1]) << 8);
}

quint32 ShowcaseAnalyzer::readLe32(const QByteArray &data, int offset)
{
    const uchar *base = reinterpret_cast<const uchar *>(data.constData()) + offset;
    return quint32(base[0])
        | (quint32(base[1]) << 8)
        | (quint32(base[2]) << 16)
        | (quint32(base[3]) << 24);
}

quint64 ShowcaseAnalyzer::readLe64(const QByteArray &data, int offset)
{
    const uchar *base = reinterpret_cast<const uchar *>(data.constData()) + offset;
    return quint64(base[0])
        | (quint64(base[1]) << 8)
        | (quint64(base[2]) << 16)
        | (quint64(base[3]) << 24)
        | (quint64(base[4]) << 32)
        | (quint64(base[5]) << 40)
        | (quint64(base[6]) << 48)
        | (quint64(base[7]) << 56);
}

QString ShowcaseAnalyzer::formatUnixTime(quint64 value)
{
    if (value == 0) {
        return {};
    }
    return QDateTime::fromSecsSinceEpoch(static_cast<qint64>(value)).toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
}

QString ShowcaseAnalyzer::formatFbinstVersion(quint16 value)
{
    const quint8 major = static_cast<quint8>(value & 0x00FF);
    const quint8 minor = static_cast<quint8>((value >> 8) & 0x00FF);
    return QStringLiteral("%1.%2").arg(major).arg(minor);
}
QString ShowcaseAnalyzer::partitionTypeToString(quint8 type)
{
    static const QMap<quint8, QString> types{
        {0x00, QStringLiteral("Empty")}, {0x01, QStringLiteral("FAT12, CHS")}, {0x04, QStringLiteral("FAT16 16-32MB, CHS")},
        {0x05, QStringLiteral("Microsoft Extended")}, {0x06, QStringLiteral("FAT16 32MB, CHS")}, {0x07, QStringLiteral("NTFS")},
        {0x0b, QStringLiteral("FAT32, CHS")}, {0x0c, QStringLiteral("FAT32, LBA")}, {0x0e, QStringLiteral("FAT16, LBA")},
        {0x0f, QStringLiteral("Microsoft Extended, LBA")}, {0x27, QStringLiteral("PQservice")}, {0x39, QStringLiteral("Plan 9")},
        {0x42, QStringLiteral("Dynamic Disk")}, {0x44, QStringLiteral("GoBack")}, {0x63, QStringLiteral("Unix System V")},
        {0x82, QStringLiteral("Linux Swap")}, {0x83, QStringLiteral("Linux")}, {0x84, QStringLiteral("Hibernation")},
        {0x85, QStringLiteral("Linux Extended")}, {0x8e, QStringLiteral("Linux LVM")}, {0xaf, QStringLiteral("Apple HFS/HFS+")},
        {0xeb, QStringLiteral("BeOS BFS")}, {0xee, QStringLiteral("EFI GPT Disk")}, {0xef, QStringLiteral("EFI System Partition")}
    };
    return types.value(type, QStringLiteral("Unknown (0x%1)").arg(type, 2, 16, QLatin1Char('0')));
}

QString ShowcaseAnalyzer::dataAreaToString(quint8 area)
{
    return area == 0 ? QStringLiteral("Primary") : QStringLiteral("Extended");
}

bool ShowcaseAnalyzer::readMbr(QSqlDatabase &partitionDb, QSqlDatabase &booticeDb, QSqlDatabase &fbinstDb, QString *errorMessage)
{
    if (!m_reader || !m_reader->isOpen()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Image reader is not open.");
        }
        return false;
    }

    const QByteArray mbr = readBytes(*m_reader, 0, SectorSize, errorMessage);
    if (mbr.size() != SectorSize) {
        return false;
    }

    const quint16 mbrBootSignature = readLe16(mbr, 510);
    const QString bootSignature = QStringLiteral("0x%1").arg(mbrBootSignature, 4, 16, QLatin1Char('0'));
    if (!recordSummary(partitionDb, QStringLiteral("mbr_signature"), bootSignature, errorMessage)) {
        return false;
    }

    auto rejectCandidate = [&](const QString &candidate, const QString &reason) -> bool {
        reportProgress(90, QStringLiteral("Recording suspicious hidden-area signature finding..."));
        return recordSummary(partitionDb, QStringLiteral("hidden_boot_type"), QStringLiteral("Suspicious %1 Signature").arg(candidate), errorMessage)
            && recordSummary(partitionDb, QStringLiteral("hidden_boot_validation"), QStringLiteral("Rejected: %1").arg(reason), errorMessage)
            && recordSummary(partitionDb, QStringLiteral("verification_status"), QStringLiteral("Failed"), errorMessage)
            && recordSummary(partitionDb, QStringLiteral("verification_failure_reason"), reason, errorMessage);
    };

    if (mbr.mid(71, 4) == QByteArrayLiteral("-ELM")) {
        if (!recordSummary(partitionDb, QStringLiteral("candidate_signature"), QStringLiteral("Bootice/EasyBoot -ELM at sector 0 offset 71"), errorMessage)) {
            return false;
        }
        if (mbrBootSignature != 0xAA55) {
            return rejectCandidate(QStringLiteral("Bootice/EasyBoot"), QStringLiteral("MBR boot signature is %1, expected 0xaa55").arg(bootSignature));
        }

        reportProgress(75, QStringLiteral("Parsing Bootice or EasyBoot structures..."));
        QString validationError;
        if (!analyzeUltraIso(partitionDb, booticeDb, &validationError)) {
            return rejectCandidate(QStringLiteral("Bootice/EasyBoot"), validationError.isEmpty() ? QStringLiteral("Bootice follow-up structure validation failed") : validationError);
        }
        return recordSummary(partitionDb, QStringLiteral("hidden_boot_type"), QStringLiteral("Confirmed Bootice/EasyBoot"), errorMessage)
            && recordSummary(partitionDb, QStringLiteral("hidden_boot_validation"), QStringLiteral("Confirmed: sector 96/99 metadata and Bootice filesystem validated"), errorMessage)
            && recordSummary(partitionDb, QStringLiteral("verification_status"), QStringLiteral("Passed"), errorMessage);
    }

    if (mbr.mid(436, 4) == QByteArrayLiteral("FBBF")) {
        if (!recordSummary(partitionDb, QStringLiteral("candidate_signature"), QStringLiteral("Fbinst FBBF at sector 0 offset 436"), errorMessage)) {
            return false;
        }
        if (mbrBootSignature != 0xAA55) {
            return rejectCandidate(QStringLiteral("Fbinst"), QStringLiteral("MBR boot signature is %1, expected 0xaa55").arg(bootSignature));
        }

        reportProgress(75, QStringLiteral("Parsing Fbinst structures..."));
        QString validationError;
        if (!analyzeFbinst(partitionDb, fbinstDb, &validationError)) {
            return rejectCandidate(QStringLiteral("Fbinst"), validationError.isEmpty() ? QStringLiteral("Fbinst follow-up structure validation failed") : validationError);
        }
        return recordSummary(partitionDb, QStringLiteral("hidden_boot_type"), QStringLiteral("Confirmed Fbinst"), errorMessage)
            && recordSummary(partitionDb, QStringLiteral("hidden_boot_validation"), QStringLiteral("Confirmed: SubMBR, file-list metadata, and sector layout validated"), errorMessage)
            && recordSummary(partitionDb, QStringLiteral("verification_status"), QStringLiteral("Passed"), errorMessage);
    }

    reportProgress(90, QStringLiteral("Recording standard MBR findings..."));
    return recordSummary(partitionDb, QStringLiteral("hidden_boot_type"), QStringLiteral("Standard MBR"), errorMessage)
        && recordSummary(partitionDb, QStringLiteral("verification_status"), QStringLiteral("Not applicable"), errorMessage);
}

bool ShowcaseAnalyzer::analyzeUltraIso(QSqlDatabase &partitionDb, QSqlDatabase &booticeDb, QString *errorMessage)
{
    Q_UNUSED(partitionDb)

    if (!m_reader || !m_reader->isOpen()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Image reader is not open.");
        }
        return false;
    }

    const QByteArray booticeSector = readBytes(*m_reader, SectorSize * 96ULL, SectorSize, errorMessage);
    if (booticeSector.size() != SectorSize) {
        return false;
    }

    const quint8 partitionType = static_cast<quint8>(booticeSector[498]);
    const quint32 startLba = readLe32(booticeSector, 502);
    const quint32 sectorCount = readLe32(booticeSector, 506);
    const quint64 size = quint64(sectorCount) * SectorSize;
    const quint64 imageSectors = m_reader->size() / SectorSize;
    if (partitionType == 0 || startLba == 0 || sectorCount == 0) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Bootice sector 96 partition metadata is empty or invalid.");
        }
        return false;
    }
    if (imageSectors > 0 && (quint64(startLba) >= imageSectors || quint64(startLba) + quint64(sectorCount) > imageSectors)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Bootice partition range is outside the evidence image: start LBA %1, sectors %2, image sectors %3.")
                .arg(startLba)
                .arg(sectorCount)
                .arg(imageSectors);
        }
        return false;
    }

    QSqlQuery insert(booticeDb);
    insert.prepare(QStringLiteral("INSERT INTO Bootice(Type, Start_LBA_Address, Total_Sector_Count, Partition_Size) VALUES(?, ?, ?, ?)"));
    insert.addBindValue(partitionTypeToString(partitionType));
    insert.addBindValue(startLba);
    insert.addBindValue(sectorCount);
    insert.addBindValue(size);
    if (!execQuery(insert, errorMessage)) {
        return false;
    }

    reportProgress(82, QStringLiteral("Reading Bootice signature sectors..."));
    const QByteArray easyBootSector = readBytes(*m_reader, SectorSize * 99ULL, SectorSize, errorMessage);
    if (easyBootSector.size() != SectorSize) {
        return false;
    }

    const QString booticeSignature = formatSignatureBytes(easyBootSector.mid(71, 4));
    const QString easyBootSignature = formatSignatureBytes(easyBootSector.mid(480, 4));
    if (easyBootSector.mid(71, 4) != QByteArrayLiteral("-ELM") && easyBootSector.mid(480, 4) != QByteArrayLiteral("-ELC")) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Bootice sector 99 does not contain expected -ELM or -ELC follow-up signature.");
        }
        return false;
    }
    const bool easyBootPresent = easyBootSector.mid(480, 4) == QByteArrayLiteral("-ELC");
    const QString classification = easyBootPresent ? QStringLiteral("EasyBoot(Deep_Hidden)") : QStringLiteral("Bootice(Deep_Hidden)");

    QSqlQuery sigInsert(booticeDb);
    sigInsert.prepare(QStringLiteral("INSERT INTO Bootice_Signatures(Bootice_Signature, EasyBoot_Signature, Classification) VALUES(?, ?, ?)"));
    sigInsert.addBindValue(booticeSignature);
    sigInsert.addBindValue(easyBootSignature);
    sigInsert.addBindValue(classification);
    if (!execQuery(sigInsert, errorMessage)) {
        return false;
    }

    reportProgress(92, QStringLiteral("Enumerating Bootice root directory..."));
    return enumerateBooticeRoot(startLba, booticeDb, errorMessage);
}

void ShowcaseAnalyzer::recordPrimaryAreaSectors(quint32 start, quint32 fileSize)
{
    const quint32 sectorCount = fileSize > 510 ? quint32((fileSize + 509) / 510) : 1;
    for (quint32 i = 0; i < sectorCount; ++i) {
        m_primarySectors.append(start + i);
    }
}

void ShowcaseAnalyzer::recordExtendedAreaSectors(quint32 start, quint32 fileSize)
{
    const quint32 sectorCount = qMax<quint32>(1, quint32((fileSize + (SectorSize - 1)) / SectorSize));
    for (quint32 i = 0; i < sectorCount; ++i) {
        m_extendedSectors.append(start + i);
    }
}

bool ShowcaseAnalyzer::persistRemainingSectors(QSqlDatabase &fbinstDb, const QVector<quint32> &sectors, const QString &areaType, quint64 areaStart, quint64 areaEnd, QString *errorMessage)
{
    if (areaEnd < areaStart) {
        return true;
    }

    constexpr int BatchSize = 4096;
    QVariantList areaTypes;
    QVariantList sectorNumbers;

    auto flushBatch = [&]() -> bool {
        if (sectorNumbers.isEmpty()) {
            return true;
        }

        QSqlQuery insert(fbinstDb);
        insert.prepare(QStringLiteral("INSERT INTO Fbinst_Remaining_Sectors(Area_Type, Sector_Number) VALUES(?, ?)"));
        insert.addBindValue(areaTypes);
        insert.addBindValue(sectorNumbers);
        if (!insert.execBatch()) {
            if (errorMessage) {
                *errorMessage = insert.lastError().text();
            }
            return false;
        }

        areaTypes.clear();
        sectorNumbers.clear();
        return true;
    };

    int coveredIndex = 0;
    for (quint64 sector = areaStart; sector <= areaEnd; ++sector) {
        while (coveredIndex < sectors.size() && quint64(sectors[coveredIndex]) < sector) {
            ++coveredIndex;
        }
        if (coveredIndex < sectors.size() && quint64(sectors[coveredIndex]) == sector) {
            continue;
        }
        areaTypes.append(areaType);
        sectorNumbers.append(sector);
        if (sectorNumbers.size() >= BatchSize && !flushBatch()) {
            return false;
        }
    }

    return flushBatch();
}

bool ShowcaseAnalyzer::persistFbinstSectors(QSqlDatabase &fbinstDb, const FbinstHeader &header, quint32 primarySize, quint32 extendedSize, QString *errorMessage)
{
    auto rollbackWithError = [&](const QString &message) -> bool {
        if (fbinstDb.isOpen()) {
            fbinstDb.rollback();
        }
        if (errorMessage) {
            *errorMessage = message;
        }
        return false;
    };

    if (!fbinstDb.transaction()) {
        if (errorMessage) {
            *errorMessage = fbinstDb.lastError().text();
        }
        return false;
    }

    const quint64 primaryDataStart = 68ULL + quint64(header.listSize);
    const quint64 primarySectorCount = quint64(primarySize);
    const quint64 primaryStart = qMin(primaryDataStart, primarySectorCount);
    const quint64 primaryEnd = primarySectorCount == 0 ? 0 : primarySectorCount - 1;
    const quint64 extendedStart = primarySectorCount;
    const quint64 extendedSectorCount = quint64(extendedSize);
    const quint64 extendedEnd = extendedSectorCount == 0 ? extendedStart - 1 : extendedStart + extendedSectorCount - 1;

    auto persistArea = [&](const QVector<quint32> &sectors, const QString &areaType, quint64 areaStart, quint64 areaEnd, int progressValue, const QString &progressMessage) -> bool {
        QVector<quint32> unique = sectors;
        std::sort(unique.begin(), unique.end());
        unique.erase(std::unique(unique.begin(), unique.end()), unique.end());

        if (!unique.isEmpty()) {
            constexpr int BatchSize = 4096;
            QVariantList areaTypes;
            QVariantList sectorNumbers;

            auto flushBatch = [&]() -> bool {
                if (sectorNumbers.isEmpty()) {
                    return true;
                }

                QSqlQuery insert(fbinstDb);
                insert.prepare(QStringLiteral("INSERT INTO Fbinst_Sectors(Area_Type, Sector_Number) VALUES(?, ?)"));
                insert.addBindValue(areaTypes);
                insert.addBindValue(sectorNumbers);
                if (!insert.execBatch()) {
                    if (errorMessage) {
                        *errorMessage = insert.lastError().text();
                    }
                    return false;
                }

                areaTypes.clear();
                sectorNumbers.clear();
                return true;
            };

            for (quint32 sector : unique) {
                areaTypes.append(areaType);
                sectorNumbers.append(sector);
                if (sectorNumbers.size() >= BatchSize && !flushBatch()) {
                    return false;
                }
            }

            if (!flushBatch()) {
                return false;
            }
        }

        reportProgress(progressValue, progressMessage);
        return persistRemainingSectors(fbinstDb, unique, areaType, areaStart, areaEnd, errorMessage);
    };

    if (!persistArea(m_primarySectors, QStringLiteral("Primary"), primaryStart, primaryEnd, 96, QStringLiteral("Recording Primary remaining sectors..."))) {
        fbinstDb.rollback();
        return false;
    }

    if (!persistArea(m_extendedSectors, QStringLiteral("Extended"), extendedStart, extendedEnd, 98, QStringLiteral("Recording Extended remaining sectors..."))) {
        fbinstDb.rollback();
        return false;
    }

    if (!fbinstDb.commit()) {
        return rollbackWithError(fbinstDb.lastError().text());
    }

    return true;
}

bool ShowcaseAnalyzer::analyzeFbinst(QSqlDatabase &partitionDb, QSqlDatabase &fbinstDb, QString *errorMessage)
{
    Q_UNUSED(partitionDb)

    if (!m_reader || !m_reader->isOpen()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Image reader is not open.");
        }
        return false;
    }

    const QByteArray subMbr = readBytes(*m_reader, SectorSize * 64ULL, SectorSize * 4ULL, errorMessage);
    if (subMbr.size() != SectorSize * 4) {
        return false;
    }

    const quint16 fbinstVersion = readLe16(subMbr, 4);
    const QString version = formatFbinstVersion(fbinstVersion);
    const FbinstHeader header{readLe16(subMbr, 6), readLe16(subMbr, 8)};
    const quint16 primarySize = readLe16(subMbr, 10);
    const quint32 extendedSize = readLe32(subMbr, 12);
    const quint8 versionMajor = static_cast<quint8>(fbinstVersion & 0x00FF);
    const quint8 versionMinor = static_cast<quint8>((fbinstVersion >> 8) & 0x00FF);
    const quint64 imageSectors = m_reader->size() / SectorSize;
    const quint64 primaryDataStart = 68ULL + quint64(header.listSize);
    const quint64 totalFbinstSectors = quint64(primarySize) + quint64(extendedSize);

    if (versionMajor == 0 || versionMajor > 9 || versionMinor > 99) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Fbinst SubMBR version field is outside supported bounds: raw=0x%1, formatted=%2.")
                .arg(fbinstVersion, 4, 16, QLatin1Char('0'))
                .arg(version);
        }
        return false;
    }
    if (header.listSize == 0 || header.listUsed > header.listSize) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Fbinst file-list metadata is invalid: List_Used=%1, List_Size=%2.")
                .arg(header.listUsed)
                .arg(header.listSize);
        }
        return false;
    }
    if (primarySize == 0 || primarySize < primaryDataStart) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Fbinst Primary area is too small for the declared file-list layout: Primary_Size=%1, required data start sector=%2.")
                .arg(primarySize)
                .arg(primaryDataStart);
        }
        return false;
    }
    if (totalFbinstSectors == 0 || (imageSectors > 0 && totalFbinstSectors > imageSectors)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Fbinst declared area exceeds the evidence image: Primary_Size=%1, Extended_Size=%2, image sectors=%3.")
                .arg(primarySize)
                .arg(extendedSize)
                .arg(imageSectors);
        }
        return false;
    }

    QSqlQuery insert(fbinstDb);
    insert.prepare(QStringLiteral("INSERT INTO Fbinst(Fbinst_Version, List_Used, List_Size, Primary_Size, Extended_Size) VALUES(?, ?, ?, ?, ?)"));
    insert.addBindValue(version);
    insert.addBindValue(header.listUsed);
    insert.addBindValue(header.listSize);
    insert.addBindValue(primarySize);
    insert.addBindValue(extendedSize);
    if (!execQuery(insert, errorMessage)) {
        return false;
    }

    reportProgress(84, QStringLiteral("Parsing Fbinst file list..."));
    if (!analyzeFbinstFileList(*m_reader, fbinstVersion, header, fbinstDb, errorMessage)) {
        return false;
    }

    reportProgress(94, QStringLiteral("Recording Fbinst sector coverage..."));
    return persistFbinstSectors(fbinstDb, header, primarySize, extendedSize, errorMessage);
}

bool ShowcaseAnalyzer::analyzeFbinstFileList(ImageReader &reader, quint16 fbinstVersion, const FbinstHeader &header, QSqlDatabase &fbinstDb, QString *errorMessage)
{
    if (header.listUsed == 0) {
        return true;
    }

    const QByteArray fileListSectors = readBytes(reader, SectorSize * 68ULL, SectorSize * quint64(header.listUsed), errorMessage);
    if (fileListSectors.isEmpty()) {
        return false;
    }

    QByteArray fileList;
    fileList.reserve(int(quint64(header.listUsed) * 510ULL));
    for (quint16 sectorIndex = 0; sectorIndex < header.listUsed; ++sectorIndex) {
        const int sectorOffset = int(sectorIndex) * int(SectorSize);
        if (sectorOffset + int(SectorSize) > fileListSectors.size()) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Corrupted Fbinst file list sector stream.");
            }
            return false;
        }
        fileList.append(fileListSectors.constData() + sectorOffset, 510);
    }

    const quint8 versionMajor = static_cast<quint8>(fbinstVersion & 0x00FF);
    const quint8 versionMinor = static_cast<quint8>((fbinstVersion >> 8) & 0x00FF);
    const bool has64BitModifiedTime = versionMajor > 1 || (versionMajor == 1 && versionMinor >= 7);
    const int entryHeaderSize = has64BitModifiedTime ? 18 : 14;

    int offset = 0;
    while (offset < fileList.size() && static_cast<quint8>(fileList[offset]) != 0) {
        if (offset + entryHeaderSize > fileList.size()) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Corrupted Fbinst file list.");
            }
            return false;
        }

        const quint8 areaType = static_cast<quint8>(fileList[offset + 1]);
        const quint32 fileStart = readLe32(fileList, offset + 2);
        const quint32 fileSize = readLe32(fileList, offset + 6);
        const quint64 modifiedTime = has64BitModifiedTime ? readLe64(fileList, offset + 10) : readLe32(fileList, offset + 10);
        if (areaType != 0 && areaType != 1) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Corrupted Fbinst file list: invalid data area type %1 at offset %2.")
                    .arg(areaType)
                    .arg(offset);
            }
            return false;
        }
        if (fileSize == 0) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Corrupted Fbinst file list: zero-sized file entry at offset %1.").arg(offset);
            }
            return false;
        }
        offset += entryHeaderSize;

        QByteArray nameBytes;
        while (offset < fileList.size() && fileList[offset] != '\0') {
            nameBytes.append(fileList[offset]);
            ++offset;
        }
        if (offset < fileList.size()) {
            ++offset;
        }
        if (nameBytes.isEmpty()) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Corrupted Fbinst file list: empty file name.");
            }
            return false;
        }

        QSqlQuery insert(fbinstDb);
        insert.prepare(QStringLiteral("INSERT INTO Fbinst_List(File_Names, Type_Of_DataArea, File_Start, File_Size, Modified_Time) VALUES(?, ?, ?, ?, ?)"));
        insert.addBindValue(QString::fromLatin1(nameBytes));
        insert.addBindValue(dataAreaToString(areaType));
        insert.addBindValue(fileStart);
        insert.addBindValue(fileSize);
        insert.addBindValue(formatUnixTime(modifiedTime));
        if (!execQuery(insert, errorMessage)) {
            return false;
        }

        if (areaType == 0) {
            recordPrimaryAreaSectors(fileStart, fileSize);
        } else if (areaType == 1) {
            recordExtendedAreaSectors(fileStart, fileSize);
        }
    }

    return true;
}

bool ShowcaseAnalyzer::enumeratePartitions(QSqlDatabase &partitionDb, QString *errorMessage)
{
    if (QFileInfo(m_sourcePath).suffix().compare(QStringLiteral("e01"), Qt::CaseInsensitive) == 0) {
        return enumerateMbrPartitionsFromReader(partitionDb, errorMessage);
    }

    TSK_IMG_INFO *image = tsk_img_open_utf8_sing(m_sourcePath.toUtf8().constData(), TSK_IMG_TYPE_DETECT, 0);
    if (!image) {
        return enumerateMbrPartitionsFromReader(partitionDb, errorMessage);
    }

    TSK_VS_INFO *volumeSystem = tsk_vs_open(image, 0, TSK_VS_TYPE_DETECT);
    if (!volumeSystem) {
        tsk_img_close(image);
        return enumerateMbrPartitionsFromReader(partitionDb, errorMessage);
    }

    quint64 totalBytes = 0;
    for (TSK_PNUM_T index = 0; index < volumeSystem->part_count; ++index) {
        const TSK_VS_PART_INFO *part = tsk_vs_part_get(volumeSystem, index);
        if (!part) {
            continue;
        }
        totalBytes += quint64(part->len) * SectorSize;
        QSqlQuery insert(partitionDb);
        insert.prepare(QStringLiteral("INSERT INTO Partitions(Number, Type, Start_LBA_Address, Total_Sector_Count, Partition_Size, Partition_Size_MB_GB) VALUES(?, ?, ?, ?, ?, ?)"));
        const quint64 partitionSize = quint64(part->len) * SectorSize;
        insert.addBindValue(int(part->addr));
        insert.addBindValue(QString::fromUtf8(part->desc));
        insert.addBindValue(quint64(part->start));
        insert.addBindValue(quint64(part->len));
        insert.addBindValue(partitionSize);
        insert.addBindValue(formatPartitionSize(partitionSize));
        if (!execQuery(insert, errorMessage)) {
            tsk_vs_close(volumeSystem);
            tsk_img_close(image);
            return false;
        }
    }

    tsk_vs_close(volumeSystem);
    tsk_img_close(image);
    return recordSummary(partitionDb, QStringLiteral("total_partition_bytes"), QString::number(totalBytes), errorMessage);
}

bool ShowcaseAnalyzer::enumerateMbrPartitionsFromReader(QSqlDatabase &partitionDb, QString *errorMessage)
{
    if (!m_reader || !m_reader->isOpen()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Image reader is not open.");
        }
        return false;
    }

    const QByteArray mbr = readBytes(*m_reader, 0, SectorSize, errorMessage);
    if (mbr.size() != SectorSize) {
        return false;
    }

    for (int slot = 0; slot < 4; ++slot) {
        const int offset = 446 + slot * 16;
        const quint8 partitionType = static_cast<quint8>(mbr[offset + 4]);
        if (partitionType == 0xee) {
            return enumerateGptPartitionsFromReader(partitionDb, errorMessage);
        }
    }

    quint64 totalBytes = 0;
    for (int slot = 0; slot < 4; ++slot) {
        const int offset = 446 + slot * 16;
        const quint8 partitionType = static_cast<quint8>(mbr[offset + 4]);
        const quint32 startLba = readLe32(mbr, offset + 8);
        const quint32 sectorCount = readLe32(mbr, offset + 12);
        if (partitionType == 0 && startLba == 0 && sectorCount == 0) {
            continue;
        }

        const quint64 partitionSize = quint64(sectorCount) * SectorSize;
        const quint64 readableBytes = m_reader ? m_reader->size() : 0;
        const quint64 partitionStartBytes = quint64(startLba) * SectorSize;
        const quint64 boundedSize = readableBytes > partitionStartBytes
            ? qMin(partitionSize, readableBytes - partitionStartBytes)
            : partitionSize;
        totalBytes += boundedSize;

        QSqlQuery insert(partitionDb);
        insert.prepare(QStringLiteral("INSERT INTO Partitions(Number, Type, Start_LBA_Address, Total_Sector_Count, Partition_Size, Partition_Size_MB_GB) VALUES(?, ?, ?, ?, ?, ?)"));
        insert.addBindValue(slot + 1);
        insert.addBindValue(partitionTypeToString(partitionType));
        insert.addBindValue(quint64(startLba));
        insert.addBindValue(quint64(sectorCount));
        insert.addBindValue(partitionSize);
        insert.addBindValue(formatPartitionSize(partitionSize));
        if (!execQuery(insert, errorMessage)) {
            return false;
        }
    }

    return recordSummary(partitionDb, QStringLiteral("total_partition_bytes"), QString::number(totalBytes), errorMessage)
        && recordSummary(partitionDb, QStringLiteral("partition_enumerator"), QStringLiteral("MBR parser via ImageReader"), errorMessage);
}

bool ShowcaseAnalyzer::enumerateGptPartitionsFromReader(QSqlDatabase &partitionDb, QString *errorMessage)
{
    if (!m_reader || !m_reader->isOpen()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Image reader is not open.");
        }
        return false;
    }

    const QByteArray header = readBytes(*m_reader, SectorSize, SectorSize, errorMessage);
    if (header.size() != SectorSize) {
        return false;
    }
    if (header.left(8) != QByteArrayLiteral("EFI PART")) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Protective MBR was found, but GPT header signature is missing.");
        }
        return false;
    }

    const quint64 entriesStartLba = readLe64(header, 72);
    const quint32 numberOfEntries = readLe32(header, 80);
    const quint32 entrySize = readLe32(header, 84);
    if (entriesStartLba == 0 || numberOfEntries == 0 || entrySize < 128 || entrySize > 4096 || numberOfEntries > 16384) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("GPT partition entry metadata is outside supported bounds.");
        }
        return false;
    }

    const quint64 entriesSize = quint64(numberOfEntries) * entrySize;
    if (entriesSize > 64ULL * 1024ULL * 1024ULL) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("GPT partition entry array is too large to read safely.");
        }
        return false;
    }

    const QByteArray entries = readBytes(*m_reader, entriesStartLba * SectorSize, entriesSize, errorMessage);
    if (quint64(entries.size()) != entriesSize) {
        return false;
    }

    quint64 totalBytes = 0;
    int visibleIndex = 1;
    for (quint32 index = 0; index < numberOfEntries; ++index) {
        const int offset = static_cast<int>(quint64(index) * entrySize);
        if (offset + int(entrySize) > entries.size() || isZeroGuid(entries, offset)) {
            continue;
        }

        const QByteArray entry = entries.mid(offset, static_cast<int>(entrySize));
        const quint64 firstLba = readLe64(entry, 32);
        const quint64 lastLba = readLe64(entry, 40);
        if (lastLba < firstLba) {
            continue;
        }

        const quint64 sectorCount = lastLba - firstLba + 1;
        const quint64 partitionSize = sectorCount * SectorSize;
        totalBytes += partitionSize;

        const QString name = readGptName(entry);
        QSqlQuery insert(partitionDb);
        insert.prepare(QStringLiteral("INSERT INTO Partitions(Number, Type, Start_LBA_Address, Total_Sector_Count, Partition_Size, Partition_Size_MB_GB) VALUES(?, ?, ?, ?, ?, ?)"));
        insert.addBindValue(visibleIndex++);
        insert.addBindValue(name.isEmpty() ? QStringLiteral("GPT Partition") : QStringLiteral("GPT: %1").arg(name));
        insert.addBindValue(firstLba);
        insert.addBindValue(sectorCount);
        insert.addBindValue(partitionSize);
        insert.addBindValue(formatPartitionSize(partitionSize));
        if (!execQuery(insert, errorMessage)) {
            return false;
        }
    }

    return recordSummary(partitionDb, QStringLiteral("total_partition_bytes"), QString::number(totalBytes), errorMessage)
        && recordSummary(partitionDb, QStringLiteral("partition_enumerator"), QStringLiteral("GPT parser via ImageReader"), errorMessage);
}

bool ShowcaseAnalyzer::enumerateBooticeRoot(quint64 startLba, QSqlDatabase &booticeDb, QString *errorMessage)
{
    QString tskSourcePath = m_sourcePath;
    QTemporaryFile temporaryRaw;
    if (QFileInfo(m_sourcePath).suffix().compare(QStringLiteral("e01"), Qt::CaseInsensitive) == 0) {
        if (!m_reader || !m_reader->isOpen()) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Image reader is not open.");
            }
            return false;
        }
        reportProgress(78, QStringLiteral("Preparing E01 image for Bootice filesystem listing..."));
        if (!materializeReaderToRawFile(*m_reader, temporaryRaw, errorMessage)) {
            return false;
        }
        tskSourcePath = temporaryRaw.fileName();
    }

    TSK_IMG_INFO *image = tsk_img_open_utf8_sing(tskSourcePath.toUtf8().constData(), TSK_IMG_TYPE_DETECT, 0);
    if (!image) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("libtsk could not open the Bootice image.");
        }
        return false;
    }

    TSK_FS_INFO *filesystem = tsk_fs_open_img(image, startLba * SectorSize, TSK_FS_TYPE_DETECT);
    if (!filesystem) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("libtsk could not open the Bootice filesystem.");
        }
        tsk_img_close(image);
        return false;
    }

    TSK_FS_DIR *rootDir = tsk_fs_dir_open(filesystem, "/");
    if (!rootDir) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("libtsk could not open the Bootice root directory.");
        }
        tsk_fs_close(filesystem);
        tsk_img_close(image);
        return false;
    }

    for (size_t i = 0; i < tsk_fs_dir_getsize(rootDir); ++i) {
        const TSK_FS_FILE *entry = tsk_fs_dir_get(rootDir, i);
        if (!entry || !entry->name || !entry->meta) {
            continue;
        }

        const char *name = entry->name->name;
        if (!name || name[0] == '\0' || QByteArray(name) == QByteArrayLiteral(".") || QByteArray(name) == QByteArrayLiteral("..")) {
            continue;
        }

        QSqlQuery insert(booticeDb);
        insert.prepare(QStringLiteral("INSERT INTO Bootice_List(Name, Type, Size, Create_Date, Modify_Date) VALUES(?, ?, ?, ?, ?)"));
        insert.addBindValue(QString::fromUtf8(name));
        insert.addBindValue(entry->meta->type == TSK_FS_META_TYPE_DIR ? QStringLiteral("DIR") : QStringLiteral("FILE"));
        insert.addBindValue(quint64(entry->meta->size));
        insert.addBindValue(formatUnixTime(static_cast<quint32>(entry->meta->crtime)));
        insert.addBindValue(formatUnixTime(static_cast<quint32>(entry->meta->mtime)));
        if (!execQuery(insert, errorMessage)) {
            tsk_fs_dir_close(rootDir);
            tsk_fs_close(filesystem);
            tsk_img_close(image);
            return false;
        }
    }

    tsk_fs_dir_close(rootDir);
    tsk_fs_close(filesystem);
    tsk_img_close(image);
    return true;
}








