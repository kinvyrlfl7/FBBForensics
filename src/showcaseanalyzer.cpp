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
#include <limits>

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

QString formatHexDecimal(quint64 value, int minimumHexWidth = 4)
{
    return QStringLiteral("0x%1(%2)")
        .arg(value, minimumHexWidth, 16, QLatin1Char('0'))
        .arg(value);
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

bool isPowerOfTwo(quint32 value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

quint32 fat32Entry(const QByteArray &fat, quint32 cluster)
{
    const quint64 offset = quint64(cluster) * 4ULL;
    if (offset + 4ULL > quint64(fat.size())) {
        return 0x0FFFFFF8U;
    }
    const uchar *base = reinterpret_cast<const uchar *>(fat.constData() + qsizetype(offset));
    return (quint32(base[0])
        | (quint32(base[1]) << 8)
        | (quint32(base[2]) << 16)
        | (quint32(base[3]) << 24)) & 0x0FFFFFFFU;
}

bool isFat32EndOfChain(quint32 entry)
{
    return entry >= 0x0FFFFFF8U;
}

bool isFat32FreeCluster(const QByteArray &fat, quint32 cluster)
{
    return fat32Entry(fat, cluster) == 0;
}

QString decodeFatShortName(const QByteArray &entry, bool deleted)
{
    if (entry.size() < 11) {
        return {};
    }

    QByteArray base = entry.left(8);
    QByteArray ext = entry.mid(8, 3);
    if (deleted && !base.isEmpty()) {
        base[0] = '?';
    }
    base = base.trimmed();
    ext = ext.trimmed();
    if (base.isEmpty()) {
        return {};
    }
    QString name = QString::fromLatin1(base);
    if (!ext.isEmpty()) {
        name += QLatin1Char('.');
        name += QString::fromLatin1(ext);
    }
    return name;
}

QString fatAttributesToString(quint8 attributes)
{
    QStringList values;
    if (attributes & 0x01) values << QStringLiteral("READONLY");
    if (attributes & 0x02) values << QStringLiteral("HIDDEN");
    if (attributes & 0x04) values << QStringLiteral("SYSTEM");
    if (attributes & 0x08) values << QStringLiteral("VOLUME");
    if (attributes & 0x10) values << QStringLiteral("DIR");
    if (attributes & 0x20) values << QStringLiteral("ARCHIVE");
    return values.isEmpty() ? QStringLiteral("NONE") : values.join(QLatin1Char('|'));
}

bool looksLikeDirectoryEntry(const QByteArray &entry)
{
    if (entry.size() < 32) {
        return false;
    }
    const quint8 first = static_cast<quint8>(entry[0]);
    const quint8 attributes = static_cast<quint8>(entry[11]);
    if (first == 0x00 || first == 0x05 || first == 0x2E || attributes == 0x0F || (attributes & 0x08)) {
        return false;
    }
    if ((attributes & 0x3F) == 0 || (attributes & 0xC0)) {
        return false;
    }
    for (int index = 1; index < 11; ++index) {
        const quint8 value = static_cast<quint8>(entry[index]);
        if (value < 0x20 && value != 0x05) {
            return false;
        }
    }
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
        QStringLiteral("DROP TABLE IF EXISTS Bootice_Signatures"),
        QStringLiteral("DROP TABLE IF EXISTS Bootice_Fat32_Info"),
        QStringLiteral("DROP TABLE IF EXISTS Bootice_Deleted_Files"),
        QStringLiteral("DROP TABLE IF EXISTS Bootice_Remaining_Clusters"),
        QStringLiteral("DROP TABLE IF EXISTS Bootice_Coverage"),
        QStringLiteral("DROP TABLE IF EXISTS Bootice_Carving_Candidates"),
        QStringLiteral("DROP TABLE IF EXISTS Bootice_Carved_Files")
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
            "Start_LBA_Address TEXT,"
            "Start_LBA_Offset TEXT,"
            "Total_Sector_Count TEXT,"
            "Partition_Size TEXT)"),
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Bootice_List ("
            "Name TEXT,"
            "Type TEXT,"
            "Size TEXT,"
            "Create_Date TEXT,"
            "Modify_Date TEXT)"),
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Bootice_Signatures ("
            "Bootice_Signature TEXT,"
            "EasyBoot_Signature TEXT,"
            "Classification TEXT)"),
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Bootice_Fat32_Info ("
            "Volume_Start_LBA INTEGER,"
            "Volume_Sector_Count INTEGER,"
            "Bytes_Per_Sector INTEGER,"
            "Sectors_Per_Cluster INTEGER,"
            "Reserved_Sectors INTEGER,"
            "FAT_Count INTEGER,"
            "FAT_Size_Sectors INTEGER,"
            "Root_Cluster INTEGER,"
            "FAT_Start_LBA INTEGER,"
            "Data_Start_LBA INTEGER,"
            "Cluster_Count INTEGER)"),
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Bootice_Deleted_Files ("
            "Directory_Cluster INTEGER,"
            "Entry_Offset INTEGER,"
            "Name_83 TEXT,"
            "Attributes TEXT,"
            "Start_Cluster INTEGER,"
            "File_Size INTEGER,"
            "Recovery_Method TEXT,"
            "Validation_Status TEXT,"
            "Notes TEXT)"),
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Bootice_Remaining_Clusters ("
            "Start_Cluster INTEGER,"
            "End_Cluster INTEGER,"
            "Start_LBA INTEGER,"
            "End_LBA INTEGER,"
            "Cluster_Count INTEGER,"
            "Byte_Count INTEGER)"),
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Bootice_Coverage ("
            "Coverage_Type TEXT,"
            "Start_Cluster INTEGER,"
            "End_Cluster INTEGER,"
            "Cluster_Count INTEGER,"
            "Notes TEXT)"),
        QStringLiteral(
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
            "Notes TEXT)"),
        QStringLiteral(
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
            "Notes TEXT)")
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
            "File_Start_Sector TEXT,"
            "File_Start_Offset TEXT,"
            "File_Size TEXT,"
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
    insert.prepare(QStringLiteral("INSERT INTO Bootice(Type, Start_LBA_Address, Start_LBA_Offset, Total_Sector_Count, Partition_Size) VALUES(?, ?, ?, ?, ?)"));
    insert.addBindValue(partitionTypeToString(partitionType));
    insert.addBindValue(formatHexDecimal(startLba, 8));
    insert.addBindValue(formatHexDecimal(quint64(startLba) * SectorSize, 8));
    insert.addBindValue(formatHexDecimal(sectorCount, 8));
    insert.addBindValue(formatHexDecimal(size, 8));
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

    reportProgress(90, QStringLiteral("Analyzing Bootice FAT32 metadata..."));
    if (!analyzeBooticeFat32(startLba, sectorCount, booticeDb, errorMessage)) {
        return false;
    }

    reportProgress(96, QStringLiteral("Enumerating Bootice root directory..."));
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
        insert.prepare(QStringLiteral("INSERT INTO Fbinst_List(File_Names, Type_Of_DataArea, File_Start_Sector, File_Start_Offset, File_Size, Modified_Time) VALUES(?, ?, ?, ?, ?, ?)"));
        insert.addBindValue(QString::fromLatin1(nameBytes));
        insert.addBindValue(dataAreaToString(areaType));
        insert.addBindValue(formatHexDecimal(fileStart, 8));
        insert.addBindValue(formatHexDecimal(quint64(fileStart) * SectorSize, 8));
        insert.addBindValue(formatHexDecimal(fileSize, 8));
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

bool ShowcaseAnalyzer::persistBooticeFat32Info(const BooticeFat32Info &info, QSqlDatabase &booticeDb, QString *errorMessage) const
{
    QSqlQuery insert(booticeDb);
    insert.prepare(QStringLiteral(
        "INSERT INTO Bootice_Fat32_Info("
        "Volume_Start_LBA, Volume_Sector_Count, Bytes_Per_Sector, Sectors_Per_Cluster, Reserved_Sectors, FAT_Count, "
        "FAT_Size_Sectors, Root_Cluster, FAT_Start_LBA, Data_Start_LBA, Cluster_Count"
        ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"));
    insert.addBindValue(info.volumeStartLba);
    insert.addBindValue(info.volumeSectorCount);
    insert.addBindValue(info.bytesPerSector);
    insert.addBindValue(info.sectorsPerCluster);
    insert.addBindValue(info.reservedSectors);
    insert.addBindValue(info.fatCount);
    insert.addBindValue(info.fatSizeSectors);
    insert.addBindValue(info.rootCluster);
    insert.addBindValue(info.fatStartLba);
    insert.addBindValue(info.dataStartLba);
    insert.addBindValue(info.clusterCount);
    return execQuery(insert, errorMessage);
}

bool ShowcaseAnalyzer::persistBooticeFat32Ranges(const BooticeFat32Info &info, const QByteArray &fat, QSqlDatabase &booticeDb, QString *errorMessage)
{
    if (info.clusterCount == 0 || info.clusterCount > quint64(std::numeric_limits<quint32>::max()) - 2ULL) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Bootice FAT32 cluster count is outside supported bounds: %1.").arg(info.clusterCount);
        }
        return false;
    }

    auto insertCoverageRange = [&](const QString &type, quint32 startCluster, quint32 endCluster, const QString &notes) -> bool {
        QSqlQuery insert(booticeDb);
        insert.prepare(QStringLiteral(
            "INSERT INTO Bootice_Coverage(Coverage_Type, Start_Cluster, End_Cluster, Cluster_Count, Notes) "
            "VALUES(?, ?, ?, ?, ?)"));
        insert.addBindValue(type);
        insert.addBindValue(startCluster);
        insert.addBindValue(endCluster);
        insert.addBindValue(quint64(endCluster) - quint64(startCluster) + 1ULL);
        insert.addBindValue(notes);
        return execQuery(insert, errorMessage);
    };

    auto insertRemainingRange = [&](quint32 startCluster, quint32 endCluster) -> bool {
        const quint64 clusterCount = quint64(endCluster) - quint64(startCluster) + 1ULL;
        const quint64 startLba = info.dataStartLba + (quint64(startCluster) - 2ULL) * info.sectorsPerCluster;
        const quint64 endLba = info.dataStartLba + (quint64(endCluster) - 1ULL) * info.sectorsPerCluster - 1ULL;
        QSqlQuery insert(booticeDb);
        insert.prepare(QStringLiteral(
            "INSERT INTO Bootice_Remaining_Clusters(Start_Cluster, End_Cluster, Start_LBA, End_LBA, Cluster_Count, Byte_Count) "
            "VALUES(?, ?, ?, ?, ?, ?)"));
        insert.addBindValue(startCluster);
        insert.addBindValue(endCluster);
        insert.addBindValue(startLba);
        insert.addBindValue(endLba);
        insert.addBindValue(clusterCount);
        insert.addBindValue(clusterCount * info.sectorsPerCluster * info.bytesPerSector);
        return execQuery(insert, errorMessage);
    };

    bool haveFreeRange = false;
    bool haveAllocatedRange = false;
    quint32 freeStart = 0;
    quint32 freeEnd = 0;
    quint32 allocatedStart = 0;
    quint32 allocatedEnd = 0;

    auto flushFree = [&]() -> bool {
        if (!haveFreeRange) {
            return true;
        }
        const bool ok = insertRemainingRange(freeStart, freeEnd);
        haveFreeRange = false;
        return ok;
    };
    auto flushAllocated = [&]() -> bool {
        if (!haveAllocatedRange) {
            return true;
        }
        const bool ok = insertCoverageRange(QStringLiteral("Allocated"), allocatedStart, allocatedEnd, QStringLiteral("FAT32 cluster currently allocated by FAT."));
        haveAllocatedRange = false;
        return ok;
    };

    const quint32 lastCluster = quint32(info.clusterCount + 1ULL);
    for (quint32 cluster = 2; cluster <= lastCluster; ++cluster) {
        const bool free = isFat32FreeCluster(fat, cluster);
        if (free) {
            if (!flushAllocated()) {
                return false;
            }
            if (!haveFreeRange) {
                freeStart = cluster;
                freeEnd = cluster;
                haveFreeRange = true;
            } else {
                freeEnd = cluster;
            }
        } else {
            if (!flushFree()) {
                return false;
            }
            if (!haveAllocatedRange) {
                allocatedStart = cluster;
                allocatedEnd = cluster;
                haveAllocatedRange = true;
            } else {
                allocatedEnd = cluster;
            }
        }
    }

    return flushFree() && flushAllocated();
}

bool ShowcaseAnalyzer::scanBooticeDeletedFiles(const BooticeFat32Info &info, const QByteArray &fat, QSqlDatabase &booticeDb, QString *errorMessage)
{
    auto clusterToOffset = [&](quint32 cluster) -> quint64 {
        return (info.dataStartLba + (quint64(cluster) - 2ULL) * info.sectorsPerCluster) * info.bytesPerSector;
    };
    auto validCluster = [&](quint32 cluster) -> bool {
        return cluster >= 2 && quint64(cluster) <= info.clusterCount + 1ULL;
    };

    QVector<quint32> pendingDirs{info.rootCluster};
    QSet<quint32> visitedDirs;
    int deletedCount = 0;

    while (!pendingDirs.isEmpty()) {
        const quint32 directoryCluster = pendingDirs.takeLast();
        if (!validCluster(directoryCluster) || visitedDirs.contains(directoryCluster)) {
            continue;
        }
        visitedDirs.insert(directoryCluster);

        quint32 currentCluster = directoryCluster;
        QSet<quint32> chainGuard;
        while (validCluster(currentCluster) && !chainGuard.contains(currentCluster)) {
            chainGuard.insert(currentCluster);
            const quint64 clusterBytes = quint64(info.sectorsPerCluster) * info.bytesPerSector;
            const QByteArray clusterData = readBytes(*m_reader, clusterToOffset(currentCluster), clusterBytes, errorMessage);
            if (quint64(clusterData.size()) != clusterBytes) {
                return false;
            }

            for (int offset = 0; offset + 32 <= clusterData.size(); offset += 32) {
                const QByteArray entry = clusterData.mid(offset, 32);
                const quint8 first = static_cast<quint8>(entry[0]);
                const quint8 attributes = static_cast<quint8>(entry[11]);
                if (first == 0x00) {
                    continue;
                }
                if (attributes == 0x0F || (attributes & 0x08)) {
                    continue;
                }

                const quint32 startCluster = (quint32(readLe16(entry, 20)) << 16) | readLe16(entry, 26);
                const quint32 fileSize = readLe32(entry, 28);
                const bool isDirectory = (attributes & 0x10) != 0;

                if (first == 0xE5) {
                    if (!looksLikeDirectoryEntry(entry)) {
                        continue;
                    }
                    const QString name = decodeFatShortName(entry.left(11), true);
                    QSqlQuery insert(booticeDb);
                    insert.prepare(QStringLiteral(
                        "INSERT INTO Bootice_Deleted_Files("
                        "Directory_Cluster, Entry_Offset, Name_83, Attributes, Start_Cluster, File_Size, Recovery_Method, Validation_Status, Notes"
                        ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)"));
                    insert.addBindValue(directoryCluster);
                    insert.addBindValue(offset);
                    insert.addBindValue(name);
                    insert.addBindValue(fatAttributesToString(attributes));
                    insert.addBindValue(startCluster);
                    insert.addBindValue(fileSize);
                    insert.addBindValue(isDirectory ? QStringLiteral("Directory metadata only") : QStringLiteral("FAT32 deleted directory entry; data clusters are free candidates"));
                    insert.addBindValue(validCluster(startCluster) ? QStringLiteral("Candidate") : QStringLiteral("Rejected"));
                    insert.addBindValue(validCluster(startCluster)
                        ? QStringLiteral("Deleted entry found. File data should be recovered from remaining free clusters and validated by format carver.")
                        : QStringLiteral("Deleted entry start cluster is outside FAT32 data area."));
                    if (!execQuery(insert, errorMessage)) {
                        return false;
                    }
                    ++deletedCount;
                    continue;
                }

                if (isDirectory && validCluster(startCluster)) {
                    const QString name = decodeFatShortName(entry.left(11), false);
                    if (name != QStringLiteral(".") && name != QStringLiteral("..")) {
                        pendingDirs.append(startCluster);
                    }
                }
            }

            const quint32 nextCluster = fat32Entry(fat, currentCluster);
            if (isFat32EndOfChain(nextCluster) || !validCluster(nextCluster)) {
                break;
            }
            currentCluster = nextCluster;
        }
    }

    Q_UNUSED(deletedCount)
    return true;
}

bool ShowcaseAnalyzer::analyzeBooticeFat32(quint64 startLba, quint64 sectorCount, QSqlDatabase &booticeDb, QString *errorMessage)
{
    if (!m_reader || !m_reader->isOpen()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Image reader is not open.");
        }
        return false;
    }

    const QByteArray bootSector = readBytes(*m_reader, startLba * SectorSize, SectorSize, errorMessage);
    if (bootSector.size() != SectorSize) {
        return false;
    }
    if (static_cast<quint8>(bootSector[510]) != 0x55 || static_cast<quint8>(bootSector[511]) != 0xAA) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Bootice hidden volume does not contain a valid FAT boot-sector signature.");
        }
        return false;
    }

    BooticeFat32Info info;
    info.volumeStartLba = startLba;
    info.bytesPerSector = readLe16(bootSector, 11);
    info.sectorsPerCluster = static_cast<quint8>(bootSector[13]);
    info.reservedSectors = readLe16(bootSector, 14);
    info.fatCount = static_cast<quint8>(bootSector[16]);
    const quint16 totalSectors16 = readLe16(bootSector, 19);
    const quint16 fatSize16 = readLe16(bootSector, 22);
    const quint32 totalSectors32 = readLe32(bootSector, 32);
    info.fatSizeSectors = fatSize16 != 0 ? fatSize16 : readLe32(bootSector, 36);
    info.rootCluster = readLe32(bootSector, 44);
    info.volumeSectorCount = totalSectors16 != 0 ? totalSectors16 : totalSectors32;
    if (info.volumeSectorCount == 0 || info.volumeSectorCount > sectorCount) {
        info.volumeSectorCount = sectorCount;
    }

    if ((info.bytesPerSector != 512 && info.bytesPerSector != 1024 && info.bytesPerSector != 2048 && info.bytesPerSector != 4096)
        || !isPowerOfTwo(info.sectorsPerCluster)
        || info.reservedSectors == 0
        || info.fatCount == 0
        || info.fatSizeSectors == 0
        || info.rootCluster < 2) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Bootice hidden volume FAT32 BPB is invalid or unsupported.");
        }
        return false;
    }

    info.fatStartLba = startLba + info.reservedSectors;
    info.dataStartLba = info.fatStartLba + quint64(info.fatCount) * info.fatSizeSectors;
    const quint64 dataStartRelative = info.dataStartLba - startLba;
    if (dataStartRelative >= info.volumeSectorCount) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Bootice FAT32 data area starts outside the hidden volume.");
        }
        return false;
    }
    info.clusterCount = (info.volumeSectorCount - dataStartRelative) / info.sectorsPerCluster;
    if (info.clusterCount == 0) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Bootice FAT32 data area contains no clusters.");
        }
        return false;
    }

    const quint64 fatBytes = quint64(info.fatSizeSectors) * info.bytesPerSector;
    if (fatBytes == 0 || fatBytes > quint64(std::numeric_limits<qsizetype>::max())) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Bootice FAT32 table is too large to read safely: %1 bytes.").arg(fatBytes);
        }
        return false;
    }
    const QByteArray fat = readBytes(*m_reader, info.fatStartLba * info.bytesPerSector, fatBytes, errorMessage);
    if (quint64(fat.size()) != fatBytes) {
        return false;
    }

    if (!booticeDb.transaction()) {
        if (errorMessage) {
            *errorMessage = booticeDb.lastError().text();
        }
        return false;
    }

    auto rollback = [&]() -> bool {
        booticeDb.rollback();
        return false;
    };

    if (!persistBooticeFat32Info(info, booticeDb, errorMessage)) {
        return rollback();
    }
    reportProgress(91, QStringLiteral("Recording Bootice FAT32 remaining clusters..."));
    if (!persistBooticeFat32Ranges(info, fat, booticeDb, errorMessage)) {
        return rollback();
    }
    reportProgress(94, QStringLiteral("Scanning Bootice FAT32 deleted directory entries..."));
    if (!scanBooticeDeletedFiles(info, fat, booticeDb, errorMessage)) {
        return rollback();
    }

    if (!booticeDb.commit()) {
        if (errorMessage) {
            *errorMessage = booticeDb.lastError().text();
        }
        return false;
    }
    return true;
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
        insert.addBindValue(formatHexDecimal(quint64(entry->meta->size), 8));
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








