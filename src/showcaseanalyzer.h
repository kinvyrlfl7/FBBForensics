#pragma once

#include "imagereader.h"

#include <QDateTime>
#include <QSet>
#include <QSqlDatabase>
#include <QString>
#include <QVector>

#include <functional>
#include <memory>

class ShowcaseAnalyzer
{
public:
    static constexpr quint32 SectorSize = 512;
    static constexpr quint32 ClusterSize = 4096;

    explicit ShowcaseAnalyzer(const QString &sourcePath);

    void setProgressCallback(std::function<void(int, const QString &)> callback);
    bool analyze(QSqlDatabase &partitionDb, QSqlDatabase &booticeDb, QSqlDatabase &fbinstDb, QString *errorMessage = nullptr);

private:
    struct FbinstHeader
    {
        quint16 listUsed = 0;
        quint16 listSize = 0;
    };

    void reportProgress(int value, const QString &message) const;

    QString m_sourcePath;
    std::unique_ptr<ImageReader> m_reader;
    QVector<quint32> m_primarySectors;
    QVector<quint32> m_extendedSectors;
    std::function<void(int, const QString &)> m_progressCallback;

    bool resetPartitionSchema(QSqlDatabase &database, QString *errorMessage) const;
    bool resetBooticeSchema(QSqlDatabase &database, QString *errorMessage) const;
    bool resetFbinstSchema(QSqlDatabase &database, QString *errorMessage) const;
    bool createPartitionTables(QSqlDatabase &database, QString *errorMessage) const;
    bool createBooticeTables(QSqlDatabase &database, QString *errorMessage) const;
    bool createFbinstTables(QSqlDatabase &database, QString *errorMessage) const;
    bool recordSummary(QSqlDatabase &database, const QString &key, const QString &value, QString *errorMessage) const;

    bool readMbr(QSqlDatabase &partitionDb, QSqlDatabase &booticeDb, QSqlDatabase &fbinstDb, QString *errorMessage);
    bool analyzeUltraIso(QSqlDatabase &partitionDb, QSqlDatabase &booticeDb, QString *errorMessage);
    bool analyzeFbinst(QSqlDatabase &partitionDb, QSqlDatabase &fbinstDb, QString *errorMessage);
    bool analyzeFbinstFileList(ImageReader &reader, quint16 fbinstVersion, const FbinstHeader &header, QSqlDatabase &fbinstDb, QString *errorMessage);

    bool enumeratePartitions(QSqlDatabase &partitionDb, QString *errorMessage);
    bool enumerateBooticeRoot(quint64 startLba, QSqlDatabase &booticeDb, QString *errorMessage);

    void recordPrimaryAreaSectors(quint32 start, quint32 fileSize);
    void recordExtendedAreaSectors(quint32 start, quint32 fileSize);
    bool persistFbinstSectors(QSqlDatabase &fbinstDb, const FbinstHeader &header, quint32 primarySize, quint32 extendedSize, QString *errorMessage);
    bool persistRemainingSectors(QSqlDatabase &fbinstDb, const QVector<quint32> &sectors, const QString &areaType, quint64 areaStart, quint64 areaEnd, QString *errorMessage);

    QByteArray readBytes(ImageReader &reader, quint64 offset, quint64 size, QString *errorMessage) const;
    static quint16 readLe16(const QByteArray &data, int offset);
    static quint32 readLe32(const QByteArray &data, int offset);
    static quint64 readLe64(const QByteArray &data, int offset);
    static QString formatUnixTime(quint64 value);
    static QString formatFbinstVersion(quint16 value);
    static QString partitionTypeToString(quint8 type);
    static QString dataAreaToString(quint8 area);
};


