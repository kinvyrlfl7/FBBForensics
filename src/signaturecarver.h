#pragma once

#include <QVector>
#include <QString>

#include <functional>
#include <optional>

class QByteArray;

struct CarvedFile
{
    QString fileType;
    QString extension;
    quint64 logicalStart = 0;
    quint64 logicalEnd = 0;
    QByteArray data;
    QString carvingMethod;
    QString validationResult;
    QString confidence;
    QString notes;
    qint64 candidateId = -1;
    QString attemptedMethods;
    QString selectedMethod;
    QString rejectReason;
};

struct CarveCandidateInfo
{
    quint64 logicalOffset = 0;
    QString family;
    QString signatureHex;
    QString expectedExtension;
    QString expectedType;
};

class SignatureCarver
{
public:
    using LogCallback = std::function<void(const QString &)>;

    QVector<CarvedFile> carve(const QByteArray &stream, qsizetype scanStride = 512) const;
    QVector<CarvedFile> carve(const QByteArray &stream, qsizetype scanStride, quint64 logicalBaseOffset) const;
    QVector<CarvedFile> carve(const QByteArray &stream, qsizetype scanStride, quint64 logicalBaseOffset, const LogCallback &logCallback) const;
    QVector<CarveCandidateInfo> scan(const QByteArray &stream, qsizetype scanStride, quint64 logicalBaseOffset = 0) const;
    std::optional<CarvedFile> validate(const QByteArray &stream, const CarveCandidateInfo &candidate) const;

private:
    struct CarveCandidate;
    struct FormatCarver;

    static QVector<CarveCandidate> scanCandidates(const QByteArray &stream, qsizetype scanStride, qsizetype windowStart, qsizetype windowEnd);
    static QVector<FormatCarver> carvers();
};
