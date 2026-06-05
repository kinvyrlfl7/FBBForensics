#pragma once

#include <QDateTime>
#include <QElapsedTimer>
#include <QHash>
#include <QString>

#include <optional>

class BenchmarkRecorder
{
public:
    struct RunConfig
    {
        QString scenarioName;
        QString sourcePath;
        QString hiddenType;
        QString operation;
        QString notes;
    };

    explicit BenchmarkRecorder(QString databasePath);
    ~BenchmarkRecorder();

    bool isEnabled() const;
    bool initialize(QString *errorMessage = nullptr);
    qint64 beginRun(const RunConfig &config, QString *errorMessage = nullptr);
    void finishRun(const QString &status, const QString &notes = QString());
    qint64 beginStage(const QString &stageName, QString *errorMessage = nullptr);
    void finishStage(qint64 stageId,
                     const QString &status,
                     quint64 bytesRead = 0,
                     quint64 bytesWritten = 0,
                     quint64 itemsProcessed = 0,
                     const QString &notes = QString());
    void sample(const QString &stageName, int progressPercent, const QString &currentStep);
    qint64 currentRunId() const;

    static bool initializeDatabase(const QString &databasePath, QString *errorMessage = nullptr);

private:
    struct ResourceSnapshot
    {
        quint64 userCpuMs = 0;
        quint64 kernelCpuMs = 0;
        quint64 workingSetBytes = 0;
        quint64 privateBytes = 0;
        quint64 peakWorkingSetBytes = 0;
        QDateTime wallTimeUtc;
    };

    struct StageState
    {
        QString name;
        QElapsedTimer timer;
        ResourceSnapshot start;
    };

    static ResourceSnapshot captureResources();
    static QString utcNow();

    bool open(QString *errorMessage);
    void close();
    void ensureRunOpen();
    double cpuPercentSinceLastSample(const ResourceSnapshot &snapshot, qint64 elapsedMs);

    QString m_databasePath;
    QString m_connectionName;
    qint64 m_runId = -1;
    QElapsedTimer m_runTimer;
    ResourceSnapshot m_runStart;
    ResourceSnapshot m_lastSample;
    qint64 m_lastSampleElapsedMs = 0;
    QHash<qint64, StageState> m_stages;
    bool m_open = false;
};

class BenchmarkStageScope
{
public:
    BenchmarkStageScope(BenchmarkRecorder *recorder, QString stageName);
    ~BenchmarkStageScope();

    void addBytesRead(quint64 value);
    void addBytesWritten(quint64 value);
    void addItems(quint64 value);
    void setStatus(const QString &status);
    void setNotes(const QString &notes);
    qint64 id() const;

private:
    BenchmarkRecorder *m_recorder = nullptr;
    qint64 m_stageId = -1;
    quint64 m_bytesRead = 0;
    quint64 m_bytesWritten = 0;
    quint64 m_items = 0;
    QString m_status = QStringLiteral("Completed");
    QString m_notes;
};
