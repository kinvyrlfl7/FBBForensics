#include "benchmarkrecorder.h"

#include <QFileInfo>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QStringList>
#include <QUuid>
#include <QtGlobal>

#include <windows.h>
#include <psapi.h>

#include <utility>

namespace
{
quint64 fileTimeToMs(const FILETIME &fileTime)
{
    ULARGE_INTEGER value{};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;
    return value.QuadPart / 10000ULL;
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
}

BenchmarkRecorder::BenchmarkRecorder(QString databasePath)
    : m_databasePath(std::move(databasePath))
    , m_connectionName(QStringLiteral("benchmark_%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces)))
{
}

BenchmarkRecorder::~BenchmarkRecorder()
{
    close();
}

bool BenchmarkRecorder::isEnabled() const
{
    return !m_databasePath.trimmed().isEmpty();
}

bool BenchmarkRecorder::initialize(QString *errorMessage)
{
    return initializeDatabase(m_databasePath, errorMessage);
}

bool BenchmarkRecorder::initializeDatabase(const QString &databasePath, QString *errorMessage)
{
    if (databasePath.trimmed().isEmpty()) {
        return true;
    }

    const QString connectionName = QStringLiteral("benchmark_init_%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
    {
        QSqlDatabase db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), connectionName);
        db.setDatabaseName(databasePath);
        if (!db.open()) {
            if (errorMessage) {
                *errorMessage = db.lastError().text();
            }
            db = QSqlDatabase();
            QSqlDatabase::removeDatabase(connectionName);
            return false;
        }

        const QStringList schema{
            QStringLiteral(
                "CREATE TABLE IF NOT EXISTS Benchmark_Runs ("
                "Run_Id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "Tool_Version TEXT,"
                "Git_Commit TEXT,"
                "Scenario_Name TEXT,"
                "Source_Path TEXT,"
                "Source_Size_Bytes INTEGER,"
                "Hidden_Type TEXT,"
                "Operation TEXT,"
                "Started_At TEXT,"
                "Ended_At TEXT,"
                "Elapsed_Ms INTEGER,"
                "Cpu_User_Ms INTEGER,"
                "Cpu_Kernel_Ms INTEGER,"
                "Cpu_Total_Ms INTEGER,"
                "Working_Set_Start_Bytes INTEGER,"
                "Working_Set_End_Bytes INTEGER,"
                "Peak_Working_Set_Bytes INTEGER,"
                "Private_Bytes_Start INTEGER,"
                "Private_Bytes_End INTEGER,"
                "Status TEXT,"
                "Notes TEXT)"),
            QStringLiteral(
                "CREATE TABLE IF NOT EXISTS Benchmark_Stages ("
                "Stage_Id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "Run_Id INTEGER,"
                "Stage_Name TEXT,"
                "Started_At TEXT,"
                "Ended_At TEXT,"
                "Elapsed_Ms INTEGER,"
                "Cpu_User_Ms INTEGER,"
                "Cpu_Kernel_Ms INTEGER,"
                "Cpu_Total_Ms INTEGER,"
                "Working_Set_Start_Bytes INTEGER,"
                "Working_Set_End_Bytes INTEGER,"
                "Peak_Working_Set_Bytes INTEGER,"
                "Private_Bytes_Start INTEGER,"
                "Private_Bytes_End INTEGER,"
                "Bytes_Read INTEGER,"
                "Bytes_Written INTEGER,"
                "Items_Processed INTEGER,"
                "Throughput_MBps REAL,"
                "Status TEXT,"
                "Notes TEXT)"),
            QStringLiteral(
                "CREATE TABLE IF NOT EXISTS Benchmark_Samples ("
                "Sample_Id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "Run_Id INTEGER,"
                "Stage_Name TEXT,"
                "Sample_Time TEXT,"
                "Elapsed_Ms INTEGER,"
                "Cpu_Percent REAL,"
                "Process_User_Cpu_Ms INTEGER,"
                "Process_Kernel_Cpu_Ms INTEGER,"
                "Working_Set_Bytes INTEGER,"
                "Private_Bytes INTEGER,"
                "Peak_Working_Set_Bytes INTEGER,"
                "Progress_Percent INTEGER,"
                "Current_Step TEXT)"),
            QStringLiteral(
                "CREATE TABLE IF NOT EXISTS Benchmark_Results ("
                "Result_Id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "Run_Id INTEGER,"
                "Candidate_Count INTEGER,"
                "Recovered_Count INTEGER,"
                "Rejected_Count INTEGER,"
                "Duplicate_Count INTEGER,"
                "Hash_Matched_Count INTEGER,"
                "Hash_Missing_Count INTEGER,"
                "Hash_Extra_Count INTEGER,"
                "Accuracy_Percent REAL,"
                "Notes TEXT)")
        };
        for (const QString &sql : schema) {
            if (!execSql(db, sql, errorMessage)) {
                db.close();
                db = QSqlDatabase();
                QSqlDatabase::removeDatabase(connectionName);
                return false;
            }
        }
        db.close();
    }
    QSqlDatabase::removeDatabase(connectionName);
    return true;
}

bool BenchmarkRecorder::open(QString *errorMessage)
{
    if (!isEnabled()) {
        return false;
    }
    if (m_open) {
        return true;
    }
    QSqlDatabase db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), m_connectionName);
    db.setDatabaseName(m_databasePath);
    if (!db.open()) {
        if (errorMessage) {
            *errorMessage = db.lastError().text();
        }
        db = QSqlDatabase();
        QSqlDatabase::removeDatabase(m_connectionName);
        return false;
    }
    QSqlQuery pragma(db);
    pragma.exec(QStringLiteral("PRAGMA busy_timeout=30000"));
    m_open = true;
    return true;
}

void BenchmarkRecorder::close()
{
    if (m_open && QSqlDatabase::contains(m_connectionName)) {
        QSqlDatabase db = QSqlDatabase::database(m_connectionName);
        if (db.isOpen()) {
            db.close();
        }
        db = QSqlDatabase();
    }
    if (QSqlDatabase::contains(m_connectionName)) {
        QSqlDatabase::removeDatabase(m_connectionName);
    }
    m_open = false;
}

qint64 BenchmarkRecorder::beginRun(const RunConfig &config, QString *errorMessage)
{
    if (!open(errorMessage) || !initialize(errorMessage)) {
        return -1;
    }
    QSqlDatabase db = QSqlDatabase::database(m_connectionName);
    m_runStart = captureResources();
    m_lastSample = m_runStart;
    m_runTimer.start();
    m_lastSampleElapsedMs = 0;

    QSqlQuery insert(db);
    insert.prepare(QStringLiteral(
        "INSERT INTO Benchmark_Runs("
        "Tool_Version, Git_Commit, Scenario_Name, Source_Path, Source_Size_Bytes, Hidden_Type, Operation, "
        "Started_At, Working_Set_Start_Bytes, Private_Bytes_Start, Status, Notes"
        ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"));
    insert.addBindValue(QStringLiteral("FBBForensics"));
    insert.addBindValue(QString());
    insert.addBindValue(config.scenarioName);
    insert.addBindValue(QFileInfo(config.sourcePath).absoluteFilePath());
    insert.addBindValue(QFileInfo(config.sourcePath).exists() ? QFileInfo(config.sourcePath).size() : 0);
    insert.addBindValue(config.hiddenType);
    insert.addBindValue(config.operation);
    insert.addBindValue(utcNow());
    insert.addBindValue(m_runStart.workingSetBytes);
    insert.addBindValue(m_runStart.privateBytes);
    insert.addBindValue(QStringLiteral("Running"));
    insert.addBindValue(config.notes);
    if (!insert.exec()) {
        if (errorMessage) {
            *errorMessage = insert.lastError().text();
        }
        return -1;
    }
    m_runId = insert.lastInsertId().toLongLong();
    sample(QStringLiteral("Run"), 0, QStringLiteral("Benchmark run started"));
    return m_runId;
}

void BenchmarkRecorder::finishRun(const QString &status, const QString &notes)
{
    if (m_runId < 0 || !m_open) {
        return;
    }
    const ResourceSnapshot end = captureResources();
    const qint64 elapsedMs = m_runTimer.isValid() ? m_runTimer.elapsed() : 0;
    QSqlDatabase db = QSqlDatabase::database(m_connectionName);
    QSqlQuery update(db);
    update.prepare(QStringLiteral(
        "UPDATE Benchmark_Runs SET Ended_At=?, Elapsed_Ms=?, Cpu_User_Ms=?, Cpu_Kernel_Ms=?, Cpu_Total_Ms=?, "
        "Working_Set_End_Bytes=?, Peak_Working_Set_Bytes=?, Private_Bytes_End=?, Status=?, Notes=? WHERE Run_Id=?"));
    const quint64 userDelta = end.userCpuMs >= m_runStart.userCpuMs ? end.userCpuMs - m_runStart.userCpuMs : 0;
    const quint64 kernelDelta = end.kernelCpuMs >= m_runStart.kernelCpuMs ? end.kernelCpuMs - m_runStart.kernelCpuMs : 0;
    update.addBindValue(utcNow());
    update.addBindValue(elapsedMs);
    update.addBindValue(userDelta);
    update.addBindValue(kernelDelta);
    update.addBindValue(userDelta + kernelDelta);
    update.addBindValue(end.workingSetBytes);
    update.addBindValue(end.peakWorkingSetBytes);
    update.addBindValue(end.privateBytes);
    update.addBindValue(status);
    update.addBindValue(notes);
    update.addBindValue(m_runId);
    update.exec();
    sample(QStringLiteral("Run"), 100, QStringLiteral("Benchmark run finished"));
}

qint64 BenchmarkRecorder::beginStage(const QString &stageName, QString *errorMessage)
{
    if (m_runId < 0 || !m_open) {
        return -1;
    }
    const ResourceSnapshot start = captureResources();
    QSqlDatabase db = QSqlDatabase::database(m_connectionName);
    QSqlQuery insert(db);
    insert.prepare(QStringLiteral(
        "INSERT INTO Benchmark_Stages("
        "Run_Id, Stage_Name, Started_At, Working_Set_Start_Bytes, Private_Bytes_Start, Status"
        ") VALUES(?, ?, ?, ?, ?, ?)"));
    insert.addBindValue(m_runId);
    insert.addBindValue(stageName);
    insert.addBindValue(utcNow());
    insert.addBindValue(start.workingSetBytes);
    insert.addBindValue(start.privateBytes);
    insert.addBindValue(QStringLiteral("Running"));
    if (!insert.exec()) {
        if (errorMessage) {
            *errorMessage = insert.lastError().text();
        }
        return -1;
    }
    const qint64 stageId = insert.lastInsertId().toLongLong();
    StageState state;
    state.name = stageName;
    state.timer.start();
    state.start = start;
    m_stages.insert(stageId, state);
    sample(stageName, -1, QStringLiteral("Stage started"));
    return stageId;
}

void BenchmarkRecorder::finishStage(qint64 stageId,
                                    const QString &status,
                                    quint64 bytesRead,
                                    quint64 bytesWritten,
                                    quint64 itemsProcessed,
                                    const QString &notes)
{
    if (stageId < 0 || !m_open) {
        return;
    }
    StageState state = m_stages.take(stageId);
    if (!state.timer.isValid()) {
        return;
    }
    const ResourceSnapshot end = captureResources();
    const qint64 elapsedMs = qMax<qint64>(1, state.timer.elapsed());
    const quint64 userDelta = end.userCpuMs >= state.start.userCpuMs ? end.userCpuMs - state.start.userCpuMs : 0;
    const quint64 kernelDelta = end.kernelCpuMs >= state.start.kernelCpuMs ? end.kernelCpuMs - state.start.kernelCpuMs : 0;
    QSqlDatabase db = QSqlDatabase::database(m_connectionName);
    QSqlQuery update(db);
    update.prepare(QStringLiteral(
        "UPDATE Benchmark_Stages SET Ended_At=?, Elapsed_Ms=?, Cpu_User_Ms=?, Cpu_Kernel_Ms=?, Cpu_Total_Ms=?, "
        "Working_Set_End_Bytes=?, Peak_Working_Set_Bytes=?, Private_Bytes_End=?, Bytes_Read=?, Bytes_Written=?, "
        "Items_Processed=?, Throughput_MBps=?, Status=?, Notes=? WHERE Stage_Id=?"));
    const double throughput = bytesRead > 0 ? (double(bytesRead) / (1024.0 * 1024.0)) / (double(elapsedMs) / 1000.0) : 0.0;
    update.addBindValue(utcNow());
    update.addBindValue(elapsedMs);
    update.addBindValue(userDelta);
    update.addBindValue(kernelDelta);
    update.addBindValue(userDelta + kernelDelta);
    update.addBindValue(end.workingSetBytes);
    update.addBindValue(end.peakWorkingSetBytes);
    update.addBindValue(end.privateBytes);
    update.addBindValue(bytesRead);
    update.addBindValue(bytesWritten);
    update.addBindValue(itemsProcessed);
    update.addBindValue(throughput);
    update.addBindValue(status);
    update.addBindValue(notes);
    update.addBindValue(stageId);
    update.exec();
}

void BenchmarkRecorder::sample(const QString &stageName, int progressPercent, const QString &currentStep)
{
    if (m_runId < 0 || !m_open) {
        return;
    }
    const ResourceSnapshot snapshot = captureResources();
    const qint64 elapsedMs = m_runTimer.isValid() ? m_runTimer.elapsed() : 0;
    const double cpuPercent = cpuPercentSinceLastSample(snapshot, elapsedMs);
    QSqlDatabase db = QSqlDatabase::database(m_connectionName);
    QSqlQuery insert(db);
    insert.prepare(QStringLiteral(
        "INSERT INTO Benchmark_Samples("
        "Run_Id, Stage_Name, Sample_Time, Elapsed_Ms, Cpu_Percent, Process_User_Cpu_Ms, Process_Kernel_Cpu_Ms, "
        "Working_Set_Bytes, Private_Bytes, Peak_Working_Set_Bytes, Progress_Percent, Current_Step"
        ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"));
    insert.addBindValue(m_runId);
    insert.addBindValue(stageName);
    insert.addBindValue(utcNow());
    insert.addBindValue(elapsedMs);
    insert.addBindValue(cpuPercent);
    insert.addBindValue(snapshot.userCpuMs);
    insert.addBindValue(snapshot.kernelCpuMs);
    insert.addBindValue(snapshot.workingSetBytes);
    insert.addBindValue(snapshot.privateBytes);
    insert.addBindValue(snapshot.peakWorkingSetBytes);
    insert.addBindValue(progressPercent);
    insert.addBindValue(currentStep);
    insert.exec();
    m_lastSample = snapshot;
    m_lastSampleElapsedMs = elapsedMs;
}

qint64 BenchmarkRecorder::currentRunId() const
{
    return m_runId;
}

BenchmarkRecorder::ResourceSnapshot BenchmarkRecorder::captureResources()
{
    ResourceSnapshot snapshot;
    snapshot.wallTimeUtc = QDateTime::currentDateTimeUtc();

    FILETIME createTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    if (GetProcessTimes(GetCurrentProcess(), &createTime, &exitTime, &kernelTime, &userTime)) {
        snapshot.userCpuMs = fileTimeToMs(userTime);
        snapshot.kernelCpuMs = fileTimeToMs(kernelTime);
    }

    PROCESS_MEMORY_COUNTERS_EX counters{};
    counters.cb = sizeof(counters);
    if (GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&counters), sizeof(counters))) {
        snapshot.workingSetBytes = quint64(counters.WorkingSetSize);
        snapshot.privateBytes = quint64(counters.PrivateUsage);
        snapshot.peakWorkingSetBytes = quint64(counters.PeakWorkingSetSize);
    }
    return snapshot;
}

QString BenchmarkRecorder::utcNow()
{
    return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
}

double BenchmarkRecorder::cpuPercentSinceLastSample(const ResourceSnapshot &snapshot, qint64 elapsedMs)
{
    const qint64 wallDelta = elapsedMs - m_lastSampleElapsedMs;
    if (wallDelta <= 0) {
        return 0.0;
    }
    const quint64 previousCpu = m_lastSample.userCpuMs + m_lastSample.kernelCpuMs;
    const quint64 currentCpu = snapshot.userCpuMs + snapshot.kernelCpuMs;
    const quint64 cpuDelta = currentCpu >= previousCpu ? currentCpu - previousCpu : 0;
    return (double(cpuDelta) / double(wallDelta)) * 100.0;
}

BenchmarkStageScope::BenchmarkStageScope(BenchmarkRecorder *recorder, QString stageName)
    : m_recorder(recorder)
{
    if (m_recorder && m_recorder->isEnabled()) {
        m_stageId = m_recorder->beginStage(stageName);
    }
}

BenchmarkStageScope::~BenchmarkStageScope()
{
    if (m_recorder && m_stageId >= 0) {
        m_recorder->finishStage(m_stageId, m_status, m_bytesRead, m_bytesWritten, m_items, m_notes);
    }
}

void BenchmarkStageScope::addBytesRead(quint64 value)
{
    m_bytesRead += value;
}

void BenchmarkStageScope::addBytesWritten(quint64 value)
{
    m_bytesWritten += value;
}

void BenchmarkStageScope::addItems(quint64 value)
{
    m_items += value;
}

void BenchmarkStageScope::setStatus(const QString &status)
{
    m_status = status;
}

void BenchmarkStageScope::setNotes(const QString &notes)
{
    m_notes = notes;
}

qint64 BenchmarkStageScope::id() const
{
    return m_stageId;
}
