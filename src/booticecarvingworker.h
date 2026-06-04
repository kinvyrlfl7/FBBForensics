#pragma once

#include <QString>

#include <atomic>
#include <functional>
#include <memory>

class BooticeCarvingWorker
{
public:
    struct Params
    {
        QString sourcePath;
        QString booticeDbPath;
        QString outputDir;
        std::shared_ptr<std::atomic_bool> cancelRequested;
    };

    struct Result
    {
        bool ok = false;
        bool cancelled = false;
        int recoveredCount = 0;
        int rangeCount = 0;
        QString message;
    };

    using ProgressCallback = std::function<void(int, const QString &)>;
    using LogCallback = std::function<void(const QString &)>;

    explicit BooticeCarvingWorker(Params params);

    Result run(const ProgressCallback &progressCallback, const LogCallback &logCallback);

private:
    Params m_params;
};
