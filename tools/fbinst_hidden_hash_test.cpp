#include "fbinstcarvingworker.h"
#include "showcaseanalyzer.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QSqlDatabase>
#include <QSqlError>
#include <QTextStream>

#include <atomic>
#include <memory>

namespace
{
QByteArray md5File(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }

    QCryptographicHash hash(QCryptographicHash::Md5);
    while (!file.atEnd()) {
        hash.addData(file.read(1024 * 1024));
    }
    return hash.result().toHex();
}

QString csv(QString value)
{
    value.replace('"', QStringLiteral("\"\""));
    return QStringLiteral("\"%1\"").arg(value);
}

bool openDatabase(QSqlDatabase *database, const QString &connectionName, const QString &path, QTextStream *err)
{
    *database = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), connectionName);
    database->setDatabaseName(path);
    if (database->open()) {
        return true;
    }
    *err << "Unable to open database " << path << ": " << database->lastError().text() << '\n';
    return false;
}

void closeDatabase(QSqlDatabase *database, const QString &connectionName)
{
    if (database->isValid() && database->isOpen()) {
        database->close();
    }
    *database = QSqlDatabase();
    QSqlDatabase::removeDatabase(connectionName);
}
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QTextStream out(stdout);
    QTextStream err(stderr);

    if (app.arguments().size() != 4) {
        err << "Usage: fbinst_hidden_hash_test <source-image> <original-files-root> <output-root>\n";
        return 1;
    }

    const QString sourcePath = QFileInfo(app.arguments().at(1)).absoluteFilePath();
    const QString originalsPath = QFileInfo(app.arguments().at(2)).absoluteFilePath();
    const QString outputPath = QFileInfo(app.arguments().at(3)).absoluteFilePath();
    if (!QFileInfo::exists(sourcePath) || !QFileInfo(originalsPath).isDir()) {
        err << "Source image or original-files root is unavailable.\n";
        return 2;
    }
    if (!QDir().mkpath(outputPath)) {
        err << "Unable to create output root: " << outputPath << '\n';
        return 3;
    }

    const QString partitionPath = QDir(outputPath).filePath(QStringLiteral("partition.db"));
    const QString booticePath = QDir(outputPath).filePath(QStringLiteral("bootice.db"));
    const QString fbinstPath = QDir(outputPath).filePath(QStringLiteral("fbinsttool.db"));
    const QString partitionConnection = QStringLiteral("hidden-test-partition");
    const QString booticeConnection = QStringLiteral("hidden-test-bootice");
    const QString fbinstConnection = QStringLiteral("hidden-test-fbinst");
    QSqlDatabase partitionDb;
    QSqlDatabase booticeDb;
    QSqlDatabase fbinstDb;

    if (!openDatabase(&partitionDb, partitionConnection, partitionPath, &err)
        || !openDatabase(&booticeDb, booticeConnection, booticePath, &err)
        || !openDatabase(&fbinstDb, fbinstConnection, fbinstPath, &err)) {
        closeDatabase(&partitionDb, partitionConnection);
        closeDatabase(&booticeDb, booticeConnection);
        closeDatabase(&fbinstDb, fbinstConnection);
        return 4;
    }

    out << "[analyze] source=" << sourcePath << '\n';
    out.flush();
    QString errorMessage;
    ShowcaseAnalyzer analyzer(sourcePath);
    analyzer.setProgressCallback([&out](int value, const QString &message) {
        out << "[analyze-progress] " << value << "% " << message << '\n';
        out.flush();
    });
    if (!analyzer.analyze(partitionDb, booticeDb, fbinstDb, &errorMessage)) {
        err << "[analyze-failed] " << errorMessage << '\n';
        closeDatabase(&partitionDb, partitionConnection);
        closeDatabase(&booticeDb, booticeConnection);
        closeDatabase(&fbinstDb, fbinstConnection);
        return 5;
    }
    closeDatabase(&partitionDb, partitionConnection);
    closeDatabase(&booticeDb, booticeConnection);
    closeDatabase(&fbinstDb, fbinstConnection);

    auto cancelled = std::make_shared<std::atomic_bool>(false);
    FbinstCarvingWorker worker(FbinstCarvingWorker::Params{sourcePath, fbinstPath, outputPath, cancelled});
    const FbinstCarvingWorker::Result result = worker.run(
        [&out](int value, const QString &message) {
            out << "[carve-progress] " << value << "% " << message << '\n';
            out.flush();
        },
        [&out](const QString &message) {
            out << "[carve-log] " << message << '\n';
            out.flush();
        });
    if (!result.ok) {
        err << "[carve-failed] " << result.message << '\n';
        return 6;
    }
    out << "[carve-done] ranges=" << result.rangeCount << " recovered=" << result.recoveredCount << '\n';
    out.flush();

    QHash<QByteArray, QStringList> originalsByHash;
    QDirIterator originalIt(originalsPath, QDir::Files, QDirIterator::Subdirectories);
    while (originalIt.hasNext()) {
        const QString path = originalIt.next();
        const QByteArray hash = md5File(path);
        if (!hash.isEmpty()) {
            originalsByHash[hash].append(QDir(originalsPath).relativeFilePath(path));
        }
    }

    QFile report(QDir(outputPath).filePath(QStringLiteral("hidden_hash_compare_report.csv")));
    QFile missingReport(QDir(outputPath).filePath(QStringLiteral("hidden_missing_originals.csv")));
    if (!report.open(QIODevice::WriteOnly | QIODevice::Text)
        || !missingReport.open(QIODevice::WriteOnly | QIODevice::Text)) {
        err << "Unable to create hash comparison reports.\n";
        return 7;
    }
    QTextStream reportOut(&report);
    QTextStream missingOut(&missingReport);
    reportOut.setEncoding(QStringConverter::Utf8);
    missingOut.setEncoding(QStringConverter::Utf8);
    reportOut << "recovered_relative_path,size,md5,exact_hash_match,original_relative_path\n";
    missingOut << "original_relative_path,md5\n";

    QHash<QByteArray, int> matchedHashes;
    int recoveredCount = 0;
    int exactMatchCount = 0;
    const QString recoveryPath = QDir(outputPath).filePath(QStringLiteral("fbinsttool_carving/internal"));
    QDirIterator recoveredIt(recoveryPath, QDir::Files, QDirIterator::Subdirectories);
    while (recoveredIt.hasNext()) {
        const QString path = recoveredIt.next();
        const QFileInfo info(path);
        const QByteArray hash = md5File(path);
        const bool exact = originalsByHash.contains(hash);
        ++recoveredCount;
        if (exact) {
            ++exactMatchCount;
            ++matchedHashes[hash];
        }
        reportOut << csv(QDir(outputPath).relativeFilePath(path)) << ','
                  << info.size() << ','
                  << csv(QString::fromLatin1(hash)) << ','
                  << (exact ? "true" : "false") << ','
                  << csv(exact ? originalsByHash.value(hash).join(QStringLiteral(";")) : QString()) << '\n';
    }

    int missingCount = 0;
    for (auto it = originalsByHash.cbegin(); it != originalsByHash.cend(); ++it) {
        if (matchedHashes.contains(it.key())) {
            continue;
        }
        for (const QString &relativePath : it.value()) {
            ++missingCount;
            missingOut << csv(relativePath) << ',' << csv(QString::fromLatin1(it.key())) << '\n';
        }
    }

    out << "[summary] originals=" << originalsByHash.size()
        << " recovered=" << recoveredCount
        << " exact_matches=" << exactMatchCount
        << " missing_originals=" << missingCount << '\n';
    out.flush();
    return 0;
}
