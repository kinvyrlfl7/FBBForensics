#include "signaturecarver.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QTextStream>

#include <algorithm>

namespace
{
QByteArray md5(const QByteArray &data)
{
    return QCryptographicHash::hash(data, QCryptographicHash::Md5).toHex();
}

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

QString csv(const QString &value)
{
    QString escaped = value;
    escaped.replace('"', QStringLiteral("\"\""));
    return QStringLiteral("\"%1\"").arg(escaped);
}

int confidenceRank(const QString &confidence)
{
    if (confidence == QStringLiteral("High")) {
        return 3;
    }
    if (confidence == QStringLiteral("Medium")) {
        return 2;
    }
    if (confidence == QStringLiteral("Low")) {
        return 1;
    }
    return 0;
}

void appendNonOverlapping(QVector<CarvedFile> *target, QVector<CarvedFile> files)
{
    std::sort(files.begin(), files.end(), [](const CarvedFile &left, const CarvedFile &right) {
        if (left.logicalStart == right.logicalStart) {
            const int leftRank = confidenceRank(left.confidence);
            const int rightRank = confidenceRank(right.confidence);
            if (leftRank != rightRank) {
                return leftRank > rightRank;
            }
            return left.logicalEnd > right.logicalEnd;
        }
        return left.logicalStart < right.logicalStart;
    });

    for (const CarvedFile &file : files) {
        if (!target->isEmpty() && file.logicalStart <= target->last().logicalEnd) {
            const int fileRank = confidenceRank(file.confidence);
            const int lastRank = confidenceRank(target->last().confidence);
            const quint64 fileSize = file.logicalEnd >= file.logicalStart ? file.logicalEnd - file.logicalStart : 0;
            const quint64 lastSize = target->last().logicalEnd >= target->last().logicalStart
                ? target->last().logicalEnd - target->last().logicalStart
                : 0;
            if (fileRank > lastRank
                || (file.logicalStart == target->last().logicalStart && fileRank == lastRank && fileSize > lastSize)) {
                target->last() = file;
            }
            continue;
        }
        target->append(file);
    }
}
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QTextStream out(stdout);
    QTextStream err(stderr);

    if (app.arguments().size() != 3) {
        err << "Usage: current_carving_hash_test <test-image-root> <output-root>\n";
        return 1;
    }

    const QDir testRoot(app.arguments().at(1));
    const QString outputRootPath = QDir::cleanPath(app.arguments().at(2));
    const QDir originalRoot(testRoot.filePath(QStringLiteral("Original_Files")));
    if (!testRoot.exists() || !originalRoot.exists()) {
        err << "Test image root or Original_Files directory does not exist.\n";
        return 2;
    }

    QDir outputRoot;
    if (!outputRoot.mkpath(outputRootPath)) {
        err << "Unable to create output directory: " << outputRootPath << '\n';
        return 3;
    }
    outputRoot.setPath(outputRootPath);

    QHash<QByteArray, QStringList> originalsByHash;
    QHash<QByteArray, QString> originalNameByHash;
    QDirIterator originalIt(originalRoot.absolutePath(), QDir::Files, QDirIterator::Subdirectories);
    while (originalIt.hasNext()) {
        const QString path = originalIt.next();
        const QByteArray hash = md5File(path);
        if (!hash.isEmpty()) {
            originalsByHash[hash].append(originalRoot.relativeFilePath(path));
            originalNameByHash.insert(hash, QFileInfo(path).fileName());
        }
    }

    QFile report(outputRoot.filePath(QStringLiteral("hash_compare_report.csv")));
    if (!report.open(QIODevice::WriteOnly | QIODevice::Text)) {
        err << "Unable to create report: " << report.fileName() << '\n';
        return 4;
    }
    QTextStream reportOut(&report);
    reportOut.setEncoding(QStringConverter::Utf8);
    reportOut << "image,logical_start,size,extension,file_type,carving_method,selected_method,attempted_methods,validation_result,confidence,md5,exact_hash_match,original_name,original_relative_path,output_file\n";

    QFile missingReport(outputRoot.filePath(QStringLiteral("missing_originals.csv")));
    if (!missingReport.open(QIODevice::WriteOnly | QIODevice::Text)) {
        err << "Unable to create missing report: " << missingReport.fileName() << '\n';
        return 5;
    }
    QTextStream missingOut(&missingReport);
    missingOut.setEncoding(QStringConverter::Utf8);
    missingOut << "original_relative_path,md5\n";

    QStringList images = testRoot.entryList({QStringLiteral("*.dd")}, QDir::Files, QDir::Name);
    QHash<QByteArray, int> matchedHashes;
    int carvedCount = 0;
    int exactMatchCount = 0;

    SignatureCarver carver;
    for (const QString &imageName : images) {
        QFile image(testRoot.filePath(imageName));
        if (!image.open(QIODevice::ReadOnly)) {
            err << "Unable to read image: " << image.fileName() << '\n';
            return 6;
        }

        out << "[scan] " << imageName << " size=" << image.size() << '\n';
        out.flush();
        const QByteArray stream = image.readAll();
        const QString imageStem = QFileInfo(imageName).completeBaseName();
        if (!outputRoot.mkpath(imageStem)) {
            err << "Unable to create image output directory: " << imageStem << '\n';
            return 7;
        }

        int imageCarvedCount = 0;
        QVector<CarvedFile> carved;
        QVector<CarvedFile> validated;
        const QVector<CarveCandidateInfo> candidates = carver.scan(stream, 512, 0);
        out << "[index] " << imageName << " candidates=" << candidates.size() << '\n';
        out.flush();
        for (const CarveCandidateInfo &candidate : candidates) {
            std::optional<CarvedFile> file = carver.validate(stream, candidate);
            if (!file.has_value()) {
                continue;
            }
            validated.append(*file);
        }
        appendNonOverlapping(&carved, validated);
        for (const CarvedFile &file : carved) {
            ++carvedCount;
            ++imageCarvedCount;
            const quint64 fileSize = file.logicalEnd >= file.logicalStart
                ? file.logicalEnd - file.logicalStart + 1
                : 0;
            const QByteArray carvedData = stream.mid(qsizetype(file.logicalStart), qsizetype(fileSize));
            const QByteArray hash = md5(carvedData);
            const bool exact = originalsByHash.contains(hash);
            if (exact) {
                ++exactMatchCount;
                ++matchedHashes[hash];
            }

            const QString outputName = QStringLiteral("%1_%2_%3.%4")
                                           .arg(imageCarvedCount, 3, 10, QChar('0'))
                                           .arg(file.logicalStart, 10, 10, QChar('0'))
                                           .arg(fileSize, 10, 10, QChar('0'))
                                           .arg(file.extension);
            const QString outputPath = outputRoot.filePath(imageStem + QLatin1Char('/') + outputName);
            QFile extracted(outputPath);
            if (!extracted.open(QIODevice::WriteOnly) || extracted.write(carvedData) != carvedData.size()) {
                err << "Unable to write carved file: " << outputPath << '\n';
                return 8;
            }

            const QStringList originalPaths = originalsByHash.value(hash);
            reportOut << csv(imageName) << ','
                      << file.logicalStart << ','
                      << fileSize << ','
                      << csv(file.extension) << ','
                      << csv(file.fileType) << ','
                      << csv(file.carvingMethod) << ','
                      << csv(file.selectedMethod) << ','
                      << csv(file.attemptedMethods) << ','
                      << csv(file.validationResult) << ','
                      << csv(file.confidence) << ','
                      << csv(QString::fromLatin1(hash)) << ','
                      << (exact ? "true" : "false") << ','
                      << csv(exact ? originalNameByHash.value(hash) : QString()) << ','
                      << csv(exact ? originalPaths.join(QStringLiteral(";")) : QString()) << ','
                      << csv(outputPath) << '\n';
        }

        out << "[done] " << imageName << " carved=" << imageCarvedCount << '\n';
        out.flush();
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
        << " carved=" << carvedCount
        << " exact_matches=" << exactMatchCount
        << " missing_originals=" << missingCount << '\n';
    return 0;
}
