#include "signaturecarver.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>

#include <optional>

namespace
{
QString unquote(QString value)
{
    value = value.trimmed();
    if (value.size() >= 2 && value.startsWith(QLatin1Char('"')) && value.endsWith(QLatin1Char('"'))) {
        value = value.mid(1, value.size() - 2);
    }
    return value;
}

QString familyFor(const QString &path, const QByteArray &data)
{
    const QString extension = QFileInfo(path).suffix().toLower();
    if (extension == QStringLiteral("docx") || extension == QStringLiteral("xlsx") || extension == QStringLiteral("pptx")) return QStringLiteral("zip");
    if (extension == QStringLiteral("wav") || extension == QStringLiteral("avi")) return QStringLiteral("riff");
    if (extension == QStringLiteral("mp4") || extension == QStringLiteral("mov")) return QStringLiteral("mp4");
    if (extension == QStringLiteral("wma") || extension == QStringLiteral("wmv")) return QStringLiteral("wmv");
    if (extension == QStringLiteral("gif")) return data.startsWith("GIF87a") ? QStringLiteral("gif87") : QStringLiteral("gif89");
    if (extension == QStringLiteral("tif")) return data.startsWith("II") ? QStringLiteral("tif-le") : QStringLiteral("tif-be");
    if (extension == QStringLiteral("mp3")) return data.startsWith("ID3") ? QStringLiteral("mp3-id3") : QStringLiteral("mp3-frame");
    if (extension == QStringLiteral("mpg")) return QStringLiteral("mpeg-pack");
    return extension;
}

QByteArray md5(const QByteArray &data)
{
    return QCryptographicHash::hash(data, QCryptographicHash::Md5).toHex();
}

QString csv(QString value)
{
    value.replace('"', QStringLiteral("\"\""));
    return QStringLiteral("\"%1\"").arg(value);
}
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QTextStream out(stdout);
    QTextStream err(stderr);
    if (app.arguments().size() != 5) {
        err << "Usage: targeted_signature_validation <source-image> <presence-report> <original-root> <output-report>\n";
        return 1;
    }

    QFile source(app.arguments().at(1));
    QFile presence(app.arguments().at(2));
    const QString originalRoot = app.arguments().at(3);
    QFile report(app.arguments().at(4));
    if (!source.open(QIODevice::ReadOnly)
        || !presence.open(QIODevice::ReadOnly | QIODevice::Text)
        || !report.open(QIODevice::WriteOnly | QIODevice::Text)) {
        err << "Unable to open one or more input/output files.\n";
        return 2;
    }

    QTextStream presenceIn(&presence);
    QTextStream reportOut(&report);
    reportOut.setEncoding(QStringConverter::Utf8);
    reportOut << "original_relative_path,physical_byte_offset,original_size,parsed_size,original_md5,parsed_md5,exact_hash_match,expected_extension,recovered_extension,selected_method,validation_result,confidence\n";
    presenceIn.readLine();

    SignatureCarver carver;
    int total = 0;
    int validated = 0;
    int exact = 0;
    while (!presenceIn.atEnd()) {
        const QString line = presenceIn.readLine();
        const QStringList columns = line.split(QLatin1Char(','));
        if (columns.size() < 6 || unquote(columns.at(3)) != QStringLiteral("True")) {
            continue;
        }
        const QString relativePath = unquote(columns.at(0));
        const quint64 originalSize = unquote(columns.at(1)).toULongLong();
        const quint64 physicalOffset = unquote(columns.at(4)).toULongLong();
        QFile original(QFileInfo(originalRoot + QLatin1Char('/') + relativePath).absoluteFilePath());
        if (!original.open(QIODevice::ReadOnly)) {
            err << "Unable to open original: " << relativePath << '\n';
            return 3;
        }
        const QByteArray originalData = original.readAll();
        const quint64 contextSize = qMin<quint64>(source.size() - physicalOffset, originalSize + 2ULL * 1024 * 1024);
        if (!source.seek(qint64(physicalOffset))) {
            err << "Unable to seek source for: " << relativePath << '\n';
            return 4;
        }
        const QByteArray context = source.read(qint64(contextSize));
        CarveCandidateInfo candidate;
        candidate.logicalOffset = 0;
        candidate.family = familyFor(relativePath, originalData);
        const std::optional<CarvedFile> carved = carver.validate(context, candidate);
        ++total;

        quint64 parsedSize = 0;
        QByteArray parsedMd5;
        QString recoveredExtension;
        QString selectedMethod;
        QString validationResult;
        QString confidence;
        if (carved.has_value()) {
            ++validated;
            parsedSize = carved->logicalEnd >= carved->logicalStart ? carved->logicalEnd - carved->logicalStart + 1 : 0;
            parsedMd5 = md5(context.mid(qsizetype(carved->logicalStart), qsizetype(parsedSize)));
            recoveredExtension = carved->extension;
            selectedMethod = carved->selectedMethod;
            validationResult = carved->validationResult;
            confidence = carved->confidence;
        }
        const QByteArray originalMd5 = md5(originalData);
        const bool hashMatch = !parsedMd5.isEmpty() && parsedMd5 == originalMd5;
        if (hashMatch) {
            ++exact;
        }
        const QString expectedExtension = QFileInfo(relativePath).suffix().toLower();
        reportOut << csv(relativePath) << ','
                  << physicalOffset << ','
                  << originalSize << ','
                  << parsedSize << ','
                  << csv(QString::fromLatin1(originalMd5)) << ','
                  << csv(QString::fromLatin1(parsedMd5)) << ','
                  << (hashMatch ? "true" : "false") << ','
                  << csv(expectedExtension) << ','
                  << csv(recoveredExtension) << ','
                  << csv(selectedMethod) << ','
                  << csv(validationResult) << ','
                  << csv(confidence) << '\n';
        out << '[' << (hashMatch ? "exact" : "mismatch") << "] "
            << relativePath << " family=" << candidate.family
            << " expected_size=" << originalSize << " parsed_size=" << parsedSize
            << " ext=" << recoveredExtension << '\n';
        out.flush();
    }

    out << "[summary] targeted=" << total << " validated=" << validated << " exact_matches=" << exact << '\n';
    return 0;
}
