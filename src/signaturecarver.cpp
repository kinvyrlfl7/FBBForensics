#include "signaturecarver.h"

#include <QByteArray>

#include <algorithm>
#include <cstdlib>
#include <future>
#include <limits>
#include <optional>
#include <thread>
#include <vector>

#include <bzlib.h>
#include <zlib.h>

namespace
{
quint16 readLe16(const QByteArray &data, qsizetype offset)
{
    if (offset < 0 || offset + 2 > data.size()) {
        return 0;
    }
    const uchar *base = reinterpret_cast<const uchar *>(data.constData() + offset);
    return quint16(base[0]) | (quint16(base[1]) << 8);
}

quint16 readBe16(const QByteArray &data, qsizetype offset)
{
    if (offset < 0 || offset + 2 > data.size()) {
        return 0;
    }
    const uchar *base = reinterpret_cast<const uchar *>(data.constData() + offset);
    return (quint16(base[0]) << 8) | quint16(base[1]);
}

quint32 readLe32(const QByteArray &data, qsizetype offset)
{
    if (offset < 0 || offset + 4 > data.size()) {
        return 0;
    }
    const uchar *base = reinterpret_cast<const uchar *>(data.constData() + offset);
    return quint32(base[0])
        | (quint32(base[1]) << 8)
        | (quint32(base[2]) << 16)
        | (quint32(base[3]) << 24);
}

quint32 readBe32(const QByteArray &data, qsizetype offset)
{
    if (offset < 0 || offset + 4 > data.size()) {
        return 0;
    }
    const uchar *base = reinterpret_cast<const uchar *>(data.constData() + offset);
    return (quint32(base[0]) << 24)
        | (quint32(base[1]) << 16)
        | (quint32(base[2]) << 8)
        | quint32(base[3]);
}

quint64 readLe64(const QByteArray &data, qsizetype offset)
{
    if (offset < 0 || offset + 8 > data.size()) {
        return 0;
    }
    const uchar *base = reinterpret_cast<const uchar *>(data.constData() + offset);
    return quint64(base[0])
        | (quint64(base[1]) << 8)
        | (quint64(base[2]) << 16)
        | (quint64(base[3]) << 24)
        | (quint64(base[4]) << 32)
        | (quint64(base[5]) << 40)
        | (quint64(base[6]) << 48)
        | (quint64(base[7]) << 56);
}

quint64 readBe64(const QByteArray &data, qsizetype offset)
{
    if (offset < 0 || offset + 8 > data.size()) {
        return 0;
    }
    const uchar *base = reinterpret_cast<const uchar *>(data.constData() + offset);
    return (quint64(base[0]) << 56)
        | (quint64(base[1]) << 48)
        | (quint64(base[2]) << 40)
        | (quint64(base[3]) << 32)
        | (quint64(base[4]) << 24)
        | (quint64(base[5]) << 16)
        | (quint64(base[6]) << 8)
        | quint64(base[7]);
}

bool hasBytes(const QByteArray &stream, qsizetype start, qsizetype size)
{
    return start >= 0 && size > 0 && start + size <= stream.size();
}

bool startsWithAt(const QByteArray &stream, qsizetype offset, const QByteArray &signature)
{
    return hasBytes(stream, offset, signature.size()) && stream.mid(offset, signature.size()) == signature;
}

bool isMpegStartCode(const QByteArray &stream, qsizetype offset)
{
    return hasBytes(stream, offset, 4)
        && static_cast<uchar>(stream[offset]) == 0x00
        && static_cast<uchar>(stream[offset + 1]) == 0x00
        && static_cast<uchar>(stream[offset + 2]) == 0x01;
}

std::optional<qsizetype> findNextStrongSignature(const QByteArray &stream, qsizetype start)
{
    const QByteArray signatures[] = {
        QByteArrayLiteral("BZh"),
        QByteArray::fromHex("1F8B08"),
        QByteArrayLiteral("Rar!\x1A\x07"),
        QByteArray::fromHex("504B0304"),
        QByteArrayLiteral("MSWIM\0\0\0"),
        QByteArrayLiteral("RIFF"),
        QByteArray::fromHex("3026B2758E66CF11A6D900AA0062CE6C"),
        QByteArray::fromHex("000001BA"),
        QByteArray::fromHex("FFD8FF"),
        QByteArray::fromHex("89504E470D0A1A0A")
    };

    qsizetype nearest = -1;
    for (const QByteArray &signature : signatures) {
        const qsizetype hit = stream.indexOf(signature, start);
        if (hit >= 0 && (nearest < 0 || hit < nearest)) {
            nearest = hit;
        }
    }
    if (nearest < 0) {
        return std::nullopt;
    }
    return nearest;
}

std::optional<qsizetype> findNextSectorAlignedForeignSignature(const QByteArray &stream, qsizetype start, qsizetype limit)
{
    const QByteArray signatures[] = {
        QByteArray::fromHex("3026B2758E66CF11A6D900AA0062CE6C"),
        QByteArray::fromHex("377ABCAF271C"),
        QByteArrayLiteral("BZh"),
        QByteArray::fromHex("1F8B08"),
        QByteArrayLiteral("Rar!\x1A\x07"),
        QByteArray::fromHex("504B0304"),
        QByteArrayLiteral("MSWIM\0\0\0"),
        QByteArrayLiteral("RIFF"),
        QByteArrayLiteral("FLV"),
        QByteArray::fromHex("89504E470D0A1A0A"),
        QByteArrayLiteral("GIF87a"),
        QByteArrayLiteral("GIF89a"),
        QByteArrayLiteral("BM"),
        QByteArrayLiteral("%PDF"),
        QByteArrayLiteral("II*\0"),
        QByteArrayLiteral("MM\0*")
    };

    qsizetype nearest = -1;
    auto considerHit = [&](qsizetype hit) {
        if (hit > start && hit < limit && (hit % 512) == 0 && (nearest < 0 || hit < nearest)) {
            nearest = hit;
        }
    };

    for (const QByteArray &signature : signatures) {
        qsizetype hit = stream.indexOf(signature, start + 1);
        while (hit >= 0 && hit < limit) {
            considerHit(hit);
            hit = stream.indexOf(signature, hit + 1);
        }
    }

    qsizetype ftypHit = stream.indexOf(QByteArrayLiteral("ftyp"), start + 1);
    while (ftypHit >= 0 && ftypHit < limit) {
        considerHit(ftypHit - 4);
        ftypHit = stream.indexOf(QByteArrayLiteral("ftyp"), ftypHit + 1);
    }

    if (nearest < 0) {
        return std::nullopt;
    }
    return nearest;
}

quint32 crc32(const char *data, qsizetype size)
{
    quint32 crc = 0xFFFFFFFFU;
    for (qsizetype i = 0; i < size; ++i) {
        crc ^= static_cast<uchar>(data[i]);
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ (0xEDB88320U & (0U - (crc & 1U)));
        }
    }
    return crc ^ 0xFFFFFFFFU;
}

bool isZeroBlock(const QByteArray &data)
{
    return std::all_of(data.begin(), data.end(), [](char ch) { return ch == '\0'; });
}

bool isPrintableTarName(const QByteArray &name)
{
    if (name.isEmpty()) {
        return false;
    }
    for (char ch : name) {
        const uchar value = static_cast<uchar>(ch);
        if (value < 0x20 || value > 0x7E) {
            return false;
        }
    }
    return true;
}

int carvingConfidenceRank(const QString &confidence)
{
    if (confidence.compare(QStringLiteral("High"), Qt::CaseInsensitive) == 0) {
        return 3;
    }
    if (confidence.compare(QStringLiteral("Medium"), Qt::CaseInsensitive) == 0) {
        return 2;
    }
    if (confidence.compare(QStringLiteral("Low"), Qt::CaseInsensitive) == 0) {
        return 1;
    }
    return 0;
}

std::optional<quint64> parseTarHeaderSize(const QByteArray &header)
{
    if (header.size() != 512 || isZeroBlock(header)) {
        return std::nullopt;
    }

    const QByteArray name = header.left(100).split('\0').value(0);
    if (!isPrintableTarName(name)) {
        return std::nullopt;
    }

    auto parseOctalField = [](QByteArray field, bool *ok) -> quint64 {
        field.replace('\0', ' ');
        return field.trimmed().toULongLong(ok, 8);
    };

    bool sizeOk = false;
    const quint64 fileSize = parseOctalField(header.mid(124, 12), &sizeOk);
    if (!sizeOk || fileSize > quint64(8) * 1024 * 1024 * 1024) {
        return std::nullopt;
    }

    bool checksumOk = false;
    const quint64 expectedChecksum = parseOctalField(header.mid(148, 8), &checksumOk);
    if (!checksumOk || expectedChecksum == 0) {
        return std::nullopt;
    }

    quint64 actualChecksum = 0;
    for (int index = 0; index < 512; ++index) {
        actualChecksum += (index >= 148 && index < 156)
            ? uchar(' ')
            : static_cast<uchar>(header[index]);
    }
    if (expectedChecksum != actualChecksum) {
        return std::nullopt;
    }
    return fileSize;
}

CarvedFile makeResult(const QByteArray &stream,
                      qsizetype start,
                      qint64 fileSize,
                      const QString &type,
                      const QString &extension,
                      const QString &method,
                      const QString &validation,
                      const QString &confidence,
                      const QString &notes)
{
    CarvedFile carved;
    carved.fileType = type;
    carved.extension = extension;
    carved.logicalStart = quint64(start);
    carved.logicalEnd = quint64(start + fileSize - 1);
    carved.carvingMethod = method;
    carved.validationResult = validation;
    carved.confidence = confidence;
    carved.notes = notes;
    return carved;
}

std::optional<CarvedFile> carveJpeg(const QByteArray &stream, qsizetype start)
{
    if ((start % 512) != 0) {
        return std::nullopt;
    }
    if (!hasBytes(stream, start, 4)
        || static_cast<uchar>(stream[start]) != 0xFF
        || static_cast<uchar>(stream[start + 1]) != 0xD8
        || static_cast<uchar>(stream[start + 2]) != 0xFF) {
        return std::nullopt;
    }

    qsizetype offset = start + 2;
    bool sawFrame = false;
    bool sawScan = false;
    bool sawQuantization = false;
    bool sawHuffman = false;
    bool sawAppSegment = false;

    auto isFrameMarker = [](uchar marker) {
        return (marker >= 0xC0 && marker <= 0xCF)
            && marker != 0xC4
            && marker != 0xC8
            && marker != 0xCC;
    };

    while (offset < stream.size()) {
        while (offset < stream.size() && static_cast<uchar>(stream[offset]) != 0xFF) {
            ++offset;
        }
        if (!hasBytes(stream, offset, 2)) {
            return std::nullopt;
        }
        while (offset < stream.size() && static_cast<uchar>(stream[offset]) == 0xFF) {
            ++offset;
        }
        if (offset >= stream.size()) {
            return std::nullopt;
        }

        const uchar marker = static_cast<uchar>(stream[offset++]);
        if (marker == 0x00) {
            if (!sawScan) {
                return std::nullopt;
            }
            continue;
        }
        if (marker == 0xD8) {
            return std::nullopt;
        }
        if (marker == 0xD9) {
            if (!sawFrame || !sawScan || (!sawQuantization && !sawHuffman && !sawAppSegment)) {
                return std::nullopt;
            }
            return makeResult(stream, start, qint64(offset - start), QStringLiteral("JPEG image"), QStringLiteral("jpg"),
                QStringLiteral("Structure"), QStringLiteral("JPEG marker segment chain and EOI validated"), QStringLiteral("High"),
                QStringLiteral("Recovered by JPEG marker-aware structure parser."));
        }
        if (marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
            continue;
        }

        if (!hasBytes(stream, offset, 2)) {
            return std::nullopt;
        }
        const quint16 segmentLength = readBe16(stream, offset);
        if (segmentLength < 2 || !hasBytes(stream, offset, segmentLength)) {
            return std::nullopt;
        }
        if (isFrameMarker(marker)) {
            sawFrame = true;
        } else if (marker == 0xDB) {
            sawQuantization = true;
        } else if (marker == 0xC4) {
            sawHuffman = true;
        } else if (marker >= 0xE0 && marker <= 0xEF) {
            sawAppSegment = true;
        }

        offset += qsizetype(segmentLength);
        if (marker != 0xDA) {
            continue;
        }

        sawScan = true;
        while (hasBytes(stream, offset, 2)) {
            const qsizetype markerOffset = stream.indexOf(char(0xFF), offset);
            if (markerOffset < 0 || !hasBytes(stream, markerOffset, 2)) {
                return std::nullopt;
            }
            uchar nextMarker = static_cast<uchar>(stream[markerOffset + 1]);
            qsizetype markerCursor = markerOffset + 1;
            while (nextMarker == 0xFF && hasBytes(stream, markerCursor, 2)) {
                ++markerCursor;
                nextMarker = static_cast<uchar>(stream[markerCursor]);
            }
            if (nextMarker == 0x00) {
                offset = markerCursor + 1;
                continue;
            }
            if (nextMarker >= 0xD0 && nextMarker <= 0xD7) {
                offset = markerCursor + 1;
                continue;
            }
            if (nextMarker == 0xD9) {
                if (!sawFrame || !sawScan || (!sawQuantization && !sawHuffman && !sawAppSegment)) {
                    return std::nullopt;
                }
                return makeResult(stream, start, qint64(markerCursor + 1 - start), QStringLiteral("JPEG image"), QStringLiteral("jpg"),
                    QStringLiteral("Structure"), QStringLiteral("JPEG segments, scan data, and EOI validated"), QStringLiteral("High"),
                    QStringLiteral("Recovered by JPEG marker-aware scan parser."));
            }
            offset = markerCursor - 1;
            break;
        }
    }

    return std::nullopt;
}

std::optional<CarvedFile> carveGif(const QByteArray &stream, qsizetype start)
{
    if (!hasBytes(stream, start, 13)) {
        return std::nullopt;
    }

    const uchar packed = static_cast<uchar>(stream[start + 10]);
    qsizetype offset = start + 13;
    if (packed & 0x80) {
        const qsizetype colorTableBytes = qsizetype(3) * (qsizetype(1) << ((packed & 0x07) + 1));
        if (!hasBytes(stream, offset, colorTableBytes)) {
            return std::nullopt;
        }
        offset += colorTableBytes;
    }

    auto skipSubBlocks = [&](qsizetype *cursor) -> bool {
        while (hasBytes(stream, *cursor, 1)) {
            const uchar blockSize = static_cast<uchar>(stream[*cursor]);
            ++(*cursor);
            if (blockSize == 0) {
                return true;
            }
            if (!hasBytes(stream, *cursor, blockSize)) {
                return false;
            }
            *cursor += blockSize;
        }
        return false;
    };

    while (hasBytes(stream, offset, 1)) {
        const uchar introducer = static_cast<uchar>(stream[offset++]);
        if (introducer == 0x3B) {
            return makeResult(stream, start, qint64(offset - start), QStringLiteral("GIF image"), QStringLiteral("gif"),
                QStringLiteral("Structure"), QStringLiteral("GIF block chain and trailer validated"), QStringLiteral("High"),
                QStringLiteral("Recovered by GIF logical-screen and block-chain parser."));
        }
        if (introducer == 0x21) {
            if (!hasBytes(stream, offset, 1)) {
                return std::nullopt;
            }
            ++offset;
            if (!skipSubBlocks(&offset)) {
                return std::nullopt;
            }
            continue;
        }
        if (introducer == 0x2C) {
            if (!hasBytes(stream, offset, 9)) {
                return std::nullopt;
            }
            const uchar imagePacked = static_cast<uchar>(stream[offset + 8]);
            offset += 9;
            if (imagePacked & 0x80) {
                const qsizetype colorTableBytes = qsizetype(3) * (qsizetype(1) << ((imagePacked & 0x07) + 1));
                if (!hasBytes(stream, offset, colorTableBytes)) {
                    return std::nullopt;
                }
                offset += colorTableBytes;
            }
            if (!hasBytes(stream, offset, 1)) {
                return std::nullopt;
            }
            ++offset;
            if (!skipSubBlocks(&offset)) {
                return std::nullopt;
            }
            continue;
        }
        return std::nullopt;
    }

    return std::nullopt;
}

std::optional<CarvedFile> carvePdf(const QByteArray &stream, qsizetype start)
{
    const qsizetype nextPdf = stream.indexOf(QByteArrayLiteral("%PDF"), start + 4);
    const qsizetype searchLimit = nextPdf > start ? nextPdf : stream.size();
    qsizetype searchFrom = start + 4;
    std::optional<qsizetype> bestEnd;
    while (true) {
        const qsizetype end = stream.indexOf(QByteArrayLiteral("%%EOF"), searchFrom);
        if (end < 0 || end >= searchLimit) {
            break;
        }
        const qsizetype startXref = stream.lastIndexOf(QByteArrayLiteral("startxref"), end);
        if (startXref >= start) {
            qsizetype numberStart = startXref + qsizetype(QByteArrayLiteral("startxref").size());
            while (numberStart < end && (stream[numberStart] == '\r' || stream[numberStart] == '\n' || stream[numberStart] == ' ' || stream[numberStart] == '\t')) {
                ++numberStart;
            }
            qsizetype numberEnd = numberStart;
            while (numberEnd < end && stream[numberEnd] >= '0' && stream[numberEnd] <= '9') {
                ++numberEnd;
            }
            if (numberEnd == numberStart) {
                searchFrom = end + 5;
                continue;
            }
            bool ok = false;
            const quint64 xrefOffset = QString::fromLatin1(stream.mid(numberStart, numberEnd - numberStart)).toULongLong(&ok);
            if (ok && xrefOffset < quint64(end - start)) {
                const qsizetype xrefPosition = start + qsizetype(xrefOffset);
                const bool classicXref = startsWithAt(stream, xrefPosition, QByteArrayLiteral("xref"));
                const bool xrefStreamObject = hasBytes(stream, xrefPosition, 16)
                    && stream.indexOf(QByteArrayLiteral("/Type"), xrefPosition) >= xrefPosition
                    && stream.indexOf(QByteArrayLiteral("/XRef"), xrefPosition) >= xrefPosition
                    && stream.indexOf(QByteArrayLiteral("stream"), xrefPosition) >= xrefPosition;
                const qsizetype trailerPosition = stream.lastIndexOf(QByteArrayLiteral("trailer"), startXref);
                if (classicXref || xrefStreamObject || trailerPosition >= start) {
                    qsizetype sizeEnd = end + 5;
                    while (sizeEnd < searchLimit && (stream[sizeEnd] == '\r' || stream[sizeEnd] == '\n' || stream[sizeEnd] == ' ' || stream[sizeEnd] == '\t')) {
                        ++sizeEnd;
                    }
                    bestEnd = sizeEnd;
                }
                searchFrom = end + 5;
                continue;
            }
        }
        searchFrom = end + 5;
    }
    if (!bestEnd.has_value() || *bestEnd <= start) {
        return std::nullopt;
    }
    return makeResult(stream, start, qint64(*bestEnd - start), QStringLiteral("PDF document"), QStringLiteral("pdf"),
        QStringLiteral("Structure"), QStringLiteral("Last valid PDF EOF before next PDF signature validated"), QStringLiteral("High"),
        QStringLiteral("Recovered by PDF last-EOF parser with next-document boundary guard."));
}

std::optional<CarvedFile> carvePng(const QByteArray &stream, qsizetype start)
{
    qsizetype offset = start + 8;
    while (hasBytes(stream, offset, 12)) {
        const quint32 chunkSize = readBe32(stream, offset);
        if (!hasBytes(stream, offset, qsizetype(chunkSize) + 12)) {
            return std::nullopt;
        }
        const QByteArray chunkType = stream.mid(offset + 4, 4);
        const quint32 expectedCrc = readBe32(stream, offset + 8 + qsizetype(chunkSize));
        const quint32 actualCrc = crc32(stream.constData() + offset + 4, qsizetype(chunkSize) + 4);
        if (expectedCrc != actualCrc) {
            return std::nullopt;
        }
        offset += qsizetype(chunkSize) + 12;
        if (chunkType == QByteArrayLiteral("IEND")) {
            return makeResult(stream, start, qint64(offset - start), QStringLiteral("PNG image"), QStringLiteral("png"),
                QStringLiteral("Val"), QStringLiteral("PNG chunk chain, chunk CRCs, and IEND validated"), QStringLiteral("High"),
                QStringLiteral("Recovered by CRC-validated PNG chunk parser."));
        }
    }
    return std::nullopt;
}

std::optional<CarvedFile> carveBmp(const QByteArray &stream, qsizetype start)
{
    if ((start % 512) != 0 || !hasBytes(stream, start, 54) || !startsWithAt(stream, start, QByteArrayLiteral("BM"))) {
        return std::nullopt;
    }
    const quint32 fileSize = readLe32(stream, start + 2);
    const quint32 reserved = readLe32(stream, start + 6);
    const quint32 pixelOffset = readLe32(stream, start + 10);
    const quint32 dibSize = readLe32(stream, start + 14);
    if (reserved != 0
        || fileSize < 54
        || pixelOffset < 14 + dibSize
        || fileSize < pixelOffset
        || !hasBytes(stream, start, qsizetype(fileSize))) {
        return std::nullopt;
    }
    if (dibSize != 40 && dibSize != 52 && dibSize != 56 && dibSize != 108 && dibSize != 124) {
        return std::nullopt;
    }
    const qint32 width = qint32(readLe32(stream, start + 18));
    const qint32 height = qint32(readLe32(stream, start + 22));
    const quint16 planes = readLe16(stream, start + 26);
    const quint16 bitsPerPixel = readLe16(stream, start + 28);
    const quint32 compression = readLe32(stream, start + 30);
    const quint32 imageSize = readLe32(stream, start + 34);
    const qint64 absoluteWidth = std::llabs(qint64(width));
    const qint64 absoluteHeight = std::llabs(qint64(height));
    if (absoluteWidth == 0 || absoluteHeight == 0 || absoluteWidth > 100000 || absoluteHeight > 100000) {
        return std::nullopt;
    }
    if (planes != 1
        || (bitsPerPixel != 1 && bitsPerPixel != 4 && bitsPerPixel != 8 && bitsPerPixel != 16 && bitsPerPixel != 24 && bitsPerPixel != 32)
        || compression > 6) {
        return std::nullopt;
    }
    const qint64 minimumRowSize = ((absoluteWidth * bitsPerPixel + 31) / 32) * 4;
    const qint64 minimumImageSize = minimumRowSize * absoluteHeight;
    if (compression == 0) {
        if (imageSize != 0 && qint64(imageSize) < minimumImageSize) {
            return std::nullopt;
        }
        if (quint64(pixelOffset) + quint64(minimumImageSize) > fileSize) {
            return std::nullopt;
        }
    }
    return makeResult(stream, start, fileSize, QStringLiteral("BMP image"), QStringLiteral("bmp"),
        QStringLiteral("Val"), QStringLiteral("BMP sector alignment, DIB header, geometry, and pixel extent validated"), QStringLiteral("High"),
        QStringLiteral("Recovered by strict BMP/DIB header validator."));
}

bool containsInRange(const QByteArray &data, qsizetype start, qsizetype size, const QByteArray &needle)
{
    if (size <= 0) {
        return false;
    }
    const qsizetype end = start + size;
    qsizetype hit = data.indexOf(needle, start);
    return hit >= start && hit < end;
}

QString classifyOpenXml(const QByteArray &data, qsizetype start, qsizetype size, QString *type)
{
    if (containsInRange(data, start, size, QByteArrayLiteral("word/"))) {
        *type = QStringLiteral("Word document");
        return QStringLiteral("docx");
    }
    if (containsInRange(data, start, size, QByteArrayLiteral("xl/"))) {
        *type = QStringLiteral("Excel workbook");
        return QStringLiteral("xlsx");
    }
    if (containsInRange(data, start, size, QByteArrayLiteral("ppt/"))) {
        *type = QStringLiteral("PowerPoint document");
        return QStringLiteral("pptx");
    }
    *type = QStringLiteral("ZIP archive");
    return QStringLiteral("zip");
}

std::optional<CarvedFile> carveZip(const QByteArray &stream, qsizetype start)
{
    qsizetype searchFrom = start + 4;
    while (true) {
        const qsizetype eocd = stream.indexOf(QByteArray::fromHex("504B0506"), searchFrom);
        if (eocd < 0 || !hasBytes(stream, eocd, 22)) {
            return std::nullopt;
        }
        const quint16 commentSize = readLe16(stream, eocd + 20);
        const qint64 fileSize = qint64(eocd - start + 22 + commentSize);
        if (fileSize > 0 && hasBytes(stream, start, qsizetype(fileSize))) {
            const quint16 diskNumber = readLe16(stream, eocd + 4);
            const quint16 cdDisk = readLe16(stream, eocd + 6);
            const quint16 diskEntries = readLe16(stream, eocd + 8);
            const quint16 totalEntries = readLe16(stream, eocd + 10);
            const quint32 centralDirectorySize = readLe32(stream, eocd + 12);
            const quint32 centralDirectoryOffset = readLe32(stream, eocd + 16);
            if (diskNumber != 0 || cdDisk != 0 || diskEntries != totalEntries) {
                searchFrom = eocd + 4;
                continue;
            }
            const qsizetype cdStart = start + qsizetype(centralDirectoryOffset);
            const qsizetype cdEnd = cdStart + qsizetype(centralDirectorySize);
            if (cdStart < start || cdEnd != eocd || !hasBytes(stream, cdStart, qsizetype(centralDirectorySize))) {
                searchFrom = eocd + 4;
                continue;
            }
            qsizetype cursor = cdStart;
            quint16 seenEntries = 0;
            bool centralDirectoryOk = true;
            while (cursor < cdEnd && seenEntries < totalEntries) {
                if (!hasBytes(stream, cursor, 46) || readLe32(stream, cursor) != 0x02014B50U) {
                    centralDirectoryOk = false;
                    break;
                }
                const quint16 nameLength = readLe16(stream, cursor + 28);
                const quint16 extraLength = readLe16(stream, cursor + 30);
                const quint16 fileCommentLength = readLe16(stream, cursor + 32);
                const quint32 localHeaderOffset = readLe32(stream, cursor + 42);
                const qsizetype localHeader = start + qsizetype(localHeaderOffset);
                if (!hasBytes(stream, localHeader, 30) || readLe32(stream, localHeader) != 0x04034B50U) {
                    centralDirectoryOk = false;
                    break;
                }
                const qsizetype next = cursor + 46 + qsizetype(nameLength) + qsizetype(extraLength) + qsizetype(fileCommentLength);
                if (next <= cursor || next > cdEnd) {
                    centralDirectoryOk = false;
                    break;
                }
                cursor = next;
                ++seenEntries;
            }
            if (!centralDirectoryOk || seenEntries != totalEntries || cursor != cdEnd) {
                searchFrom = eocd + 4;
                continue;
            }
            QString type;
            const QString extension = classifyOpenXml(stream, start, qsizetype(fileSize), &type);
            return makeResult(stream, start, fileSize, type, extension, QStringLiteral("Val"),
                QStringLiteral("ZIP EOCD, central directory entries, and local header offsets validated"), QStringLiteral("High"),
                QStringLiteral("Recovered by ZIP central-directory and local-header validator."));
        }
        searchFrom = eocd + 4;
    }
}

std::optional<CarvedFile> carveRiff(const QByteArray &stream, qsizetype start)
{
    if (!hasBytes(stream, start, 12)) {
        return std::nullopt;
    }
    const quint32 riffSize = readLe32(stream, start + 4);
    const qint64 fileSize = qint64(riffSize) + 8;
    if (fileSize <= 12 || !hasBytes(stream, start, qsizetype(fileSize))) {
        return std::nullopt;
    }
    const QByteArray riffType = stream.mid(start + 8, 4);
    bool sawFormat = false;
    bool sawData = false;
    bool sawAviHeader = false;
    bool sawMovi = false;
    qsizetype offset = start + 12;
    const qsizetype end = start + qsizetype(fileSize);
    qsizetype lastChunkEnd = offset;
    while (offset + 8 <= end) {
        if (riffType == QByteArrayLiteral("WAVE") && offset == start + qsizetype(riffSize)) {
            break;
        }
        const QByteArray chunkId = stream.mid(offset, 4);
        const quint32 chunkSize = readLe32(stream, offset + 4);
        const qsizetype chunkData = offset + 8;
        const qsizetype next = chunkData + qsizetype(chunkSize) + (chunkSize & 1U);
        if (next < chunkData || next > end) {
            return std::nullopt;
        }
        if (chunkId == QByteArrayLiteral("fmt ")) {
            sawFormat = true;
        } else if (chunkId == QByteArrayLiteral("data")) {
            sawData = true;
        } else if (chunkId == QByteArrayLiteral("avih")) {
            sawAviHeader = true;
        } else if (chunkId == QByteArrayLiteral("LIST") && hasBytes(stream, chunkData, 4) && stream.mid(chunkData, 4) == QByteArrayLiteral("movi")) {
            sawMovi = true;
        } else if (chunkId == QByteArrayLiteral("LIST") || chunkId == QByteArrayLiteral("RIFF")) {
            if (hasBytes(stream, chunkData, 4)) {
                const QByteArray listType = stream.mid(chunkData, 4);
                if (listType == QByteArrayLiteral("movi")) {
                    sawMovi = true;
                }
            }
        }
        lastChunkEnd = next;
        offset = next;
    }
    if (riffType == QByteArrayLiteral("WAVE")) {
        if (!sawFormat || !sawData) {
            return std::nullopt;
        }
        qint64 wavFileSize = fileSize;
        if (lastChunkEnd > start + 12 && lastChunkEnd <= end) {
            const qint64 chunkDerivedSize = qint64(lastChunkEnd - start);
            if (chunkDerivedSize == qint64(riffSize)) {
                wavFileSize = chunkDerivedSize;
            }
        }
        return makeResult(stream, start, wavFileSize, QStringLiteral("WAV audio"), QStringLiteral("wav"),
            QStringLiteral("Val"), QStringLiteral("RIFF size, WAVE subtype, fmt/data chunks validated"), QStringLiteral("High"),
            QStringLiteral("Recovered by RIFF/WAVE chunk parser."));
    }
    if (riffType == QByteArrayLiteral("AVI ")) {
        if (!sawAviHeader && !sawMovi) {
            return std::nullopt;
        }
        return makeResult(stream, start, fileSize, QStringLiteral("AVI video"), QStringLiteral("avi"),
            QStringLiteral("Val"), QStringLiteral("RIFF size, AVI subtype, and AVI chunks validated"), QStringLiteral("High"),
            QStringLiteral("Recovered by RIFF/AVI chunk parser."));
    }
    return std::nullopt;
}

std::optional<CarvedFile> carveIsoBmff(const QByteArray &stream, qsizetype start)
{
    if (!hasBytes(stream, start, 12) || stream.mid(start + 4, 4) != QByteArrayLiteral("ftyp")) {
        return std::nullopt;
    }

    const QByteArray majorBrand = stream.mid(start + 8, 4);
    qsizetype offset = start;
    bool sawMediaBox = false;
    while (hasBytes(stream, offset, 8)) {
        quint64 boxSize = readBe32(stream, offset);
        qsizetype headerSize = 8;
        if (boxSize == 1) {
            boxSize = readBe64(stream, offset + 8);
            headerSize = 16;
        }
        if (boxSize < quint64(headerSize) || offset + boxSize > quint64(stream.size())) {
            break;
        }
        const QByteArray boxType = stream.mid(offset + 4, 4);
        if (boxType == QByteArrayLiteral("moov") || boxType == QByteArrayLiteral("mdat")) {
            sawMediaBox = true;
        }
        offset += qsizetype(boxSize);
        if (!hasBytes(stream, offset, 8)) {
            break;
        }
        const QByteArray nextType = stream.mid(offset + 4, 4);
        if (nextType != QByteArrayLiteral("ftyp")
            && nextType != QByteArrayLiteral("moov")
            && nextType != QByteArrayLiteral("mdat")
            && nextType != QByteArrayLiteral("free")
            && nextType != QByteArrayLiteral("wide")
            && nextType != QByteArrayLiteral("skip")
            && nextType != QByteArrayLiteral("uuid")) {
            break;
        }
    }
    if (!sawMediaBox || offset <= start + 12) {
        return std::nullopt;
    }
    const bool looksMov = majorBrand == QByteArrayLiteral("qt  ");
    return makeResult(stream, start, qint64(offset - start), QStringLiteral("MP4/MOV video"), looksMov ? QStringLiteral("mov") : QStringLiteral("mp4"),
        QStringLiteral("Structure"), QStringLiteral("ISO BMFF box chain and ftyp brand validated"), QStringLiteral("Medium"),
        QStringLiteral("Recovered by ISO BMFF box structure carver."));
}

std::optional<CarvedFile> carveAsf(const QByteArray &stream, qsizetype start)
{
    const quint64 headerSize = readLe64(stream, start + 16);
    if (headerSize <= 30 || !hasBytes(stream, start, qsizetype(headerSize))) {
        return std::nullopt;
    }

    const QByteArray filePropertiesGuid = QByteArray::fromHex("A1DCAB8C47A9CF118EE400C00C205365");
    const QByteArray streamPropertiesGuid = QByteArray::fromHex("9107DCB7B7A9CF118EE600C00C205365");
    const QByteArray audioMediaGuid = QByteArray::fromHex("409E69F84D5BCF11A8FD00805F5C442B");
    const QByteArray videoMediaGuid = QByteArray::fromHex("C0EF19BC4D5BCF11A8FD00805F5C442B");

    quint64 fileSize = 0;
    bool sawAudio = false;
    bool sawVideo = false;
    qsizetype objectOffset = start + 30;
    const qsizetype headerEnd = start + qsizetype(headerSize);
    while (objectOffset + 24 <= headerEnd) {
        const QByteArray objectGuid = stream.mid(objectOffset, 16);
        const quint64 objectSize = readLe64(stream, objectOffset + 16);
        if (objectSize < 24 || objectOffset + objectSize > quint64(headerEnd)) {
            return std::nullopt;
        }
        if (objectGuid == filePropertiesGuid && objectSize >= 104) {
            fileSize = readLe64(stream, objectOffset + 40);
        } else if (objectGuid == streamPropertiesGuid && objectSize >= 78) {
            const QByteArray streamType = stream.mid(objectOffset + 24, 16);
            sawAudio = sawAudio || streamType == audioMediaGuid;
            sawVideo = sawVideo || streamType == videoMediaGuid;
        }
        objectOffset += qsizetype(objectSize);
    }
    quint64 topLevelSize = headerSize;
    qsizetype topLevelObjectOffset = start + qsizetype(headerSize);
    while (hasBytes(stream, topLevelObjectOffset, 24)) {
        const quint64 objectSize = readLe64(stream, topLevelObjectOffset + 16);
        if (objectSize < 24 || objectSize > quint64(stream.size() - topLevelObjectOffset)) {
            break;
        }
        topLevelSize += objectSize;
        topLevelObjectOffset += qsizetype(objectSize);
    }
    fileSize = std::max(fileSize, topLevelSize);
    if (fileSize == 0 || fileSize > quint64(std::numeric_limits<qsizetype>::max()) || !hasBytes(stream, start, qsizetype(fileSize))) {
        return std::nullopt;
    }
    const QString extension = sawVideo ? QStringLiteral("wmv") : (sawAudio ? QStringLiteral("wma") : QStringLiteral("asf"));
    const QString type = sawVideo ? QStringLiteral("ASF/WMV media") : (sawAudio ? QStringLiteral("ASF/WMA audio") : QStringLiteral("ASF media"));
    return makeResult(stream, start, qint64(fileSize), type, extension,
        QStringLiteral("Val"), QStringLiteral("ASF File Properties size, top-level object chain, and Stream Properties validated where present"), sawVideo || sawAudio ? QStringLiteral("High") : QStringLiteral("Medium"),
        QStringLiteral("Recovered by ASF object-chain parser."));
}

std::optional<CarvedFile> carveTar(const QByteArray &stream, qsizetype start)
{
    if ((start % 512) != 0 || !hasBytes(stream, start, 512)) {
        return std::nullopt;
    }

    qsizetype offset = start;
    int fileHeaders = 0;
    while (hasBytes(stream, offset, 512)) {
        const QByteArray header = stream.mid(offset, 512);
        const bool empty = isZeroBlock(header);
        if (empty) {
            if (fileHeaders == 0) {
                return std::nullopt;
            }
            if (!hasBytes(stream, offset, 1024) || !isZeroBlock(stream.mid(offset + 512, 512))) {
                return std::nullopt;
            }
            return makeResult(stream, start, qint64(offset - start + 1024), QStringLiteral("TAR archive"), QStringLiteral("tar"),
                QStringLiteral("Val"), QStringLiteral("TAR header checksums and two zero blocks validated"), QStringLiteral("High"),
                QStringLiteral("Recovered by TAR block-chain and checksum parser."));
        }

        const std::optional<quint64> fileSize = parseTarHeaderSize(header);
        if (!fileSize.has_value()) {
            return std::nullopt;
        }
        const quint64 blocks = (*fileSize + 511) / 512;
        offset += 512 + qsizetype(blocks * 512);
        ++fileHeaders;
    }
    return std::nullopt;
}

std::optional<CarvedFile> carvePcx(const QByteArray &stream, qsizetype start)
{
    if (!hasBytes(stream, start, 128)) {
        return std::nullopt;
    }

    const uchar manufacturer = static_cast<uchar>(stream[start]);
    const uchar version = static_cast<uchar>(stream[start + 1]);
    const uchar encoding = static_cast<uchar>(stream[start + 2]);
    const uchar bitsPerPixel = static_cast<uchar>(stream[start + 3]);
    const quint16 xMin = readLe16(stream, start + 4);
    const quint16 yMin = readLe16(stream, start + 6);
    const quint16 xMax = readLe16(stream, start + 8);
    const quint16 yMax = readLe16(stream, start + 10);
    const uchar colorPlanes = static_cast<uchar>(stream[start + 65]);
    const quint16 bytesPerLine = readLe16(stream, start + 66);
    const quint16 paletteInfo = readLe16(stream, start + 68);

    const bool knownVersion = version == 0 || version == 2 || version == 3 || version == 4 || version == 5;
    const bool knownBits = bitsPerPixel == 1 || bitsPerPixel == 2 || bitsPerPixel == 4 || bitsPerPixel == 8;
    const bool saneGeometry = xMax >= xMin && yMax >= yMin && (quint32(xMax) - xMin + 1) <= 65535 && (quint32(yMax) - yMin + 1) <= 65535;
    const bool sanePlanes = colorPlanes == 1 || colorPlanes == 3 || colorPlanes == 4;
    const bool sanePalette = paletteInfo == 0 || paletteInfo == 1 || paletteInfo == 2;
    if (manufacturer != 0x0A || !knownVersion || encoding != 1 || !knownBits || !saneGeometry || !sanePlanes || bytesPerLine == 0 || !sanePalette) {
        return std::nullopt;
    }

    const quint64 height = quint64(yMax) - yMin + 1;
    const quint64 imageBytes = height * colorPlanes * bytesPerLine;
    qsizetype encodedOffset = start + 128;
    quint64 decodedBytes = 0;
    while (decodedBytes < imageBytes && encodedOffset < stream.size()) {
        const uchar value = static_cast<uchar>(stream[encodedOffset++]);
        if ((value & 0xC0) == 0xC0) {
            const uchar run = value & 0x3F;
            if (!hasBytes(stream, encodedOffset, 1)) {
                return std::nullopt;
            }
            ++encodedOffset;
            decodedBytes += run;
        } else {
            ++decodedBytes;
        }
    }
    if (decodedBytes != imageBytes) {
        return std::nullopt;
    }

    if (version == 5 && bitsPerPixel == 8 && colorPlanes == 1) {
        if (!hasBytes(stream, encodedOffset, 769) || static_cast<uchar>(stream[encodedOffset]) != 0x0C) {
            return std::nullopt;
        }
        encodedOffset += 769;
    }

    return makeResult(stream, start, qint64(encodedOffset - start), QStringLiteral("PCX image"), QStringLiteral("pcx"),
        QStringLiteral("Val"), QStringLiteral("PCX header geometry and RLE decoded byte count validated"), QStringLiteral("High"),
        QStringLiteral("Recovered by PCX RLE structure parser."));
}

int tiffTypeSize(quint16 type)
{
    switch (type) {
    case 1:
    case 2:
    case 6:
    case 7:
        return 1;
    case 3:
    case 8:
        return 2;
    case 4:
    case 9:
    case 11:
        return 4;
    case 5:
    case 10:
    case 12:
        return 8;
    default:
        return 0;
    }
}

quint16 readTiff16(const QByteArray &stream, qsizetype offset, bool littleEndian)
{
    return littleEndian ? readLe16(stream, offset) : readBe16(stream, offset);
}

quint32 readTiff32(const QByteArray &stream, qsizetype offset, bool littleEndian)
{
    return littleEndian ? readLe32(stream, offset) : readBe32(stream, offset);
}

QVector<quint64> readTiffValues(const QByteArray &stream,
                                qsizetype start,
                                qsizetype valueFieldOffset,
                                bool littleEndian,
                                quint16 type,
                                quint32 count,
                                quint32 valueOrOffset)
{
    QVector<quint64> values;
    const int unitSize = tiffTypeSize(type);
    if (unitSize <= 0 || count == 0 || count > 4096) {
        return values;
    }

    const quint64 totalBytes = quint64(unitSize) * count;
    qsizetype valueStart = valueFieldOffset;
    if (totalBytes > 4) {
        valueStart = start + qsizetype(valueOrOffset);
    }
    if (!hasBytes(stream, valueStart, qsizetype(totalBytes))) {
        return values;
    }

    for (quint32 index = 0; index < count; ++index) {
        const qsizetype offset = valueStart + qsizetype(index * unitSize);
        if (type == 3 || type == 8) {
            values.append(readTiff16(stream, offset, littleEndian));
        } else if (type == 4 || type == 9 || type == 11) {
            values.append(readTiff32(stream, offset, littleEndian));
        }
    }
    return values;
}

std::optional<CarvedFile> carveTiff(const QByteArray &stream, qsizetype start)
{
    if (!hasBytes(stream, start, 8)) {
        return std::nullopt;
    }

    const bool littleEndian = stream.mid(start, 2) == QByteArrayLiteral("II");
    const bool bigEndian = stream.mid(start, 2) == QByteArrayLiteral("MM");
    if ((!littleEndian && !bigEndian) || readTiff16(stream, start + 2, littleEndian) != 42) {
        return std::nullopt;
    }

    quint32 ifdOffset = readTiff32(stream, start + 4, littleEndian);
    quint64 maxEnd = 8;
    int ifdCount = 0;
    while (ifdOffset != 0 && ++ifdCount <= 32) {
        const qsizetype ifd = start + qsizetype(ifdOffset);
        if (!hasBytes(stream, ifd, 2)) {
            return std::nullopt;
        }
        const quint16 entryCount = readTiff16(stream, ifd, littleEndian);
        if (entryCount == 0 || entryCount > 1024 || !hasBytes(stream, ifd + 2, qsizetype(entryCount) * 12 + 4)) {
            return std::nullopt;
        }

        QVector<quint64> stripOffsets;
        QVector<quint64> stripByteCounts;
        QVector<quint64> tileOffsets;
        QVector<quint64> tileByteCounts;
        bool sawImageWidth = false;
        bool sawImageLength = false;
        bool sawBitsPerSample = false;
        bool sawCompression = false;
        bool sawPhotometric = false;

        const qsizetype entriesStart = ifd + 2;
        const qsizetype nextIfdOffsetPosition = entriesStart + qsizetype(entryCount) * 12;
        maxEnd = std::max<quint64>(maxEnd, quint64(nextIfdOffsetPosition - start + 4));

        for (quint16 entry = 0; entry < entryCount; ++entry) {
            const qsizetype de = entriesStart + qsizetype(entry) * 12;
            const quint16 tag = readTiff16(stream, de, littleEndian);
            const quint16 type = readTiff16(stream, de + 2, littleEndian);
            const quint32 count = readTiff32(stream, de + 4, littleEndian);
            const quint32 valueOrOffset = readTiff32(stream, de + 8, littleEndian);
            const int unitSize = tiffTypeSize(type);
            if (unitSize <= 0 || count == 0 || count > 65536) {
                continue;
            }

            const quint64 totalBytes = quint64(unitSize) * count;
            if (totalBytes > 4) {
                if (!hasBytes(stream, start + qsizetype(valueOrOffset), qsizetype(totalBytes))) {
                    return std::nullopt;
                }
                maxEnd = std::max<quint64>(maxEnd, quint64(valueOrOffset) + totalBytes);
            }

            QVector<quint64> values = readTiffValues(stream, start, de + 8, littleEndian, type, count, valueOrOffset);
            if (tag == 273) {
                stripOffsets = values;
            } else if (tag == 279) {
                stripByteCounts = values;
            } else if (tag == 324) {
                tileOffsets = values;
            } else if (tag == 325) {
                tileByteCounts = values;
            } else if (tag == 256) {
                sawImageWidth = true;
            } else if (tag == 257) {
                sawImageLength = true;
            } else if (tag == 258) {
                sawBitsPerSample = true;
            } else if (tag == 259) {
                sawCompression = true;
            } else if (tag == 262) {
                sawPhotometric = true;
            }
        }

        if (!sawImageWidth || !sawImageLength || !sawBitsPerSample || !sawCompression || !sawPhotometric) {
            return std::nullopt;
        }

        auto extendImageData = [&](const QVector<quint64> &offsets, const QVector<quint64> &sizes) -> bool {
            if (offsets.isEmpty() || offsets.size() != sizes.size()) {
                return true;
            }
            for (int index = 0; index < offsets.size(); ++index) {
                const quint64 end = offsets[index] + sizes[index];
                if (end <= offsets[index] || end > quint64(stream.size() - start)) {
                    return false;
                }
                maxEnd = std::max(maxEnd, end);
            }
            return true;
        };
        if (!extendImageData(stripOffsets, stripByteCounts) || !extendImageData(tileOffsets, tileByteCounts)) {
            return std::nullopt;
        }

        ifdOffset = readTiff32(stream, nextIfdOffsetPosition, littleEndian);
    }

    if (maxEnd <= 8 || maxEnd > quint64(std::numeric_limits<qsizetype>::max()) || !hasBytes(stream, start, qsizetype(maxEnd))) {
        return std::nullopt;
    }
    return makeResult(stream, start, qint64(maxEnd), QStringLiteral("TIFF image"), QStringLiteral("tif"),
        QStringLiteral("Structure"), QStringLiteral("TIFF IFD chain and strip/tile extents validated"), QStringLiteral("Medium"),
        QStringLiteral("Recovered by TIFF IFD structure carver."));
}

int synchsafeToInt(const QByteArray &stream, qsizetype offset)
{
    if (!hasBytes(stream, offset, 4)) {
        return -1;
    }
    const uchar b0 = static_cast<uchar>(stream[offset]);
    const uchar b1 = static_cast<uchar>(stream[offset + 1]);
    const uchar b2 = static_cast<uchar>(stream[offset + 2]);
    const uchar b3 = static_cast<uchar>(stream[offset + 3]);
    if ((b0 | b1 | b2 | b3) & 0x80) {
        return -1;
    }
    return (int(b0) << 21) | (int(b1) << 14) | (int(b2) << 7) | int(b3);
}

int mp3BitrateKbps(int versionBits, int layerBits, int index)
{
    if (index <= 0 || index >= 15 || layerBits == 0 || versionBits == 1) {
        return 0;
    }
    static const int mpeg1Layer1[] = {0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448};
    static const int mpeg1Layer2[] = {0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384};
    static const int mpeg1Layer3[] = {0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320};
    static const int mpeg2Layer1[] = {0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256};
    static const int mpeg2Layer23[] = {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160};
    const bool mpeg1 = versionBits == 3;
    if (mpeg1 && layerBits == 3) return mpeg1Layer1[index];
    if (mpeg1 && layerBits == 2) return mpeg1Layer2[index];
    if (mpeg1 && layerBits == 1) return mpeg1Layer3[index];
    if (!mpeg1 && layerBits == 3) return mpeg2Layer1[index];
    return mpeg2Layer23[index];
}

int mp3SampleRate(int versionBits, int index)
{
    if (index >= 3) {
        return 0;
    }
    static const int mpeg1[] = {44100, 48000, 32000};
    static const int mpeg2[] = {22050, 24000, 16000};
    static const int mpeg25[] = {11025, 12000, 8000};
    if (versionBits == 3) return mpeg1[index];
    if (versionBits == 2) return mpeg2[index];
    if (versionBits == 0) return mpeg25[index];
    return 0;
}

int mp3FrameSize(const QByteArray &stream, qsizetype offset)
{
    if (!hasBytes(stream, offset, 4)) {
        return 0;
    }
    const uchar b0 = static_cast<uchar>(stream[offset]);
    const uchar b1 = static_cast<uchar>(stream[offset + 1]);
    const uchar b2 = static_cast<uchar>(stream[offset + 2]);
    if (b0 != 0xFF || (b1 & 0xE0) != 0xE0) {
        return 0;
    }
    const int versionBits = (b1 >> 3) & 0x03;
    const int layerBits = (b1 >> 1) & 0x03;
    const int bitrateIndex = (b2 >> 4) & 0x0F;
    const int sampleRateIndex = (b2 >> 2) & 0x03;
    const int padding = (b2 >> 1) & 0x01;
    const int bitrate = mp3BitrateKbps(versionBits, layerBits, bitrateIndex);
    const int sampleRate = mp3SampleRate(versionBits, sampleRateIndex);
    if (bitrate == 0 || sampleRate == 0) {
        return 0;
    }
    if (layerBits == 3) {
        return ((12 * bitrate * 1000 / sampleRate) + padding) * 4;
    }
    const int coefficient = (versionBits == 3 || layerBits == 2) ? 144 : 72;
    return coefficient * bitrate * 1000 / sampleRate + padding;
}

std::optional<CarvedFile> carveMp3(const QByteArray &stream, qsizetype start)
{
    qsizetype offset = start;
    if (startsWithAt(stream, start, QByteArrayLiteral("ID3"))) {
        if (!hasBytes(stream, start, 10)) {
            return std::nullopt;
        }
        const int tagSize = synchsafeToInt(stream, start + 6);
        if (tagSize < 0) {
            return std::nullopt;
        }
        offset = start + 10 + tagSize;
    }

    int frames = 0;
    qsizetype end = offset;
    while (hasBytes(stream, end, 4)) {
        const int frameSize = mp3FrameSize(stream, end);
        if (frameSize <= 4 || !hasBytes(stream, end, frameSize)) {
            break;
        }
        const qsizetype tagOffset = stream.indexOf(QByteArrayLiteral("TAG"), end);
        if (tagOffset == end) {
            break;
        }
        if (tagOffset > end && tagOffset < end + frameSize && tagOffset - end < 1024) {
            end = tagOffset;
            break;
        }
        end += frameSize;
        ++frames;
    }
    if (frames < 8) {
        return std::nullopt;
    }
    bool includedTrailingTag = false;
    if (hasBytes(stream, end, 128) && startsWithAt(stream, end, QByteArrayLiteral("TAG"))) {
        end += 128;
        includedTrailingTag = true;
    }
    if (hasBytes(stream, end, 32) && startsWithAt(stream, end, QByteArrayLiteral("APETAGEX"))) {
        const quint32 apeSize = readLe32(stream, end + 12);
        if (apeSize >= 32 && apeSize <= quint32(stream.size() - end) && startsWithAt(stream, end + qsizetype(apeSize) - 32, QByteArrayLiteral("APETAGEX"))) {
            end += qsizetype(apeSize);
            includedTrailingTag = true;
        }
    }
    const QString validation = includedTrailingTag
        ? QStringLiteral("ID3 tag, MPEG audio frame chain, and trailing ID3v1/APE tag validated")
        : QStringLiteral("ID3 tag and MPEG audio frame chain validated");
    return makeResult(stream, start, qint64(end - start), QStringLiteral("MP3 audio"), QStringLiteral("mp3"),
        QStringLiteral("Structure"), validation, QStringLiteral("Medium"),
        QStringLiteral("Recovered by MP3 frame-chain structure carver with trailing tag preservation."));
}

std::optional<CarvedFile> carveMpeg(const QByteArray &stream, qsizetype start)
{
    if (!isMpegStartCode(stream, start)) {
        return std::nullopt;
    }
    const uchar firstCode = static_cast<uchar>(stream[start + 3]);
    if (firstCode != 0xBA && firstCode != 0xB3) {
        return std::nullopt;
    }

    qsizetype cursor = start;
    qsizetype end = start;
    int startCodes = 0;
    bool sawPack = false;
    bool sawSequence = false;
    bool sawPayload = false;
    bool sawSequenceEnd = false;
    constexpr qsizetype MaxMpegStartCodeGap = qsizetype(1024) * 1024;

    while (cursor >= 0 && cursor + 4 <= stream.size()) {
        if (!isMpegStartCode(stream, cursor)) {
            cursor = stream.indexOf(QByteArray::fromHex("000001"), cursor + 1);
            continue;
        }

        const uchar code = static_cast<uchar>(stream[cursor + 3]);
        qsizetype next = stream.indexOf(QByteArray::fromHex("000001"), cursor + 4);
        bool foundNextStartCode = next >= 0;
        bool nextStartCodeTooFar = false;
        if (!foundNextStartCode) {
            next = cursor + 4;
        } else if (next - cursor > MaxMpegStartCodeGap) {
            nextStartCodeTooFar = true;
        }

        bool accepted = true;
        qsizetype packetEnd = next;
        if (code == 0xBA) {
            if (nextStartCodeTooFar) {
                break;
            }
            sawPack = true;
            if (!hasBytes(stream, cursor, 12)) {
                return std::nullopt;
            }
            if (hasBytes(stream, cursor, 14) && (static_cast<uchar>(stream[cursor + 4]) & 0xC0) == 0x40) {
                packetEnd = cursor + 14 + qsizetype(static_cast<uchar>(stream[cursor + 13]) & 0x07);
            } else {
                packetEnd = cursor + 12;
            }
        } else if (code == 0xBB) {
            if (!hasBytes(stream, cursor, 6)) {
                return std::nullopt;
            }
            packetEnd = cursor + 6 + qsizetype(readBe16(stream, cursor + 4));
        } else if (code == 0xB3) {
            if (!foundNextStartCode || nextStartCodeTooFar) {
                break;
            }
            sawSequence = true;
        } else if (code == 0xB7) {
            sawSequenceEnd = true;
            packetEnd = cursor + 4;
            end = packetEnd;
            ++startCodes;
            break;
        } else if (code == 0xB5 || code == 0xB8 || code == 0x00 || (code >= 0x01 && code <= 0xAF)) {
            if (!foundNextStartCode || nextStartCodeTooFar) {
                break;
            }
            sawPayload = true;
        } else if ((code >= 0xBC && code <= 0xBF) || (code >= 0xC0 && code <= 0xEF)) {
            if (!hasBytes(stream, cursor, 6)) {
                return std::nullopt;
            }
            const quint16 packetLength = readBe16(stream, cursor + 4);
            sawPayload = true;
            if (packetLength > 0) {
                packetEnd = cursor + 6 + qsizetype(packetLength);
            } else if (!foundNextStartCode || nextStartCodeTooFar) {
                break;
            }
        } else {
            accepted = false;
        }

        if (!accepted) {
            break;
        }
        if (packetEnd <= cursor || packetEnd > stream.size()) {
            return std::nullopt;
        }
        end = std::max(end, packetEnd);
        ++startCodes;
        if (nextStartCodeTooFar) {
            break;
        }
        cursor = std::max(packetEnd, next);
    }

    if (end <= start || startCodes < 3 || (!sawPack && !sawSequence) || !sawPayload) {
        return std::nullopt;
    }

    QString validation = sawSequenceEnd
        ? QStringLiteral("MPEG start-code chain, packet lengths, and sequence-end code validated")
        : QStringLiteral("MPEG start-code chain and packet lengths validated");
    const std::optional<qsizetype> foreignBoundary = findNextSectorAlignedForeignSignature(stream, start, end);
    if (foreignBoundary.has_value() && *foreignBoundary > start) {
        end = *foreignBoundary;
        validation += QStringLiteral("; trimmed at next sector-aligned foreign file signature");
    }
    const QString confidence = sawSequenceEnd ? QStringLiteral("High") : QStringLiteral("Medium");
    return makeResult(stream, start, qint64(end - start), QStringLiteral("MPEG video"), QStringLiteral("mpg"),
        QStringLiteral("Structure"), validation, confidence,
        QStringLiteral("Recovered by MPEG program/video stream start-code chain parser."));
}

std::optional<qsizetype> parseRar4End(const QByteArray &stream, qsizetype start)
{
    qsizetype offset = start + 7;
    while (hasBytes(stream, offset, 7)) {
        const uchar blockType = static_cast<uchar>(stream[offset + 2]);
        const quint16 flags = readLe16(stream, offset + 3);
        const quint16 headerSize = readLe16(stream, offset + 5);
        if (headerSize < 7 || !hasBytes(stream, offset, headerSize)) {
            return std::nullopt;
        }
        qsizetype blockSize = headerSize;
        if (flags & 0x8000) {
            if (!hasBytes(stream, offset + 7, 4)) {
                return std::nullopt;
            }
            blockSize += qsizetype(readLe32(stream, offset + 7));
        }
        if (blockType == 0x7B) {
            return offset + headerSize;
        }
        if (blockSize <= 0 || !hasBytes(stream, offset, blockSize)) {
            return std::nullopt;
        }
        offset += blockSize;
    }
    return std::nullopt;
}

std::optional<CarvedFile> carveFlv(const QByteArray &stream, qsizetype start)
{
    if (!hasBytes(stream, start, 13) || !startsWithAt(stream, start, QByteArrayLiteral("FLV"))) {
        return std::nullopt;
    }
    const quint32 dataOffset = readBe32(stream, start + 5);
    if (dataOffset < 9 || !hasBytes(stream, start, qsizetype(dataOffset) + 4)) {
        return std::nullopt;
    }
    qsizetype offset = start + qsizetype(dataOffset) + 4;
    qsizetype end = offset;
    int tags = 0;
    while (hasBytes(stream, offset, 11)) {
        const uchar tagType = static_cast<uchar>(stream[offset]);
        if (tagType != 0x08 && tagType != 0x09 && tagType != 0x12) {
            break;
        }
        const quint32 dataSize = (quint32(static_cast<uchar>(stream[offset + 1])) << 16)
            | (quint32(static_cast<uchar>(stream[offset + 2])) << 8)
            | quint32(static_cast<uchar>(stream[offset + 3]));
        const qsizetype next = offset + 11 + qsizetype(dataSize) + 4;
        if (!hasBytes(stream, offset, 11 + qsizetype(dataSize) + 4)) {
            break;
        }
        end = next;
        offset = next;
        ++tags;
    }
    if (tags == 0) {
        return std::nullopt;
    }
    return makeResult(stream, start, qint64(end - start), QStringLiteral("FLV video"), QStringLiteral("flv"),
        QStringLiteral("Structure"), QStringLiteral("FLV tag chain validated"), QStringLiteral("Medium"),
        QStringLiteral("Recovered by FLV tag-chain structure carver."));
}

std::optional<CarvedFile> carveGzip(const QByteArray &stream, qsizetype start)
{
    if (!hasBytes(stream, start, 10) || !startsWithAt(stream, start, QByteArray::fromHex("1F8B08"))) {
        return std::nullopt;
    }

    const uchar flags = static_cast<uchar>(stream[start + 3]);
    if ((flags & 0xE0) != 0) {
        return std::nullopt;
    }

    qsizetype offset = start + 10;
    if (flags & 0x04) {
        if (!hasBytes(stream, offset, 2)) {
            return std::nullopt;
        }
        const quint16 extraLength = readLe16(stream, offset);
        offset += 2 + qsizetype(extraLength);
        if (!hasBytes(stream, offset, 1)) {
            return std::nullopt;
        }
    }
    auto skipCString = [&](qsizetype *cursor) -> bool {
        while (*cursor < stream.size()) {
            if (stream[*cursor] == '\0') {
                ++(*cursor);
                return true;
            }
            ++(*cursor);
        }
        return false;
    };
    if ((flags & 0x08) && !skipCString(&offset)) {
        return std::nullopt;
    }
    if ((flags & 0x10) && !skipCString(&offset)) {
        return std::nullopt;
    }
    if (flags & 0x02) {
        offset += 2;
        if (!hasBytes(stream, offset, 1)) {
            return std::nullopt;
        }
    }

    z_stream zstream {};
    if (inflateInit2(&zstream, -MAX_WBITS) != Z_OK) {
        return std::nullopt;
    }

    QByteArray scratch(64 * 1024, Qt::Uninitialized);
    zstream.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(stream.constData() + offset));
    zstream.avail_in = uInt(stream.size() - offset);
    int ret = Z_OK;
    do {
        zstream.next_out = reinterpret_cast<Bytef *>(scratch.data());
        zstream.avail_out = uInt(scratch.size());
        ret = inflate(&zstream, Z_NO_FLUSH);
    } while (ret == Z_OK);

    const quint64 compressedBytes = zstream.total_in;
    const quint64 uncompressedBytes = zstream.total_out;
    inflateEnd(&zstream);
    if (ret != Z_STREAM_END) {
        return std::nullopt;
    }

    const quint64 fileSize = quint64(offset - start) + compressedBytes + 8;
    if (fileSize > quint64(std::numeric_limits<qsizetype>::max()) || !hasBytes(stream, start, qsizetype(fileSize))) {
        return std::nullopt;
    }
    const qsizetype trailer = start + qsizetype(fileSize) - 8;
    const quint32 isize = readLe32(stream, trailer + 4);
    if (isize != quint32(uncompressedBytes & 0xFFFFFFFFU)) {
        return std::nullopt;
    }

    return makeResult(stream, start, qint64(fileSize), QStringLiteral("GZip archive"), QStringLiteral("gz"),
        QStringLiteral("Val"), QStringLiteral("GZip header, deflate stream end, and ISIZE trailer validated"), QStringLiteral("High"),
        QStringLiteral("Recovered by gzip header parser and zlib deflate stream validator."));
}

std::optional<CarvedFile> carveWim(const QByteArray &stream, qsizetype start)
{
    if (!hasBytes(stream, start, 208) || !startsWithAt(stream, start, QByteArrayLiteral("MSWIM\0\0\0"))) {
        return std::nullopt;
    }
    const quint32 headerSize = readLe32(stream, start + 8);
    const quint32 version = readLe32(stream, start + 12);
    if (headerSize < 148 || headerSize > 4096 || version == 0 || !hasBytes(stream, start, qsizetype(headerSize))) {
        return std::nullopt;
    }

    quint64 fileSize = headerSize;
    auto extendFromResource = [&](qsizetype resourceOffset) -> bool {
        if (!hasBytes(stream, start + resourceOffset, 24)) {
            return false;
        }
        const quint64 packedSize = readLe64(stream, start + resourceOffset);
        const quint64 size = packedSize & 0x00FFFFFFFFFFFFFFULL;
        const quint64 offset = readLe64(stream, start + resourceOffset + 8);
        if (size == 0) {
            return true;
        }
        const quint64 end = offset + size;
        if (offset < headerSize || end <= offset || end > quint64(std::numeric_limits<qsizetype>::max())) {
            return false;
        }
        fileSize = std::max(fileSize, end);
        return true;
    };

    if (!extendFromResource(0x30) || !extendFromResource(0x48) || !extendFromResource(0x60) || !extendFromResource(0x78)) {
        return std::nullopt;
    }
    if (fileSize <= headerSize || !hasBytes(stream, start, qsizetype(fileSize))) {
        return std::nullopt;
    }
    return makeResult(stream, start, qint64(fileSize), QStringLiteral("WIM image"), QStringLiteral("wim"),
        QStringLiteral("HeaderLength"), QStringLiteral("WIM header resource offsets and sizes validated"), QStringLiteral("High"),
        QStringLiteral("Recovered by WIM resource table length parser."));
}

std::optional<CarvedFile> carve7z(const QByteArray &stream, qsizetype start)
{
    if (!hasBytes(stream, start, 32) || !startsWithAt(stream, start, QByteArray::fromHex("377ABCAF271C"))) {
        return std::nullopt;
    }
    const quint32 expectedStartHeaderCrc = readLe32(stream, start + 8);
    const quint32 actualStartHeaderCrc = crc32(stream.constData() + start + 12, 20);
    if (expectedStartHeaderCrc != actualStartHeaderCrc) {
        return std::nullopt;
    }
    const quint64 nextHeaderOffset = readLe64(stream, start + 12);
    const quint64 nextHeaderSize = readLe64(stream, start + 20);
    const quint32 expectedNextHeaderCrc = readLe32(stream, start + 28);
    const quint64 fileSize = 32 + nextHeaderOffset + nextHeaderSize;
    if (fileSize <= 32 || fileSize > quint64(std::numeric_limits<qsizetype>::max()) || !hasBytes(stream, start, qsizetype(fileSize))) {
        const std::optional<qsizetype> nextSignature = findNextStrongSignature(stream, start + 6);
        if (nextSignature.has_value() && *nextSignature > start + 32) {
            return makeResult(stream, start, qint64(*nextSignature - start), QStringLiteral("7z archive"), QStringLiteral("7z"),
                QStringLiteral("HeaderBoundaryFallback"), QStringLiteral("7z Start Header CRC validated; ended at next strong signature after invalid Next Header bounds"), QStringLiteral("Low"),
                QStringLiteral("Recovered by conservative 7z fallback after strict Next Header validation failed."));
        }
        return std::nullopt;
    }
    const qsizetype nextHeaderStart = start + 32 + qsizetype(nextHeaderOffset);
    if (nextHeaderSize > 0) {
        if (!hasBytes(stream, nextHeaderStart, qsizetype(nextHeaderSize))) {
            return std::nullopt;
        }
        const quint32 actualNextHeaderCrc = crc32(stream.constData() + nextHeaderStart, qsizetype(nextHeaderSize));
        if (expectedNextHeaderCrc != actualNextHeaderCrc) {
            const std::optional<qsizetype> nextSignature = findNextStrongSignature(stream, start + 6);
            if (nextSignature.has_value() && *nextSignature > start + 32) {
                return makeResult(stream, start, qint64(*nextSignature - start), QStringLiteral("7z archive"), QStringLiteral("7z"),
                    QStringLiteral("HeaderBoundaryFallback"), QStringLiteral("7z Start Header CRC validated; Next Header CRC failed, ended at next strong signature"), QStringLiteral("Low"),
                    QStringLiteral("Recovered by conservative 7z fallback after strict Next Header CRC failed."));
            }
            return std::nullopt;
        }
    }
    return makeResult(stream, start, qint64(fileSize), QStringLiteral("7z archive"), QStringLiteral("7z"),
        QStringLiteral("Val"), QStringLiteral("7z Start Header CRC and Next Header CRC validated"), QStringLiteral("High"),
        QStringLiteral("Recovered by CRC-validated 7z Start Header parser."));
}

std::optional<CarvedFile> carveBzip2(const QByteArray &stream, qsizetype start)
{
    if (!hasBytes(stream, start, 4)) {
        return std::nullopt;
    }
    const uchar blockSize = static_cast<uchar>(stream[start + 3]);
    if (blockSize < '1' || blockSize > '9') {
        return std::nullopt;
    }

    bz_stream bzStream {};
    int bzStatus = BZ2_bzDecompressInit(&bzStream, 0, 0);
    if (bzStatus != BZ_OK) {
        return std::nullopt;
    }

    auto finish = [&]() {
        BZ2_bzDecompressEnd(&bzStream);
    };

    qsizetype cursor = start;
    constexpr qsizetype ChunkBytes = qsizetype(1024) * 1024;
    char outputBuffer[32 * 1024];
    while (cursor < stream.size()) {
        const qsizetype chunkSize = std::min<qsizetype>(ChunkBytes, stream.size() - cursor);
        bzStream.next_in = const_cast<char *>(stream.constData() + cursor);
        bzStream.avail_in = unsigned(chunkSize);

        do {
            bzStream.next_out = outputBuffer;
            bzStream.avail_out = sizeof(outputBuffer);
            bzStatus = BZ2_bzDecompress(&bzStream);
            if (bzStatus == BZ_STREAM_END) {
                const qsizetype consumed = chunkSize - qsizetype(bzStream.avail_in);
                cursor += consumed;
                finish();
                return makeResult(stream, start, qint64(cursor - start), QStringLiteral("BZip2 archive"), QStringLiteral("bz2"),
                    QStringLiteral("Val"), QStringLiteral("BZip2 stream decompressed to BZ_STREAM_END"), QStringLiteral("High"),
                    QStringLiteral("Recovered by libbz2 decompressor EOF validator."));
            }
            if (bzStatus != BZ_OK) {
                finish();
                return std::optional<CarvedFile>();
            }
        } while (bzStream.avail_in > 0);

        cursor += chunkSize;
    }

    finish();
    return std::nullopt;
}

std::optional<CarvedFile> carveBzip2MarkerFallback(const QByteArray &stream, qsizetype start)
{
    if (!hasBytes(stream, start, 4)) {
        return std::nullopt;
    }
    const uchar blockSize = static_cast<uchar>(stream[start + 3]);
    if (blockSize < '1' || blockSize > '9') {
        return std::nullopt;
    }
    const QByteArray blockMagic = QByteArray::fromHex("314159265359");
    const QByteArray footer = QByteArray::fromHex("177245385090");
    const qsizetype firstBlock = stream.indexOf(blockMagic, start + 4);
    if (firstBlock < 0) {
        return std::nullopt;
    }
    const qsizetype end = stream.indexOf(footer, firstBlock + blockMagic.size());
    if (end <= start) {
        return std::nullopt;
    }
    return makeResult(stream, start, qint64(end - start + footer.size()), QStringLiteral("BZip2 archive"), QStringLiteral("bz2"),
        QStringLiteral("Structure"), QStringLiteral("BZip2 block size, block magic, and stream-end marker validated"), QStringLiteral("Medium"),
        QStringLiteral("Recovered by BZip2 structural marker parser."));
}

std::optional<CarvedFile> carveRar(const QByteArray &stream, qsizetype start)
{
    const bool rar4 = startsWithAt(stream, start, QByteArrayLiteral("Rar!\x1A\x07\x00"));
    const bool rar5 = startsWithAt(stream, start, QByteArrayLiteral("Rar!\x1A\x07\x01\x00"));
    if (!rar4 && !rar5) {
        return std::nullopt;
    }
    if (rar4) {
        const std::optional<qsizetype> end = parseRar4End(stream, start);
        if (end.has_value() && *end > start) {
            return makeResult(stream, start, qint64(*end - start), QStringLiteral("RAR archive"), QStringLiteral("rar"),
                QStringLiteral("Structure"), QStringLiteral("RAR4 block chain and end-of-archive block validated"), QStringLiteral("High"),
                QStringLiteral("Recovered by RAR4 block-chain parser."));
        }
    }
    return std::nullopt;
}

std::optional<CarvedFile> carveAu(const QByteArray &stream, qsizetype start)
{
    if (!hasBytes(stream, start, 24) || !startsWithAt(stream, start, QByteArrayLiteral(".snd"))) {
        return std::nullopt;
    }
    const quint32 dataOffset = readBe32(stream, start + 4);
    const quint32 dataSize = readBe32(stream, start + 8);
    const quint32 encoding = readBe32(stream, start + 12);
    const quint32 sampleRate = readBe32(stream, start + 16);
    const quint32 channels = readBe32(stream, start + 20);
    if (dataOffset < 24 || dataSize == 0xFFFFFFFFU || dataSize == 0 || encoding == 0 || sampleRate == 0 || channels == 0) {
        return std::nullopt;
    }
    const quint64 fileSize = quint64(dataOffset) + dataSize;
    if (fileSize > quint64(std::numeric_limits<qsizetype>::max()) || !hasBytes(stream, start, qsizetype(fileSize))) {
        return std::nullopt;
    }
    return makeResult(stream, start, qint64(fileSize), QStringLiteral("AU audio"), QStringLiteral("au"),
        QStringLiteral("HeaderLength"), QStringLiteral("AU data offset, data size, encoding, sample rate, and channels validated"), QStringLiteral("High"),
        QStringLiteral("Recovered by AU header length fields."));
}

std::optional<CarvedFile> carveByNextSignature(const QByteArray &stream,
                                               qsizetype start,
                                               const QByteArray &signature,
                                               const QString &type,
                                               const QString &extension)
{
    const qsizetype next = stream.indexOf(signature, start + signature.size());
    if (next <= start) {
        return std::nullopt;
    }
    return makeResult(stream, start, qint64(next - start), type, extension, QStringLiteral("Signature"),
        QStringLiteral("Ended at next same-format signature"), QStringLiteral("Low"),
        QStringLiteral("Recovered by fallback signature-delimited carver."));
}
}

struct SignatureCarver::CarveCandidate
{
    qsizetype offset = 0;
    QString family;
};

struct SignatureCarver::FormatCarver
{
    QString family;
    QByteArray signature;
    QString type;
    QString extension;
    std::optional<CarvedFile> (*carve)(const QByteArray &, qsizetype) = nullptr;
    bool supportsHeaderFooter = false;
    bool supportsHeaderMax = false;
    bool supportsHeaderLength = false;
    bool supportsFileStructure = true;
};

QVector<SignatureCarver::FormatCarver> SignatureCarver::carvers()
{
    return {
        {QStringLiteral("jpg"), QByteArray::fromHex("FFD8FF"), QStringLiteral("JPEG image"), QStringLiteral("jpg"), &carveJpeg, true, true, false, true},
        {QStringLiteral("png"), QByteArray::fromHex("89504E470D0A1A0A"), QStringLiteral("PNG image"), QStringLiteral("png"), &carvePng, true, false, false, true},
        {QStringLiteral("gif87"), QByteArrayLiteral("GIF87a"), QStringLiteral("GIF image"), QStringLiteral("gif"), &carveGif, true, false, false, true},
        {QStringLiteral("gif89"), QByteArrayLiteral("GIF89a"), QStringLiteral("GIF image"), QStringLiteral("gif"), &carveGif, true, false, false, true},
        {QStringLiteral("bmp"), QByteArrayLiteral("BM"), QStringLiteral("BMP image"), QStringLiteral("bmp"), &carveBmp, false, false, true, true},
        {QStringLiteral("pdf"), QByteArrayLiteral("%PDF"), QStringLiteral("PDF document"), QStringLiteral("pdf"), &carvePdf, true, false, false, true},
        {QStringLiteral("zip"), QByteArray::fromHex("504B0304"), QStringLiteral("ZIP/OOXML archive"), QStringLiteral("zip"), &carveZip, true, false, true, true},
        {QStringLiteral("riff"), QByteArrayLiteral("RIFF"), QStringLiteral("RIFF media"), QStringLiteral("riff"), &carveRiff, true, false, true, true},
        {QStringLiteral("mp4"), QByteArrayLiteral("ftyp"), QStringLiteral("MP4/MOV video"), QStringLiteral("mp4"), &carveIsoBmff, false, false, true, true},
        {QStringLiteral("wmv"), QByteArray::fromHex("3026B2758E66CF11A6D900AA0062CE6C"), QStringLiteral("ASF/WMV media"), QStringLiteral("wmv"), &carveAsf, false, false, true, true},
        {QStringLiteral("tar"), QByteArrayLiteral("ustar"), QStringLiteral("TAR archive"), QStringLiteral("tar"), &carveTar, true, false, true, true},
        {QStringLiteral("tif-le"), QByteArrayLiteral("II*\0"), QStringLiteral("TIFF image"), QStringLiteral("tif"), &carveTiff, false, false, true, true},
        {QStringLiteral("tif-be"), QByteArrayLiteral("MM\0*"), QStringLiteral("TIFF image"), QStringLiteral("tif"), &carveTiff, false, false, true, true},
        {QStringLiteral("pcx"), QByteArray(1, char(0x0A)), QStringLiteral("PCX image"), QStringLiteral("pcx"), &carvePcx, false, false, true, true},
        {QStringLiteral("7z"), QByteArray::fromHex("377ABCAF271C"), QStringLiteral("7z archive"), QStringLiteral("7z"), &carve7z, false, false, true, true},
        {QStringLiteral("rar"), QByteArrayLiteral("Rar!\x1A\x07"), QStringLiteral("RAR archive"), QStringLiteral("rar"), &carveRar, true, false, false, true},
        {QStringLiteral("gz"), QByteArray::fromHex("1F8B08"), QStringLiteral("GZip archive"), QStringLiteral("gz"), &carveGzip, true, true, true, true},
        {QStringLiteral("bz2"), QByteArrayLiteral("BZh"), QStringLiteral("BZip2 archive"), QStringLiteral("bz2"), &carveBzip2, true, false, false, true},
        {QStringLiteral("wim"), QByteArrayLiteral("MSWIM\0\0\0"), QStringLiteral("WIM image"), QStringLiteral("wim"), &carveWim, false, false, true, true},
        {QStringLiteral("mp3-id3"), QByteArrayLiteral("ID3"), QStringLiteral("MP3 audio"), QStringLiteral("mp3"), &carveMp3, true, true, true, true},
        {QStringLiteral("mp3-frame"), QByteArray::fromHex("FF"), QStringLiteral("MP3 audio"), QStringLiteral("mp3"), &carveMp3, true, true, false, true},
        {QStringLiteral("mpeg-pack"), QByteArray::fromHex("000001BA"), QStringLiteral("MPEG video"), QStringLiteral("mpg"), &carveMpeg, true, false, false, true},
        {QStringLiteral("mpeg-seq"), QByteArray::fromHex("000001B3"), QStringLiteral("MPEG video"), QStringLiteral("mpg"), &carveMpeg, true, false, false, true},
        {QStringLiteral("flv"), QByteArrayLiteral("FLV"), QStringLiteral("FLV video"), QStringLiteral("flv"), &carveFlv, false, false, true, true},
        {QStringLiteral("au"), QByteArrayLiteral(".snd"), QStringLiteral("AU audio"), QStringLiteral("au"), &carveAu, false, true, true, true}
    };
}

QVector<SignatureCarver::CarveCandidate> SignatureCarver::scanCandidates(const QByteArray &stream, qsizetype scanStride, qsizetype windowStart, qsizetype windowEnd)
{
    QVector<CarveCandidate> candidates;
    const QVector<FormatCarver> availableCarvers = carvers();
    const qsizetype step = std::max<qsizetype>(1, scanStride);
    const qsizetype boundedStart = std::max<qsizetype>(0, windowStart);
    const qsizetype boundedEnd = std::min<qsizetype>(stream.size(), windowEnd);
    if (boundedStart >= boundedEnd) {
        return candidates;
    }

    auto appendCandidate = [&](qsizetype offset, const QString &family) {
        if (offset < boundedStart || offset >= boundedEnd) {
            return;
        }
        for (const CarveCandidate &candidate : candidates) {
            if (candidate.offset == offset && candidate.family == family) {
                return;
            }
        }
        candidates.append(CarveCandidate{offset, family});
    };

    for (const FormatCarver &carver : availableCarvers) {
        if (carver.family == QStringLiteral("tar")
            || carver.family == QStringLiteral("mp4")
            || carver.family == QStringLiteral("pcx")
            || carver.family == QStringLiteral("mp3-frame")
            || carver.signature.size() < 3) {
            continue;
        }

        qsizetype hit = stream.indexOf(carver.signature, boundedStart);
        if (carver.family == QStringLiteral("mpeg-pack") || carver.family == QStringLiteral("mpeg-seq")) {
            while (hit >= 0 && hit < boundedEnd) {
                if ((hit % 512) == 0) {
                    appendCandidate(hit, carver.family);
                    if (carver.carve) {
                        const std::optional<CarvedFile> parsed = carver.carve(stream, hit);
                        if (parsed.has_value() && parsed->logicalEnd > quint64(hit)) {
                            const qsizetype skipTo = qMin<qsizetype>(boundedEnd, qsizetype(parsed->logicalEnd + 1));
                            hit = stream.indexOf(carver.signature, qMax(hit + 1, skipTo));
                            continue;
                        }
                    }
                }
                hit = stream.indexOf(carver.signature, hit + 1);
            }
            continue;
        }
        while (hit >= 0 && hit < boundedEnd) {
            appendCandidate(hit, carver.family);
            hit = stream.indexOf(carver.signature, hit + 1);
        }
    }

    qsizetype ftypHit = stream.indexOf(QByteArrayLiteral("ftyp"), boundedStart);
    while (ftypHit >= 0 && ftypHit < boundedEnd) {
        const qsizetype candidateOffset = ftypHit - 4;
        if (candidateOffset >= 0 && hasBytes(stream, candidateOffset, 12)) {
            appendCandidate(candidateOffset, QStringLiteral("mp4"));
        }
        ftypHit = stream.indexOf(QByteArrayLiteral("ftyp"), ftypHit + 1);
    }

    qsizetype ustarHit = stream.indexOf(QByteArrayLiteral("ustar"), boundedStart);
    while (ustarHit >= 0 && ustarHit < boundedEnd) {
        const qsizetype candidateOffset = ustarHit - 257;
        if (candidateOffset >= 0 && hasBytes(stream, candidateOffset, 512)) {
            appendCandidate(candidateOffset, QStringLiteral("tar"));
        }
        ustarHit = stream.indexOf(QByteArrayLiteral("ustar"), ustarHit + 1);
    }

    for (qsizetype offset = boundedStart; offset < boundedEnd; offset += step) {
        for (const FormatCarver &carver : availableCarvers) {
            if (carver.family == QStringLiteral("tar")) {
                if (hasBytes(stream, offset, 512) && parseTarHeaderSize(stream.mid(offset, 512)).has_value()) {
                    appendCandidate(offset, carver.family);
                }
                continue;
            }
            if (carver.family == QStringLiteral("mp4")) {
                if (hasBytes(stream, offset, 12) && stream.mid(offset + 4, 4) == QByteArrayLiteral("ftyp")) {
                    appendCandidate(offset, carver.family);
                }
                continue;
            }
            if (carver.family == QStringLiteral("pcx")) {
                if (hasBytes(stream, offset, 128)
                    && static_cast<uchar>(stream[offset]) == 0x0A
                    && static_cast<uchar>(stream[offset + 1]) <= 0x05
                    && static_cast<uchar>(stream[offset + 2]) == 0x01) {
                    appendCandidate(offset, carver.family);
                }
                continue;
            }
            if (carver.family == QStringLiteral("mp3-frame")) {
                if (hasBytes(stream, offset, 4) && mp3FrameSize(stream, offset) > 4) {
                    appendCandidate(offset, carver.family);
                }
                continue;
            }
            if (carver.signature.size() < 3 && startsWithAt(stream, offset, carver.signature)) {
                appendCandidate(offset, carver.family);
            }
        }
    }

    std::sort(candidates.begin(), candidates.end(), [](const CarveCandidate &left, const CarveCandidate &right) {
        if (left.offset == right.offset) {
            return left.family < right.family;
        }
        return left.offset < right.offset;
    });
    return candidates;
}

QVector<CarvedFile> SignatureCarver::carve(const QByteArray &stream, qsizetype scanStride) const
{
    return carve(stream, scanStride, 0);
}

QVector<CarvedFile> SignatureCarver::carve(const QByteArray &stream, qsizetype scanStride, quint64 logicalBaseOffset) const
{
    return carve(stream, scanStride, logicalBaseOffset, LogCallback());
}

QVector<CarvedFile> SignatureCarver::carve(const QByteArray &stream, qsizetype scanStride, quint64 logicalBaseOffset, const LogCallback &logCallback) const
{
    QVector<CarvedFile> results;
    const QVector<FormatCarver> availableCarvers = carvers();
    constexpr qsizetype WindowBytes = qsizetype(256) * 1024 * 1024;
    const unsigned int hardwareThreads = std::thread::hardware_concurrency();
    const int maxParallelTasks = std::max(1, std::min<int>(int(hardwareThreads == 0 ? 2 : hardwareThreads), 4));

    auto log = [&](const QString &message) {
        if (logCallback) {
            logCallback(message);
        }
    };

    auto hexSignature = [](const QByteArray &signature) -> QString {
        return QString::fromLatin1(signature.toHex(' ').toUpper());
    };

    auto formatOffset = [](quint64 offset) -> QString {
        return QStringLiteral("0x%1").arg(offset, 0, 16).toUpper();
    };

    auto parseCandidate = [&](const CarveCandidate &candidate,
                              qsizetype fallbackLimit,
                              const QVector<CarveCandidate> &windowCandidates) -> std::optional<CarvedFile> {
        auto carverIt = std::find_if(availableCarvers.begin(), availableCarvers.end(), [&](const FormatCarver &carver) {
            return carver.family == candidate.family;
        });
        if (carverIt == availableCarvers.end()) {
            return std::nullopt;
        }

        if (carverIt->carve) {
            std::optional<CarvedFile> parsed = carverIt->carve(stream, candidate.offset);
            if (parsed.has_value()) {
                return parsed;
            }
            return std::nullopt;
        }

        qsizetype fallbackEnd = fallbackLimit;
        for (const CarveCandidate &nextCandidate : windowCandidates) {
            if (nextCandidate.offset > candidate.offset && nextCandidate.family != candidate.family) {
                fallbackEnd = nextCandidate.offset;
                break;
            }
        }
        if (fallbackEnd <= candidate.offset) {
            return std::nullopt;
        }
        return makeResult(stream,
            candidate.offset,
            qint64(fallbackEnd - candidate.offset),
            carverIt->type,
            carverIt->extension,
            QStringLiteral("SignatureBoundaryFallback"),
            QStringLiteral("Structure parser unavailable; ended at next different signature boundary inside scan window"),
            QStringLiteral("Low"),
            QStringLiteral("Recovered by windowed signature-boundary fallback after format parser was unavailable."));
    };

    auto appendNonOverlapping = [&](QVector<CarvedFile> batchResults) {
        std::sort(batchResults.begin(), batchResults.end(), [](const CarvedFile &left, const CarvedFile &right) {
            if (left.logicalStart == right.logicalStart) {
                const int leftRank = carvingConfidenceRank(left.confidence);
                const int rightRank = carvingConfidenceRank(right.confidence);
                if (leftRank != rightRank) {
                    return leftRank > rightRank;
                }
                return left.logicalEnd > right.logicalEnd;
            }
            return left.logicalStart < right.logicalStart;
        });

        for (const CarvedFile &carved : batchResults) {
            CarvedFile adjusted = carved;
            adjusted.logicalStart += logicalBaseOffset;
            adjusted.logicalEnd += logicalBaseOffset;
            if (!results.isEmpty() && adjusted.logicalStart <= results.last().logicalEnd) {
                const int currentRank = carvingConfidenceRank(adjusted.confidence);
                const int lastRank = carvingConfidenceRank(results.last().confidence);
                const quint64 currentSize = adjusted.logicalEnd >= adjusted.logicalStart ? adjusted.logicalEnd - adjusted.logicalStart : 0;
                const CarvedFile &last = results.last();
                const quint64 lastSize = last.logicalEnd >= last.logicalStart ? last.logicalEnd - last.logicalStart : 0;
                if (currentRank > lastRank || (adjusted.logicalStart == last.logicalStart && currentRank == lastRank && currentSize > lastSize)) {
                    results.last() = adjusted;
                }
                continue;
            }
            results.append(adjusted);
        }
    };

    for (qsizetype windowStart = 0; windowStart < stream.size(); windowStart += WindowBytes) {
        const qsizetype windowEnd = std::min<qsizetype>(stream.size(), windowStart + WindowBytes);
        QVector<CarveCandidate> windowCandidates = scanCandidates(stream, scanStride, windowStart, windowEnd);
        log(QStringLiteral("  Carver window %1-%2 bytes: %3 signature candidates detected.")
                .arg(formatOffset(logicalBaseOffset + quint64(windowStart)))
                .arg(formatOffset(logicalBaseOffset + quint64(windowEnd == 0 ? 0 : windowEnd - 1)))
                .arg(windowCandidates.size()));
        if (windowCandidates.isEmpty()) {
            continue;
        }

        QVector<CarvedFile> windowResults;
        for (int index = 0; index < windowCandidates.size();) {
            struct PendingParse
            {
                CarveCandidate candidate;
                FormatCarver carver;
                std::future<std::optional<CarvedFile>> future;
            };
            std::vector<PendingParse> pending;
            const int batchEnd = std::min<int>(windowCandidates.size(), index + maxParallelTasks);
            for (int taskIndex = index; taskIndex < batchEnd; ++taskIndex) {
                const CarveCandidate candidate = windowCandidates[taskIndex];
                auto carverIt = std::find_if(availableCarvers.begin(), availableCarvers.end(), [&](const FormatCarver &carver) {
                    return carver.family == candidate.family;
                });
                if (carverIt == availableCarvers.end()) {
                    continue;
                }
                log(QStringLiteral("  Signature recognized: offset=%1 family=%2 expected_ext=%3 signature=[%4] parser=%5")
                        .arg(formatOffset(logicalBaseOffset + quint64(candidate.offset)))
                        .arg(candidate.family)
                        .arg(carverIt->extension)
                        .arg(hexSignature(carverIt->signature))
                        .arg(carverIt->carve ? QStringLiteral("format-specific parser") : QStringLiteral("signature-boundary fallback")));
                pending.push_back(PendingParse{candidate, *carverIt, std::async(std::launch::async, [&, candidate, windowEnd]() {
                    return parseCandidate(candidate, windowEnd, windowCandidates);
                })});
            }

            for (auto &item : pending) {
                std::optional<CarvedFile> carved = item.future.get();
                if (carved.has_value()) {
                    log(QStringLiteral("  Carving success: offset=%1 ext=%2 method=%3 confidence=%4 size=%5 bytes validation=\"%6\"")
                            .arg(formatOffset(logicalBaseOffset + carved->logicalStart))
                            .arg(carved->extension)
                            .arg(carved->carvingMethod)
                            .arg(carved->confidence)
                            .arg(carved->data.size())
                            .arg(carved->validationResult));
                    windowResults.append(*carved);
                } else {
                    log(QStringLiteral("  Carving rejected: offset=%1 family=%2 expected_ext=%3 reason=format parser validation failed")
                            .arg(formatOffset(logicalBaseOffset + quint64(item.candidate.offset)))
                            .arg(item.candidate.family)
                            .arg(item.carver.extension));
                }
            }
            index = batchEnd;
        }

        appendNonOverlapping(windowResults);
    }

    return results;
}

QVector<CarveCandidateInfo> SignatureCarver::scan(const QByteArray &stream, qsizetype scanStride, quint64 logicalBaseOffset) const
{
    QVector<CarveCandidateInfo> infos;
    const QVector<FormatCarver> availableCarvers = carvers();
    const QVector<CarveCandidate> candidates = scanCandidates(stream, scanStride, 0, stream.size());
    for (const CarveCandidate &candidate : candidates) {
        auto carverIt = std::find_if(availableCarvers.begin(), availableCarvers.end(), [&](const FormatCarver &carver) {
            return carver.family == candidate.family;
        });
        if (carverIt == availableCarvers.end()) {
            continue;
        }
        CarveCandidateInfo info;
        info.logicalOffset = logicalBaseOffset + quint64(candidate.offset);
        info.family = candidate.family;
        info.signatureHex = QString::fromLatin1(carverIt->signature.toHex(' ').toUpper());
        info.expectedExtension = carverIt->extension;
        info.expectedType = carverIt->type;
        infos.append(info);
    }
    return infos;
}

std::optional<CarvedFile> SignatureCarver::validate(const QByteArray &stream, const CarveCandidateInfo &candidate) const
{
    if (candidate.logicalOffset > quint64(std::numeric_limits<qsizetype>::max())) {
        return std::nullopt;
    }
    const qsizetype offset = qsizetype(candidate.logicalOffset);
    const QVector<FormatCarver> availableCarvers = carvers();
    auto carverIt = std::find_if(availableCarvers.begin(), availableCarvers.end(), [&](const FormatCarver &carver) {
        return carver.family == candidate.family;
    });
    if (carverIt == availableCarvers.end() || !carverIt->carve) {
        return std::nullopt;
    }
    struct Strategy
    {
        QString name;
        bool supported = false;
    };
    const Strategy strategies[] = {
        {QStringLiteral("H/Len"), carverIt->supportsHeaderLength},
        {QStringLiteral("H/F"), carverIt->supportsHeaderFooter},
        {QStringLiteral("H/Max"), carverIt->supportsHeaderMax},
        {QStringLiteral("FSB"), carverIt->supportsFileStructure}
    };

    QStringList attempts;
    for (const Strategy &strategy : strategies) {
        if (!strategy.supported) {
            attempts.append(QStringLiteral("%1 skipped").arg(strategy.name));
            continue;
        }
        std::optional<CarvedFile> parsed = carverIt->carve(stream, offset);
        if (!parsed.has_value()) {
            attempts.append(QStringLiteral("%1 rejected").arg(strategy.name));
            continue;
        }
        parsed->attemptedMethods = attempts.join(QStringLiteral("; "));
        if (!parsed->attemptedMethods.isEmpty()) {
            parsed->attemptedMethods.append(QStringLiteral("; "));
        }
        parsed->attemptedMethods.append(QStringLiteral("%1 validated").arg(strategy.name));
        parsed->selectedMethod = strategy.name;
        parsed->carvingMethod = QStringLiteral("%1+Val").arg(strategy.name);
        return parsed;
    }
    return std::nullopt;
}
