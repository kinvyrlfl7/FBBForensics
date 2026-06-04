#include "imagereader.h"

#include <QFile>
#include <QFileInfo>
#include <libewf.h>
#include <tsk/libtsk.h>

#include <limits>
#include <windows.h>
#include <winioctl.h>

namespace
{
constexpr quint64 PhysicalSectorSize = 512;

bool isPhysicalDrivePath(const QString &path)
{
    return path.startsWith(QStringLiteral("\\\\.\\PhysicalDrive"), Qt::CaseInsensitive);
}

quint64 queryPhysicalDriveSize(const QString &path)
{
    const HANDLE handle = CreateFileW(
        reinterpret_cast<LPCWSTR>(path.utf16()),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return 0;
    }

    GET_LENGTH_INFORMATION lengthInfo{};
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(
        handle,
        IOCTL_DISK_GET_LENGTH_INFO,
        nullptr,
        0,
        &lengthInfo,
        sizeof(lengthInfo),
        &returned,
        nullptr);
    CloseHandle(handle);
    return ok ? quint64(lengthInfo.Length.QuadPart) : 0;
}

QString takeLibewfError(libewf_error_t **error)
{
    if (!error || !*error) {
        return {};
    }

    char message[4096] = {};
    QString result;
    if (libewf_error_sprint(*error, message, sizeof(message)) > 0) {
        result = QString::fromUtf8(message);
    }
    libewf_error_free(error);
    return result;
}

class RawImageReader final : public ImageReader
{
public:
    explicit RawImageReader(const QString &sourcePath)
        : m_sourcePath(sourcePath)
        , m_file(sourcePath)
    {
    }

    bool open(QString *errorMessage) override
    {
        if (m_file.open(QIODevice::ReadOnly)) {
            return true;
        }
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to open raw image/device: %1").arg(m_file.errorString());
        }
        return false;
    }

    void close() override
    {
        m_file.close();
    }

    bool isOpen() const override
    {
        return m_file.isOpen();
    }

    quint64 size() const override
    {
        if (isPhysicalDrivePath(m_sourcePath)) {
            return queryPhysicalDriveSize(m_sourcePath);
        }
        return m_file.size() < 0 ? 0 : quint64(m_file.size());
    }

    QByteArray read(quint64 offset, quint64 size, QString *errorMessage) override
    {
        if (size == 0) {
            return {};
        }

        if (!m_file.seek(offset)) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Seek failed at offset %1 for %2").arg(offset).arg(m_sourcePath);
            }
            return {};
        }

        const QByteArray data = m_file.read(static_cast<qint64>(size));
        if (quint64(data.size()) != size) {
            QByteArray alignedData;
            if (readAligned(offset, size, &alignedData)) {
                return alignedData;
            }
        } else {
            return data;
        }

        if (errorMessage) {
            *errorMessage = QStringLiteral("Read failed at offset %1 for %2").arg(offset).arg(m_sourcePath);
        }
        return {};
    }

    QString backendName() const override
    {
        return QStringLiteral("Raw/QFile");
    }

private:
    bool readAligned(quint64 offset, quint64 size, QByteArray *result)
    {
        if (!isPhysicalDrivePath(m_sourcePath)) {
            return false;
        }

        const quint64 alignedOffset = (offset / PhysicalSectorSize) * PhysicalSectorSize;
        const quint64 offsetDelta = offset - alignedOffset;
        const quint64 alignedEnd = ((offset + size + PhysicalSectorSize - 1) / PhysicalSectorSize) * PhysicalSectorSize;
        const quint64 alignedSize = alignedEnd - alignedOffset;

        if (alignedSize > quint64(std::numeric_limits<int>::max())) {
            return readAlignedInChunks(alignedOffset, offsetDelta, size, result);
        }

        if (!m_file.seek(alignedOffset)) {
            return false;
        }

        const QByteArray data = m_file.read(static_cast<qint64>(alignedSize));
        if (quint64(data.size()) != alignedSize || offsetDelta + size > quint64(data.size())) {
            return false;
        }

        *result = data.mid(static_cast<qsizetype>(offsetDelta), static_cast<qsizetype>(size));
        return quint64(result->size()) == size;
    }

    bool readAlignedInChunks(quint64 alignedOffset, quint64 offsetDelta, quint64 size, QByteArray *result)
    {
        constexpr quint64 ChunkSize = 1024 * 1024;
        const quint64 alignedChunkSize = (ChunkSize / PhysicalSectorSize) * PhysicalSectorSize;
        quint64 bytesNeeded = offsetDelta + size;
        quint64 currentOffset = alignedOffset;
        QByteArray collected;
        collected.reserve(static_cast<qsizetype>(qMin<quint64>(bytesNeeded, quint64(std::numeric_limits<int>::max()))));

        while (bytesNeeded > 0) {
            const quint64 bytesToRead = qMin<quint64>(alignedChunkSize, ((bytesNeeded + PhysicalSectorSize - 1) / PhysicalSectorSize) * PhysicalSectorSize);
            if (!m_file.seek(currentOffset)) {
                return false;
            }
            const QByteArray chunk = m_file.read(static_cast<qint64>(bytesToRead));
            if (quint64(chunk.size()) != bytesToRead) {
                return false;
            }
            collected.append(chunk);
            currentOffset += bytesToRead;
            bytesNeeded = bytesNeeded > bytesToRead ? bytesNeeded - bytesToRead : 0;
        }

        if (offsetDelta + size > quint64(collected.size())) {
            return false;
        }
        *result = collected.mid(static_cast<qsizetype>(offsetDelta), static_cast<qsizetype>(size));
        return quint64(result->size()) == size;
    }

    QString m_sourcePath;
    QFile m_file;
};

class TskImageReader final : public ImageReader
{
public:
    explicit TskImageReader(const QString &sourcePath)
        : m_sourcePath(sourcePath)
    {
    }

    ~TskImageReader() override
    {
        close();
    }

    bool open(QString *errorMessage) override
    {
        close();
        m_image = tsk_img_open_utf8_sing(m_sourcePath.toUtf8().constData(), TSK_IMG_TYPE_DETECT, 0);
        if (m_image) {
            return true;
        }

        if (errorMessage) {
            const char *tskError = tsk_error_get();
            *errorMessage = QStringLiteral("libtsk could not open image through TSK_IMG_TYPE_DETECT. If this is E01, rebuild libtsk with libewf support. %1")
                .arg(tskError && tskError[0] ? QString::fromUtf8(tskError) : QString());
        }
        return false;
    }

    void close() override
    {
        if (m_image) {
            tsk_img_close(m_image);
            m_image = nullptr;
        }
    }

    bool isOpen() const override
    {
        return m_image != nullptr;
    }

    quint64 size() const override
    {
        return m_image ? quint64(m_image->size) : 0;
    }

    QByteArray read(quint64 offset, quint64 size, QString *errorMessage) override
    {
        if (!m_image) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("TSK image reader is not open.");
            }
            return {};
        }

        QByteArray data(static_cast<qsizetype>(size), Qt::Uninitialized);
        const auto bytesRead = tsk_img_read(m_image, static_cast<TSK_OFF_T>(offset), data.data(), static_cast<size_t>(size));
        if (bytesRead < 0 || quint64(bytesRead) != size) {
            if (errorMessage) {
                const char *tskError = tsk_error_get();
                *errorMessage = QStringLiteral("libtsk read failed at offset %1 for %2. %3")
                    .arg(offset)
                    .arg(m_sourcePath)
                    .arg(tskError && tskError[0] ? QString::fromUtf8(tskError) : QString());
            }
            return {};
        }
        return data;
    }

    QString backendName() const override
    {
        return QStringLiteral("libtsk image reader");
    }

private:
    QString m_sourcePath;
    TSK_IMG_INFO *m_image = nullptr;
};

class EwfImageReader final : public ImageReader
{
public:
    explicit EwfImageReader(const QString &sourcePath)
        : m_sourcePath(sourcePath)
    {
    }

    ~EwfImageReader() override
    {
        close();
    }

    bool open(QString *errorMessage) override
    {
        close();

        libewf_error_t *error = nullptr;
        const QByteArray utf8Path = m_sourcePath.toUtf8();
        libewf_set_codepage(0, nullptr);
        if (libewf_glob(utf8Path.constData(), static_cast<size_t>(utf8Path.size()), LIBEWF_FORMAT_UNKNOWN, &m_filenames, &m_numberOfFilenames, &error) != 1
            || m_numberOfFilenames <= 0) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("libewf could not locate E01 segment files for %1. %2")
                    .arg(m_sourcePath, takeLibewfError(&error));
            } else {
                takeLibewfError(&error);
            }
            close();
            return false;
        }

        if (libewf_handle_initialize(&m_handle, &error) != 1 || !m_handle) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("libewf handle initialization failed for %1. %2")
                    .arg(m_sourcePath, takeLibewfError(&error));
            } else {
                takeLibewfError(&error);
            }
            close();
            return false;
        }

        if (libewf_handle_open(m_handle, m_filenames, m_numberOfFilenames, libewf_get_access_flags_read(), &error) != 1) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("libewf could not open E01 image %1. %2")
                    .arg(m_sourcePath, takeLibewfError(&error));
            } else {
                takeLibewfError(&error);
            }
            close();
            return false;
        }

        size64_t mediaSize = 0;
        if (libewf_handle_get_media_size(m_handle, &mediaSize, &error) != 1) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("libewf could not read logical media size for %1. %2")
                    .arg(m_sourcePath, takeLibewfError(&error));
            } else {
                takeLibewfError(&error);
            }
            close();
            return false;
        }

        m_mediaSize = static_cast<quint64>(mediaSize);
        return true;
    }

    void close() override
    {
        if (m_handle) {
            libewf_error_t *error = nullptr;
            libewf_handle_close(m_handle, &error);
            takeLibewfError(&error);
            libewf_handle_free(&m_handle, &error);
            takeLibewfError(&error);
            m_handle = nullptr;
        }

        if (m_filenames) {
            libewf_error_t *error = nullptr;
            libewf_glob_free(m_filenames, m_numberOfFilenames, &error);
            takeLibewfError(&error);
            m_filenames = nullptr;
            m_numberOfFilenames = 0;
        }

        m_mediaSize = 0;
    }

    bool isOpen() const override
    {
        return m_handle != nullptr;
    }

    quint64 size() const override
    {
        return m_mediaSize;
    }

    QByteArray read(quint64 offset, quint64 size, QString *errorMessage) override
    {
        if (size == 0) {
            return {};
        }

        if (!m_handle) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("E01 image reader is not open.");
            }
            return {};
        }

        if (offset > m_mediaSize || size > m_mediaSize - offset) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("E01 read range is outside logical media: offset %1, size %2, media %3.")
                    .arg(offset)
                    .arg(size)
                    .arg(m_mediaSize);
            }
            return {};
        }

        if (size > quint64(std::numeric_limits<qsizetype>::max())) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("E01 read request is too large for a single buffer: %1 bytes.").arg(size);
            }
            return {};
        }

        QByteArray data(static_cast<qsizetype>(size), Qt::Uninitialized);
        libewf_error_t *error = nullptr;
        const ssize_t bytesRead = libewf_handle_read_random(
            m_handle,
            data.data(),
            static_cast<size_t>(size),
            static_cast<off64_t>(offset),
            &error);

        if (bytesRead < 0 || quint64(bytesRead) != size) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("libewf read failed at offset %1 for %2. Requested %3 bytes, read %4 bytes. %5")
                    .arg(offset)
                    .arg(m_sourcePath)
                    .arg(size)
                    .arg(bytesRead)
                    .arg(takeLibewfError(&error));
            } else {
                takeLibewfError(&error);
            }
            return {};
        }

        return data;
    }

    QString backendName() const override
    {
        return QStringLiteral("libewf image reader");
    }

private:
    QString m_sourcePath;
    libewf_handle_t *m_handle = nullptr;
    char **m_filenames = nullptr;
    int m_numberOfFilenames = 0;
    quint64 m_mediaSize = 0;
};
}

std::unique_ptr<ImageReader> ImageReader::create(const QString &sourcePath)
{
    const QString suffix = QFileInfo(sourcePath).suffix().toLower();
    if (suffix == QStringLiteral("e01")) {
        return std::make_unique<EwfImageReader>(sourcePath);
    }
    return std::make_unique<RawImageReader>(sourcePath);
}
