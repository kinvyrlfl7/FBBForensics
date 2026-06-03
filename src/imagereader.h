#pragma once

#include <QByteArray>
#include <QString>

#include <memory>

class ImageReader
{
public:
    virtual ~ImageReader() = default;

    virtual bool open(QString *errorMessage = nullptr) = 0;
    virtual void close() = 0;
    virtual bool isOpen() const = 0;
    virtual quint64 size() const = 0;
    virtual QByteArray read(quint64 offset, quint64 size, QString *errorMessage = nullptr) = 0;
    virtual QString backendName() const = 0;

    static std::unique_ptr<ImageReader> create(const QString &sourcePath);
};

