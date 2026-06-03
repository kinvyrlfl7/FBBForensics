#pragma once

#include <QString>
#include <QStringList>

class RawDevice
{
public:
    static QString normalizePhysicalDrive(const QString &value);
    static QStringList listPhysicalDrives(QString *errorMessage = nullptr);
    static bool isUserAdmin();
};
