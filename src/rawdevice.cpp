#include "rawdevice.h"

#include <windows.h>
#include <winioctl.h>

namespace
{
quint64 queryDiskSize(const QString &path)
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
    return ok ? static_cast<quint64>(lengthInfo.Length.QuadPart) : 0;
}
}

QString RawDevice::normalizePhysicalDrive(const QString &value)
{
    if (value.startsWith(QStringLiteral(R"(\\.\)"))) {
        return value;
    }

    if (value.startsWith(QStringLiteral("PhysicalDrive"), Qt::CaseInsensitive)) {
        return QStringLiteral(R"(\\.\)") + value;
    }

    return QStringLiteral(R"(\\.\PhysicalDrive)") + value;
}

QStringList RawDevice::listPhysicalDrives(QString *errorMessage)
{
    QStringList drives;
    int accessDeniedCount = 0;

    for (int i = 0; i < 32; ++i) {
        const QString path = QStringLiteral(R"(\\.\PhysicalDrive%1)").arg(i);
        const quint64 size = queryDiskSize(path);
        if (size > 0) {
            drives << QStringLiteral("PhysicalDrive%1 (%2 bytes)").arg(i).arg(size);
            continue;
        }

        const DWORD lastError = GetLastError();
        if (lastError == ERROR_ACCESS_DENIED || lastError == ERROR_SHARING_VIOLATION) {
            ++accessDeniedCount;
        }
    }

    if (drives.isEmpty() && errorMessage) {
        if (accessDeniedCount > 0) {
            *errorMessage = QStringLiteral("Physical drives exist but could not be opened in read-only mode. Run the application as administrator.");
        } else {
            *errorMessage = QStringLiteral("No readable physical drives were detected.");
        }
    }

    return drives;
}

bool RawDevice::isUserAdmin()
{
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;
    BOOL isAdmin = FALSE;

    if (AllocateAndInitializeSid(&ntAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin == TRUE;
}
