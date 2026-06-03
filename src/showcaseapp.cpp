#include "showcaseapp.h"

#include "fbinstcarvingworker.h"
#include "imagereader.h"
#include "rawdevice.h"
#include "signaturecarver.h"
#include "showcaseanalyzer.h"

#include <QApplication>
#include <QComboBox>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QModelIndex>
#include <QProgressBar>
#include <QPushButton>
#include <QRadioButton>
#include <QSplitter>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QSqlTableModel>
#include <QTableView>
#include <QTextEdit>
#include <QThread>
#include <QTimer>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <memory>
#include <tsk/libtsk.h>

namespace
{
constexpr int TableNameRole = Qt::UserRole + 1;
constexpr int TableTitleRole = Qt::UserRole + 2;
constexpr int DbKeyRole = Qt::UserRole + 3;
constexpr quint64 CarvingChunkSectors = 8192;
constexpr qint64 CarvingScanWindowBytes = qint64(256) * 1024 * 1024;
constexpr qint64 CarvingScanOverlapBytes = qint64(16) * 1024 * 1024;

struct FbinstCarveRange
{
    QString areaType;
    quint64 startSector = 0;
    quint64 endSector = 0;
    QString signatureHint;
};

QString rangeName(const FbinstCarveRange &range)
{
    const QString suffix = range.signatureHint.isEmpty() ? QStringLiteral("range") : range.signatureHint;
    return QStringLiteral("%1_%2_%3_%4")
        .arg(range.areaType)
        .arg(range.startSector, 10, 10, QLatin1Char('0'))
        .arg(range.endSector, 10, 10, QLatin1Char('0'))
        .arg(suffix);
}

QString detectCarvingSignature(const QByteArray &data)
{
    auto startsWith = [&](const QByteArray &signature) {
        return data.size() >= signature.size() && data.startsWith(signature);
    };

    if (startsWith(QByteArray::fromHex("FFD8FF"))) return QStringLiteral("jpg");
    if (startsWith(QByteArray::fromHex("89504E470D0A1A0A"))) return QStringLiteral("png");
    if (startsWith(QByteArrayLiteral("GIF87a")) || startsWith(QByteArrayLiteral("GIF89a"))) return QStringLiteral("gif");
    if (startsWith(QByteArrayLiteral("BM"))) return QStringLiteral("bmp");
    if (startsWith(QByteArrayLiteral("II*\0")) || startsWith(QByteArrayLiteral("MM\0*"))) return QStringLiteral("tif");
    if (data.size() >= 128
        && static_cast<uchar>(data[0]) == 0x0A
        && static_cast<uchar>(data[1]) <= 0x05
        && static_cast<uchar>(data[2]) == 0x01) return QStringLiteral("pcx");
    if (startsWith(QByteArrayLiteral("%PDF"))) return QStringLiteral("pdf");
    if (startsWith(QByteArray::fromHex("504B0304"))) return QStringLiteral("zip");
    if (startsWith(QByteArray::fromHex("377ABCAF271C"))) return QStringLiteral("7z");
    if (startsWith(QByteArrayLiteral("Rar!\x1A\x07"))) return QStringLiteral("rar");
    if (startsWith(QByteArray::fromHex("1F8B08"))) return QStringLiteral("gz");
    if (startsWith(QByteArrayLiteral("BZh"))) return QStringLiteral("bz2");
    if (data.size() >= 262 && data.mid(257, 5) == QByteArrayLiteral("ustar")) return QStringLiteral("tar");
    if (startsWith(QByteArrayLiteral("MSWIM\0\0\0"))) return QStringLiteral("wim");
    if (data.size() >= 12 && data.startsWith(QByteArrayLiteral("RIFF")) && data.mid(8, 4) == QByteArrayLiteral("WAVE")) return QStringLiteral("wav");
    if (data.size() >= 12 && data.startsWith(QByteArrayLiteral("RIFF")) && data.mid(8, 4) == QByteArrayLiteral("AVI ")) return QStringLiteral("avi");
    if (startsWith(QByteArrayLiteral("FLV"))) return QStringLiteral("flv");
    if (startsWith(QByteArrayLiteral("ID3"))) return QStringLiteral("mp3");
    if (startsWith(QByteArray::fromHex("000001BA"))) return QStringLiteral("mpg");
    if (startsWith(QByteArray::fromHex("3026B2758E66CF11A6D900AA0062CE6C"))) return QStringLiteral("asf");
    if (data.size() >= 12 && data.mid(4, 4) == QByteArrayLiteral("ftyp")) return QStringLiteral("mp4");
    return {};
}

QString sha256ForFile(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);
    while (!file.atEnd()) {
        hash.addData(file.read(1024 * 1024));
    }
    return QString::fromLatin1(hash.result().toHex());
}

QString sanitizedFileName(QString name)
{
    name = name.trimmed();
    if (name.isEmpty()) {
        name = QStringLiteral("fbinst_file");
    }

    const QString invalid = QStringLiteral("<>:\"/\\|?*");
    for (const QChar ch : invalid) {
        name.replace(ch, QLatin1Char('_'));
    }
    while (name.endsWith(QLatin1Char('.')) || name.endsWith(QLatin1Char(' '))) {
        name.chop(1);
    }
    return name.isEmpty() ? QStringLiteral("fbinst_file") : name;
}

QString uniqueOutputPath(const QString &directory, const QString &fileName)
{
    QDir dir(directory);
    const QFileInfo info(sanitizedFileName(fileName));
    const QString completeSuffix = info.completeSuffix();
    const QString baseName = info.completeBaseName().isEmpty() ? info.baseName() : info.completeBaseName();
    const QString cleanBase = baseName.isEmpty() ? QStringLiteral("fbinst_file") : baseName;
    const QString suffixPart = completeSuffix.isEmpty() ? QString() : QStringLiteral(".%1").arg(completeSuffix);

    QString candidate = dir.filePath(cleanBase + suffixPart);
    int index = 1;
    while (QFileInfo::exists(candidate)) {
        candidate = dir.filePath(QStringLiteral("%1_%2%3").arg(cleanBase).arg(index++, 3, 10, QLatin1Char('0')).arg(suffixPart));
    }
    return candidate;
}

bool extractFbinstRecordToFile(const QSqlRecord &record, ImageReader &reader, const QString &outputPath, QString *errorMessage)
{
    const QString areaType = record.value(QStringLiteral("Type_Of_DataArea")).toString();
    const quint64 fileStart = record.value(QStringLiteral("File_Start")).toULongLong();
    const quint64 fileSize = record.value(QStringLiteral("File_Size")).toULongLong();
    const quint64 physicalStartSector = fileStart;

    QFile output(outputPath);
    if (!output.open(QIODevice::WriteOnly)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to create output file: %1").arg(output.errorString());
        }
        return false;
    }

    auto fail = [&](const QString &message) -> bool {
        output.close();
        output.remove();
        if (errorMessage) {
            *errorMessage = message;
        }
        return false;
    };

    if (areaType == QStringLiteral("Primary")) {
        if (fileSize <= 510) {
            QString readError;
            const QByteArray data = reader.read(physicalStartSector * ShowcaseAnalyzer::SectorSize, fileSize, &readError);
            if (quint64(data.size()) != fileSize) {
                return fail(readError.isEmpty() ? QStringLiteral("Failed to read Primary-area file data.") : readError);
            }
            if (output.write(data) != data.size()) {
                return fail(QStringLiteral("Failed to write Primary-area file data."));
            }
        } else {
            quint64 remaining = fileSize;
            quint64 sector = physicalStartSector;
            while (remaining > 0) {
                QString readError;
                const QByteArray sectorData = reader.read(sector * ShowcaseAnalyzer::SectorSize, ShowcaseAnalyzer::SectorSize, &readError);
                if (sectorData.size() != static_cast<int>(ShowcaseAnalyzer::SectorSize)) {
                    return fail(readError.isEmpty() ? QStringLiteral("Failed to read Primary-area sector data.") : readError);
                }
                const qint64 chunkSize = static_cast<qint64>(qMin<quint64>(510, remaining));
                if (output.write(sectorData.constData(), chunkSize) != chunkSize) {
                    return fail(QStringLiteral("Failed to write reconstructed Primary-area data."));
                }
                remaining -= static_cast<quint64>(chunkSize);
                ++sector;
            }
        }
    } else {
        quint64 remaining = fileSize;
        quint64 offset = physicalStartSector * ShowcaseAnalyzer::SectorSize;
        constexpr quint64 bufferSize = 1024 * 1024;
        while (remaining > 0) {
            QString readError;
            const quint64 bytesToRead = qMin<quint64>(bufferSize, remaining);
            const QByteArray chunk = reader.read(offset, bytesToRead, &readError);
            if (quint64(chunk.size()) != bytesToRead) {
                return fail(readError.isEmpty() ? QStringLiteral("Failed to read Extended-area file data.") : readError);
            }
            if (output.write(chunk) != chunk.size()) {
                return fail(QStringLiteral("Failed to write Extended-area file data."));
            }
            remaining -= quint64(chunk.size());
            offset += quint64(chunk.size());
        }
    }

    output.close();
    return true;
}

}

ShowcaseApp::ShowcaseApp()
    : m_partitionDb(new QSqlDatabase())
    , m_booticeDb(new QSqlDatabase())
    , m_fbinstDb(new QSqlDatabase())
    , m_partitionConnectionName(QStringLiteral("showcase-partition"))
    , m_booticeConnectionName(QStringLiteral("showcase-bootice"))
    , m_fbinstConnectionName(QStringLiteral("showcase-fbinst"))
{
    setWindowTitle(QStringLiteral("ShowcaseQt Forensics Workbench"));
    resize(1240, 780);

    auto *central = new QWidget(this);
    auto *mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(12, 12, 12, 12);
    mainLayout->setSpacing(10);

    auto *inputGroup = new QGroupBox(QStringLiteral("Evidence Source"), central);
    auto *inputLayout = new QGridLayout(inputGroup);

    m_imageMode = new QRadioButton(QStringLiteral("Disk image"), inputGroup);
    m_physicalMode = new QRadioButton(QStringLiteral("Physical drive"), inputGroup);
    m_imageMode->setChecked(true);

    m_imagePathEdit = new QLineEdit(inputGroup);
    m_imagePathEdit->setPlaceholderText(QStringLiteral("Select .001, .img, .dd, .E01, or raw image file"));
    m_imageBrowseButton = new QPushButton(QStringLiteral("Browse..."), inputGroup);

    m_physicalDriveCombo = new QComboBox(inputGroup);
    m_physicalDriveCombo->setEditable(false);
    m_detectDriveButton = new QPushButton(QStringLiteral("Detect"), inputGroup);

    m_outputDirEdit = new QLineEdit(QDir::currentPath(), inputGroup);
    auto *outputBrowseButton = new QPushButton(QStringLiteral("Output..."), inputGroup);

    m_runButton = new QPushButton(QStringLiteral("Acquire Metadata"), inputGroup);

    inputLayout->addWidget(m_imageMode, 0, 0);
    inputLayout->addWidget(m_physicalMode, 0, 1);
    inputLayout->addWidget(new QLabel(QStringLiteral("Image path"), inputGroup), 1, 0);
    inputLayout->addWidget(m_imagePathEdit, 1, 1);
    inputLayout->addWidget(m_imageBrowseButton, 1, 2);
    inputLayout->addWidget(new QLabel(QStringLiteral("Physical drive"), inputGroup), 2, 0);
    inputLayout->addWidget(m_physicalDriveCombo, 2, 1);
    inputLayout->addWidget(m_detectDriveButton, 2, 2);
    inputLayout->addWidget(new QLabel(QStringLiteral("Output folder"), inputGroup), 3, 0);
    inputLayout->addWidget(m_outputDirEdit, 3, 1);
    inputLayout->addWidget(outputBrowseButton, 3, 2);
    inputLayout->addWidget(m_runButton, 4, 2);

    auto *summaryGroup = new QGroupBox(QStringLiteral("Case Summary"), central);
    auto *summaryLayout = new QGridLayout(summaryGroup);
    m_statusLabel = new QLabel(QStringLiteral("Idle"), summaryGroup);
    m_sourceLabel = new QLabel(QStringLiteral("No evidence loaded"), summaryGroup);
    summaryLayout->addWidget(new QLabel(QStringLiteral("Status"), summaryGroup), 0, 0);
    summaryLayout->addWidget(m_statusLabel, 0, 1);
    summaryLayout->addWidget(new QLabel(QStringLiteral("Current source"), summaryGroup), 1, 0);
    summaryLayout->addWidget(m_sourceLabel, 1, 1);

    auto *horizontalSplitter = new QSplitter(Qt::Horizontal, central);
    auto *rightPane = new QWidget(horizontalSplitter);
    auto *rightLayout = new QVBoxLayout(rightPane);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->setSpacing(8);

    auto *rightSplitter = new QSplitter(Qt::Vertical, rightPane);
    m_navigationTree = new QTreeWidget(horizontalSplitter);
    m_navigationTree->setHeaderLabel(QStringLiteral("Evidence Navigator"));

    auto *resultHeader = new QWidget(rightPane);
    auto *resultHeaderLayout = new QHBoxLayout(resultHeader);
    resultHeaderLayout->setContentsMargins(0, 0, 0, 0);
    m_viewTitleLabel = new QLabel(QStringLiteral("Result Grid"), resultHeader);
    m_filterEdit = new QLineEdit(resultHeader);
    m_filterEdit->setPlaceholderText(QStringLiteral("Quick filter current result view"));
    m_extractButton = new QPushButton(QStringLiteral("Extract Selected File"), resultHeader);
    m_extractButton->setEnabled(false);
    m_carveButton = new QPushButton(QStringLiteral("Carve Remaining Sectors"), resultHeader);
    m_carveButton->setEnabled(false);
    resultHeaderLayout->addWidget(m_viewTitleLabel);
    resultHeaderLayout->addStretch(1);
    resultHeaderLayout->addWidget(new QLabel(QStringLiteral("Filter"), resultHeader));
    resultHeaderLayout->addWidget(m_filterEdit);
    resultHeaderLayout->addWidget(m_extractButton);
    resultHeaderLayout->addWidget(m_carveButton);

    m_resultTable = new QTableView(rightSplitter);
    m_resultTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_resultTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_resultTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_resultTable->setAlternatingRowColors(true);
    m_resultTable->horizontalHeader()->setStretchLastSection(true);
    m_resultTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    m_detailView = new QTextEdit(rightSplitter);
    m_detailView->setReadOnly(true);
    m_detailView->setPlaceholderText(QStringLiteral("Record properties and analysis notes appear here."));

    horizontalSplitter->addWidget(m_navigationTree);
    rightSplitter->addWidget(m_resultTable);
    rightSplitter->addWidget(m_detailView);
    rightLayout->addWidget(resultHeader);
    rightLayout->addWidget(rightSplitter, 1);
    horizontalSplitter->addWidget(rightPane);
    horizontalSplitter->setStretchFactor(0, 0);
    horizontalSplitter->setStretchFactor(1, 1);
    horizontalSplitter->setSizes({300, 860});
    rightSplitter->setSizes({440, 220});

    m_logView = new QTextEdit(central);
    m_logView->setReadOnly(true);
    m_logView->setMaximumHeight(160);
    m_logView->setPlaceholderText(QStringLiteral("Acquisition and parsing log."));

    auto *progressWidget = new QWidget(central);
    auto *progressLayout = new QHBoxLayout(progressWidget);
    progressLayout->setContentsMargins(0, 0, 0, 0);
    m_progressLabel = new QLabel(QStringLiteral("Idle"), progressWidget);
    m_progressBar = new QProgressBar(progressWidget);
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    progressLayout->addWidget(m_progressLabel);
    progressLayout->addWidget(m_progressBar, 1);

    mainLayout->addWidget(inputGroup);
    mainLayout->addWidget(summaryGroup);
    mainLayout->addWidget(horizontalSplitter, 1);
    mainLayout->addWidget(m_logView);
    mainLayout->addWidget(progressWidget);
    setCentralWidget(central);

    connect(m_imageBrowseButton, &QPushButton::clicked, this, [this] { browseImage(); });
    connect(m_detectDriveButton, &QPushButton::clicked, this, [this] { detectPhysicalDrives(); });
    connect(outputBrowseButton, &QPushButton::clicked, this, [this] { browseOutputDirectory(); });
    connect(m_imageMode, &QRadioButton::toggled, this, [this] { updateInputMode(); });
    connect(m_runButton, &QPushButton::clicked, this, [this] { runAnalysis(); });
    connect(m_extractButton, &QPushButton::clicked, this, [this] { extractSelectedCurrentFile(); });
    connect(m_carveButton, &QPushButton::clicked, this, [this] { carveFbinstRemainingSectors(); });
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this] { applyFilter(); });
    connect(m_resultTable, &QTableView::doubleClicked, this, [this](const QModelIndex &index) { handleResultTableActivated(index); });
    connect(m_navigationTree, &QTreeWidget::itemSelectionChanged, this, [this] {
        const QList<QTreeWidgetItem *> items = m_navigationTree->selectedItems();
        if (items.isEmpty()) {
            return;
        }
        const QTreeWidgetItem *item = items.first();
        const QString dbKey = item->data(0, DbKeyRole).toString();
        const QString tableName = item->data(0, TableNameRole).toString();
        const QString tableTitle = item->data(0, TableTitleRole).toString();
        if (!dbKey.isEmpty() && !tableName.isEmpty()) {
            showTable(dbKey, tableName, tableTitle);
        }
    });

    m_logFlushTimer = new QTimer(this);
    m_logFlushTimer->setInterval(150);
    connect(m_logFlushTimer, &QTimer::timeout, this, [this] { flushPendingLogs(); });

    updateInputMode();
    appendLog(QStringLiteral("Ready. Results will be split across partition.db, bootice.db, and fbinsttool.db."));
    appendLog(QStringLiteral("Administrator privileges: %1").arg(RawDevice::isUserAdmin() ? QStringLiteral("Yes") : QStringLiteral("No")));
    updateProgress(0, QStringLiteral("Idle"));
    detectPhysicalDrives();
}

ShowcaseApp::~ShowcaseApp()
{
    if (m_carvingThread) {
        if (m_carvingCancel) {
            m_carvingCancel->store(true);
        }
        m_carvingThread->disconnect();
        m_carvingThread->quit();
        m_carvingThread->wait();
        delete m_carvingThread;
        m_carvingThread = nullptr;
    }
    flushPendingLogs();
    closeDatabases();
    delete m_tableModel;
    delete m_partitionDb;
    delete m_booticeDb;
    delete m_fbinstDb;
}

QSqlDatabase *ShowcaseApp::databaseForKey(const QString &dbKey) const
{
    if (dbKey == QStringLiteral("partition")) {
        return m_partitionDb;
    }
    if (dbKey == QStringLiteral("bootice")) {
        return m_booticeDb;
    }
    if (dbKey == QStringLiteral("fbinst")) {
        return m_fbinstDb;
    }
    return nullptr;
}

void ShowcaseApp::browseImage()
{
    const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("Select image file"), QDir::currentPath(), QStringLiteral("Disk Images (*.001 *.img *.dd *.E01);;All Files (*.*)"));
    if (!path.isEmpty()) {
        m_imagePathEdit->setText(path);
    }
}

void ShowcaseApp::browseOutputDirectory()
{
    const QString path = QFileDialog::getExistingDirectory(this, QStringLiteral("Select output folder"), m_outputDirEdit->text().isEmpty() ? QDir::currentPath() : m_outputDirEdit->text());
    if (!path.isEmpty()) {
        m_outputDirEdit->setText(path);
    }
}

void ShowcaseApp::detectPhysicalDrives()
{
    QString errorMessage;
    const QStringList drives = RawDevice::listPhysicalDrives(&errorMessage);
    if (drives.isEmpty()) {
        const QString message = errorMessage.isEmpty()
            ? QStringLiteral("No accessible physical drives were detected.")
            : errorMessage;
        appendLog(message);
        m_statusLabel->setText(QStringLiteral("Physical drive detection failed"));
        QMessageBox::warning(this, QStringLiteral("Detect physical drives"), message);
        return;
    }

    appendLog(QStringLiteral("Detected physical drives (read-only):"));
    m_physicalDriveCombo->clear();
    for (const QString &drive : drives) {
        appendLog(QStringLiteral("  %1").arg(drive));
        QString physicalName = drive;
        const int spaceIndex = physicalName.indexOf(' ');
        if (spaceIndex > 0) {
            physicalName = physicalName.left(spaceIndex);
        }
        m_physicalDriveCombo->addItem(drive, physicalName);
    }

    const QString first = m_physicalDriveCombo->currentData().toString();
    m_statusLabel->setText(QStringLiteral("Detected %1 physical drive(s)").arg(drives.size()));
    m_sourceLabel->setText(QStringLiteral("Read-only device access enabled"));
    QMessageBox::information(this, QStringLiteral("Detect physical drives"), QStringLiteral("Detected %1 physical drive(s). Selected %2 for read-only analysis.").arg(drives.size()).arg(first));
}

void ShowcaseApp::updateInputMode()
{
    const bool imageMode = m_imageMode->isChecked();
    m_imagePathEdit->setEnabled(imageMode);
    m_imageBrowseButton->setEnabled(imageMode);
    m_physicalDriveCombo->setEnabled(!imageMode);
    m_detectDriveButton->setEnabled(!imageMode);
}

void ShowcaseApp::appendLog(const QString &message)
{
    m_logView->append(message);
}

void ShowcaseApp::enqueueLog(const QString &message)
{
    m_pendingLogs.append(message);
    if (m_logFlushTimer && !m_logFlushTimer->isActive()) {
        m_logFlushTimer->start();
    }
}

void ShowcaseApp::flushPendingLogs()
{
    if (m_pendingLogs.isEmpty() || !m_logView) {
        if (m_logFlushTimer) {
            m_logFlushTimer->stop();
        }
        return;
    }

    m_logView->append(m_pendingLogs.join(QLatin1Char('\n')));
    m_pendingLogs.clear();
    if (m_logFlushTimer) {
        m_logFlushTimer->stop();
    }
}

void ShowcaseApp::updateProgress(int value, const QString &message)
{
    if (m_progressBar) {
        m_progressBar->setValue(qBound(0, value, 100));
    }
    if (m_progressLabel) {
        m_progressLabel->setText(message);
    }
    QApplication::processEvents();
}

void ShowcaseApp::closeDatabases()
{
    if (m_tableModel) {
        m_resultTable->setModel(nullptr);
        delete m_tableModel;
        m_tableModel = nullptr;
    }

    auto closeOne = [](QSqlDatabase *db, const QString &name) {
        if (db && db->isValid()) {
            if (db->isOpen()) {
                db->close();
            }
            *db = QSqlDatabase();
        }
        if (QSqlDatabase::contains(name)) {
            QSqlDatabase::removeDatabase(name);
        }
    };

    closeOne(m_partitionDb, m_partitionConnectionName);
    closeOne(m_booticeDb, m_booticeConnectionName);
    closeOne(m_fbinstDb, m_fbinstConnectionName);
    m_currentDbKey.clear();
    m_currentTableName.clear();
}

void ShowcaseApp::rebuildNavigation()
{
    m_navigationTree->clear();

    const struct DbSpec {
        QString key;
        QString label;
        QSqlDatabase *db;
        QList<QPair<QString, QString>> tables;
    } specs[] = {
        {QStringLiteral("partition"), QStringLiteral("partition.db"), m_partitionDb, {{QStringLiteral("AnalysisSummary"), QStringLiteral("Analysis Summary")}, {QStringLiteral("Partitions"), QStringLiteral("Partition Map")}}},
        {QStringLiteral("bootice"), QStringLiteral("bootice.db"), m_booticeDb, {{QStringLiteral("Bootice"), QStringLiteral("Bootice Metadata")}, {QStringLiteral("Bootice_Signatures"), QStringLiteral("Bootice Signatures")}, {QStringLiteral("Bootice_List"), QStringLiteral("Bootice Root Listing")}}},
        {QStringLiteral("fbinst"), QStringLiteral("fbinsttool.db"), m_fbinstDb, {{QStringLiteral("Fbinst"), QStringLiteral("Fbinst Metadata")}, {QStringLiteral("Fbinst_List"), QStringLiteral("Fbinst File List")}, {QStringLiteral("Fbinst_Sectors"), QStringLiteral("Fbinst Covered Sectors")}, {QStringLiteral("Fbinst_Remaining_Sectors"), QStringLiteral("Fbinst Remaining Sectors")}, {QStringLiteral("Fbinst_Carving_Candidates"), QStringLiteral("Fbinst Carving Candidates")}, {QStringLiteral("Fbinst_Carved_Files"), QStringLiteral("Fbinst Carved Files")}}}
    };

    QTreeWidgetItem *firstLeaf = nullptr;
    for (const DbSpec &spec : specs) {
        if (!spec.db || !spec.db->isOpen()) {
            continue;
        }
        auto *root = new QTreeWidgetItem(m_navigationTree, QStringList{spec.label});
        root->setExpanded(true);
        const QStringList available = spec.db->tables();
        for (const auto &pair : spec.tables) {
            if (!available.contains(pair.first)) {
                continue;
            }
            auto *item = new QTreeWidgetItem(root, QStringList{pair.second});
            item->setData(0, DbKeyRole, spec.key);
            item->setData(0, TableNameRole, pair.first);
            item->setData(0, TableTitleRole, pair.second);
            if (!firstLeaf) {
                firstLeaf = item;
            }
        }
    }

    if (firstLeaf) {
        m_navigationTree->setCurrentItem(firstLeaf);
        showTable(firstLeaf->data(0, DbKeyRole).toString(), firstLeaf->data(0, TableNameRole).toString(), firstLeaf->data(0, TableTitleRole).toString());
    }
}

void ShowcaseApp::showTable(const QString &dbKey, const QString &tableName, const QString &title)
{
    QSqlDatabase *database = databaseForKey(dbKey);
    if (!database || !database->isOpen()) {
        return;
    }

    if (!m_tableModel || m_currentDbKey != dbKey) {
        if (m_tableModel) {
            m_resultTable->setModel(nullptr);
            delete m_tableModel;
            m_tableModel = nullptr;
        }
        m_tableModel = new QSqlTableModel(this, *database);
        m_resultTable->setModel(m_tableModel);
        connect(m_resultTable->selectionModel(), &QItemSelectionModel::selectionChanged, this, [this] { updateRecordDetails(); });
        m_currentDbKey = dbKey;
    }

    m_currentTableName = tableName;
    m_filterEdit->clear();
    m_tableModel->setFilter(QString());
    m_tableModel->setTable(tableName);
    if (dbKey == QStringLiteral("partition") && tableName == QStringLiteral("Partitions")) {
        m_tableModel->setHeaderData(m_tableModel->fieldIndex(QStringLiteral("Partition_Size")), Qt::Horizontal, QStringLiteral("Partition Size (Bytes)"));
        m_tableModel->setHeaderData(m_tableModel->fieldIndex(QStringLiteral("Partition_Size_MB_GB")), Qt::Horizontal, QStringLiteral("Partition Size (MB / GB)"));
    }
    m_tableModel->select();
    m_resultTable->resizeColumnsToContents();
    m_viewTitleLabel->setText(title);
    if (tableName == QStringLiteral("Bootice_List") || tableName == QStringLiteral("Fbinst_List")) {
        m_detailView->setPlainText(QStringLiteral("%1 loaded. Select a file row and click 'Extract Selected File' or double-click the row to export it.").arg(title));
    } else if (tableName == QStringLiteral("Fbinst_Remaining_Sectors")) {
        m_detailView->setPlainText(QStringLiteral("%1 loaded. Click 'Carve Remaining Sectors' to run the internal signature carver against Primary and Extended remaining-sector streams.").arg(title));
    } else {
        m_detailView->setPlainText(QStringLiteral("%1 loaded. Select a row to inspect its properties.").arg(title));
    }
    m_extractButton->setEnabled(canExtractCurrentRecord());
    m_carveButton->setEnabled(m_currentDbKey == QStringLiteral("fbinst") && m_currentTableName == QStringLiteral("Fbinst_Remaining_Sectors"));
    m_statusLabel->setText(QStringLiteral("Loaded %1 rows from %2").arg(m_tableModel->rowCount()).arg(title));
}

bool ShowcaseApp::canExtractCurrentBooticeRecord() const
{
    if (m_currentDbKey != QStringLiteral("bootice") || m_currentTableName != QStringLiteral("Bootice_List") || !m_tableModel || !m_resultTable->selectionModel()) {
        return false;
    }

    const QModelIndexList rows = m_resultTable->selectionModel()->selectedRows();
    if (rows.isEmpty()) {
        return false;
    }

    const QSqlRecord record = m_tableModel->record(rows.first().row());
    return record.value(QStringLiteral("Type")).toString() == QStringLiteral("FILE");
}

bool ShowcaseApp::canExtractCurrentFbinstRecord() const
{
    if (m_currentDbKey != QStringLiteral("fbinst") || m_currentTableName != QStringLiteral("Fbinst_List") || !m_tableModel || !m_resultTable->selectionModel()) {
        return false;
    }

    const QModelIndexList rows = m_resultTable->selectionModel()->selectedRows();
    if (rows.isEmpty()) {
        return false;
    }

    for (const QModelIndex &row : rows) {
        const QSqlRecord record = m_tableModel->record(row.row());
        if (!record.value(QStringLiteral("File_Names")).toString().trimmed().isEmpty()
            && record.value(QStringLiteral("File_Size")).toULongLong() > 0) {
            return true;
        }
    }
    return false;
}

bool ShowcaseApp::canExtractCurrentRecord() const
{
    return canExtractCurrentBooticeRecord() || canExtractCurrentFbinstRecord();
}

void ShowcaseApp::updateRecordDetails()
{
    if (!m_tableModel || !m_resultTable->selectionModel()) {
        m_extractButton->setEnabled(false);
        m_carveButton->setEnabled(false);
        return;
    }
    const QModelIndexList rows = m_resultTable->selectionModel()->selectedRows();
    if (rows.isEmpty()) {
        m_extractButton->setEnabled(false);
        m_carveButton->setEnabled(m_currentDbKey == QStringLiteral("fbinst") && m_currentTableName == QStringLiteral("Fbinst_Remaining_Sectors"));
        return;
    }
    const QSqlRecord record = m_tableModel->record(rows.first().row());
    QStringList lines{QStringLiteral("Record Details"), QStringLiteral("")};
    for (int i = 0; i < record.count(); ++i) {
        lines << QStringLiteral("%1: %2").arg(record.fieldName(i), record.value(i).toString());
    }
    if (m_currentDbKey == QStringLiteral("bootice") && m_currentTableName == QStringLiteral("Bootice_List")) {
        if (record.value(QStringLiteral("Type")).toString() == QStringLiteral("FILE")) {
            lines << QString();
            lines << QStringLiteral("Action: Click 'Extract Selected File' or double-click this row to export the file from the Bootice filesystem.");
        } else {
            lines << QString();
            lines << QStringLiteral("Action: Direct extraction is available for file entries only.");
        }
    }
    if (m_currentDbKey == QStringLiteral("fbinst") && m_currentTableName == QStringLiteral("Fbinst_List")) {
        lines << QString();
        lines << QStringLiteral("Action: Select one or more rows, then click 'Extract Selected File' to export Fbinst files from their recorded data areas.");
    }
    if (m_currentDbKey == QStringLiteral("fbinst") && m_currentTableName == QStringLiteral("Fbinst_Remaining_Sectors")) {
        lines << QString();
        lines << QStringLiteral("Action: Click 'Carve Remaining Sectors' to carve all remaining Primary and Extended ranges with the internal signature carver.");
    }
    m_detailView->setPlainText(lines.join('\n'));
    m_extractButton->setEnabled(canExtractCurrentRecord());
    m_carveButton->setEnabled(m_currentDbKey == QStringLiteral("fbinst") && m_currentTableName == QStringLiteral("Fbinst_Remaining_Sectors"));
}

void ShowcaseApp::handleResultTableActivated(const QModelIndex &index)
{
    if (!index.isValid()) {
        return;
    }
    if (canExtractCurrentRecord()) {
        extractSelectedCurrentFile();
    }
}

void ShowcaseApp::extractSelectedCurrentFile()
{
    if (canExtractCurrentBooticeRecord()) {
        extractSelectedBooticeFile();
        return;
    }
    if (canExtractCurrentFbinstRecord()) {
        extractSelectedFbinstFile();
        return;
    }

    QMessageBox::information(this, QStringLiteral("Extraction unavailable"), QStringLiteral("Select an extractable file row first."));
}
void ShowcaseApp::extractSelectedBooticeFile()
{
    if (!canExtractCurrentBooticeRecord()) {
        QMessageBox::information(this, QStringLiteral("Extraction unavailable"), QStringLiteral("Select a file row in Bootice Root Listing first."));
        return;
    }

    const QModelIndexList rows = m_resultTable->selectionModel()->selectedRows();
    const QSqlRecord record = m_tableModel->record(rows.first().row());
    const QString entryName = record.value(QStringLiteral("Name")).toString();
    const QString entryType = record.value(QStringLiteral("Type")).toString();
    if (entryType != QStringLiteral("FILE")) {
        QMessageBox::information(this, QStringLiteral("Extraction unavailable"), QStringLiteral("Only file entries can be extracted."));
        return;
    }

    QSqlQuery query(*m_booticeDb);
    if (!query.exec(QStringLiteral("SELECT Start_LBA_Address FROM Bootice LIMIT 1")) || !query.next()) {
        QMessageBox::critical(this, QStringLiteral("Extraction failed"), QStringLiteral("Bootice partition metadata is missing."));
        return;
    }
    const quint64 startLba = query.value(0).toULongLong();

    const QString defaultPath = QDir(m_outputDirEdit->text().trimmed()).filePath(entryName);
    const QString outputPath = QFileDialog::getSaveFileName(this, QStringLiteral("Save extracted file"), defaultPath, QStringLiteral("All Files (*.*)"));
    if (outputPath.isEmpty()) {
        return;
    }

    TSK_IMG_INFO *image = tsk_img_open_utf8_sing(m_currentSourcePath.toUtf8().constData(), TSK_IMG_TYPE_DETECT, 0);
    if (!image) {
        QMessageBox::critical(this, QStringLiteral("Extraction failed"), QStringLiteral("libtsk could not reopen the source image."));
        return;
    }

    TSK_FS_INFO *filesystem = tsk_fs_open_img(image, startLba * ShowcaseAnalyzer::SectorSize, TSK_FS_TYPE_DETECT);
    if (!filesystem) {
        tsk_img_close(image);
        QMessageBox::critical(this, QStringLiteral("Extraction failed"), QStringLiteral("libtsk could not open the Bootice filesystem."));
        return;
    }

    const QByteArray filePath = QByteArrayLiteral("/") + entryName.toUtf8();
    TSK_FS_FILE *tskFile = tsk_fs_file_open(filesystem, nullptr, filePath.constData());
    if (!tskFile || !tskFile->meta) {
        if (tskFile) {
            tsk_fs_file_close(tskFile);
        }
        tsk_fs_close(filesystem);
        tsk_img_close(image);
        QMessageBox::critical(this, QStringLiteral("Extraction failed"), QStringLiteral("libtsk could not open the selected file inside the Bootice filesystem."));
        return;
    }

    QFile output(outputPath);
    if (!output.open(QIODevice::WriteOnly)) {
        tsk_fs_file_close(tskFile);
        tsk_fs_close(filesystem);
        tsk_img_close(image);
        QMessageBox::critical(this, QStringLiteral("Extraction failed"), QStringLiteral("Unable to create output file: %1").arg(output.errorString()));
        return;
    }

    constexpr size_t bufferSize = 1024 * 1024;
    QByteArray buffer(static_cast<int>(bufferSize), Qt::Uninitialized);
    quint64 offset = 0;
    const quint64 fileSize = quint64(tskFile->meta->size);
    bool ok = true;
    QString errorMessage;

    while (offset < fileSize) {
        const size_t bytesToRead = static_cast<size_t>(qMin<quint64>(bufferSize, fileSize - offset));
        const auto bytesRead = tsk_fs_file_read(tskFile, static_cast<TSK_OFF_T>(offset), buffer.data(), bytesToRead, TSK_FS_FILE_READ_FLAG_NONE);
        if (bytesRead <= 0) {
            ok = false;
            errorMessage = QStringLiteral("libtsk failed while reading the selected file.");
            break;
        }
        if (output.write(buffer.constData(), bytesRead) != bytesRead) {
            ok = false;
            errorMessage = QStringLiteral("Failed to write the extracted file to disk.");
            break;
        }
        offset += static_cast<quint64>(bytesRead);
    }

    output.close();
    tsk_fs_file_close(tskFile);
    tsk_fs_close(filesystem);
    tsk_img_close(image);

    if (!ok) {
        output.remove();
        QMessageBox::critical(this, QStringLiteral("Extraction failed"), errorMessage);
        appendLog(QStringLiteral("Bootice extraction failed for %1: %2").arg(entryName, errorMessage));
        return;
    }

    appendLog(QStringLiteral("Extracted Bootice file: %1 -> %2").arg(entryName, QFileInfo(outputPath).absoluteFilePath()));
    QMessageBox::information(this, QStringLiteral("Extraction complete"), QStringLiteral("File extracted to %1").arg(QFileInfo(outputPath).absoluteFilePath()));
}

void ShowcaseApp::extractSelectedFbinstFile()
{
    if (!canExtractCurrentFbinstRecord()) {
        QMessageBox::information(this, QStringLiteral("Extraction unavailable"), QStringLiteral("Select a file row in Fbinst File List first."));
        return;
    }

    const QModelIndexList rows = m_resultTable->selectionModel()->selectedRows();
    QList<QSqlRecord> records;
    for (const QModelIndex &row : rows) {
        const QSqlRecord record = m_tableModel->record(row.row());
        if (record.value(QStringLiteral("File_Names")).toString().trimmed().isEmpty()
            || record.value(QStringLiteral("File_Size")).toULongLong() == 0) {
            continue;
        }
        records.append(record);
    }
    if (records.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("Extraction unavailable"), QStringLiteral("Selected rows do not contain extractable Fbinst files."));
        return;
    }

    QString singleOutputPath;
    QString outputDirectory;
    if (records.size() == 1) {
        const QString entryName = records.first().value(QStringLiteral("File_Names")).toString();
        const QString defaultPath = QDir(m_outputDirEdit->text().trimmed()).filePath(sanitizedFileName(entryName));
        singleOutputPath = QFileDialog::getSaveFileName(this, QStringLiteral("Save extracted file"), defaultPath, QStringLiteral("All Files (*.*)"));
        if (singleOutputPath.isEmpty()) {
            return;
        }
    } else {
        outputDirectory = QFileDialog::getExistingDirectory(this, QStringLiteral("Select folder for extracted Fbinst files"), m_outputDirEdit->text().trimmed());
        if (outputDirectory.isEmpty()) {
            return;
        }
    }

    std::unique_ptr<ImageReader> reader = ImageReader::create(m_currentSourcePath);
    QString readerError;
    if (!reader || !reader->open(&readerError)) {
        QMessageBox::critical(this, QStringLiteral("Extraction failed"), QStringLiteral("Unable to reopen the source image: %1").arg(readerError));
        return;
    }

    QApplication::setOverrideCursor(Qt::WaitCursor);
    int successCount = 0;
    int failureCount = 0;
    QStringList failureLines;

    for (int index = 0; index < records.size(); ++index) {
        const QSqlRecord record = records[index];
        const QString entryName = record.value(QStringLiteral("File_Names")).toString();
        const QString outputPath = records.size() == 1
            ? singleOutputPath
            : uniqueOutputPath(outputDirectory, entryName);
        QString errorMessage;

        updateProgress(records.size() == 1 ? 0 : (index * 100 / records.size()), QStringLiteral("Extracting Fbinst file %1 of %2...").arg(index + 1).arg(records.size()));
        QApplication::processEvents();

        if (extractFbinstRecordToFile(record, *reader, outputPath, &errorMessage)) {
            ++successCount;
            appendLog(QStringLiteral("Extracted Fbinst file: %1 -> %2").arg(entryName, QFileInfo(outputPath).absoluteFilePath()));
        } else {
            ++failureCount;
            failureLines << QStringLiteral("%1: %2").arg(entryName, errorMessage);
            appendLog(QStringLiteral("Fbinst extraction failed for %1: %2").arg(entryName, errorMessage));
        }
    }

    reader->close();
    QApplication::restoreOverrideCursor();
    updateProgress(100, QStringLiteral("Fbinst extraction complete"));

    const QString summary = QStringLiteral("Fbinst extraction complete. Success: %1, Failed: %2.").arg(successCount).arg(failureCount);
    appendLog(summary);
    if (failureCount > 0) {
        QMessageBox::warning(this, QStringLiteral("Extraction complete with failures"), summary + QStringLiteral("\n\n") + failureLines.join('\n'));
    } else if (records.size() == 1) {
        QMessageBox::information(this, QStringLiteral("Extraction complete"), QStringLiteral("File extracted to %1").arg(QFileInfo(singleOutputPath).absoluteFilePath()));
    } else {
        QMessageBox::information(this, QStringLiteral("Extraction complete"), summary);
    }
}

void ShowcaseApp::carveFbinstRemainingSectors()
{
    if (!m_fbinstDb || !m_fbinstDb->isOpen()) {
        QMessageBox::warning(this, QStringLiteral("Carving unavailable"), QStringLiteral("Open an analyzed fbinsttool.db first."));
        return;
    }
    if (m_currentSourcePath.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Carving unavailable"), QStringLiteral("No evidence source is currently loaded."));
        return;
    }
    if (m_carvingThread) {
        if (m_carvingCancel) {
            m_carvingCancel->store(true);
        }
        m_carveButton->setEnabled(false);
        m_carveButton->setText(QStringLiteral("Cancelling..."));
        appendLog(QStringLiteral("Cancellation requested for Fbinst carving worker."));
        updateProgress(m_progressBar ? m_progressBar->value() : 0, QStringLiteral("Cancelling Fbinst carving..."));
        return;
    }

    const QString fbinstDbPath = m_fbinstDb->databaseName();
    const QString outputPath = m_outputDirEdit->text().trimmed();
    if (fbinstDbPath.isEmpty() || outputPath.isEmpty() || !QDir(outputPath).exists()) {
        QMessageBox::warning(this, QStringLiteral("Carving unavailable"), QStringLiteral("A valid fbinsttool.db and output folder are required."));
        return;
    }

    if (m_tableModel && m_currentDbKey == QStringLiteral("fbinst")) {
        m_resultTable->setModel(nullptr);
        delete m_tableModel;
        m_tableModel = nullptr;
    }
    if (m_fbinstDb->isOpen()) {
        m_fbinstDb->close();
    }

    FbinstCarvingWorker::Params params;
    params.sourcePath = m_currentSourcePath;
    params.fbinstDbPath = fbinstDbPath;
    params.outputDir = outputPath;
    m_carvingCancel = std::make_shared<std::atomic_bool>(false);
    params.cancelRequested = m_carvingCancel;

    m_carveButton->setText(QStringLiteral("Cancel Carving"));
    m_carveButton->setEnabled(true);
    updateProgress(0, QStringLiteral("Starting background Fbinst carving..."));
    appendLog(QStringLiteral("Starting Fbinst carving worker thread."));

    auto worker = std::make_shared<FbinstCarvingWorker>(params);
    m_carvingThread = QThread::create([this, worker]() {
        const FbinstCarvingWorker::Result result = worker->run(
            [this](int value, const QString &message) {
                QMetaObject::invokeMethod(this, [this, value, message]() {
                    updateProgress(value, message);
                }, Qt::QueuedConnection);
            },
            [this](const QString &message) {
                QMetaObject::invokeMethod(this, [this, message]() {
                    enqueueLog(message);
                }, Qt::QueuedConnection);
            });

        QMetaObject::invokeMethod(this, [this, result]() {
            flushPendingLogs();
            m_carvingThread = nullptr;
            m_carvingCancel.reset();

            if (!m_fbinstDb->isOpen()) {
                m_fbinstDb->setDatabaseName(m_fbinstDb->databaseName().isEmpty() ? QString() : m_fbinstDb->databaseName());
                if (!m_fbinstDb->open()) {
                    appendLog(QStringLiteral("Unable to reopen fbinsttool.db after carving: %1").arg(m_fbinstDb->lastError().text()));
                }
            }
            rebuildNavigation();
            m_carveButton->setText(QStringLiteral("Carve Remaining Sectors"));
            m_carveButton->setEnabled(m_currentDbKey == QStringLiteral("fbinst") && m_currentTableName == QStringLiteral("Fbinst_Remaining_Sectors"));
            if (m_fbinstDb->isOpen()) {
                showTable(QStringLiteral("fbinst"), QStringLiteral("Fbinst_Carved_Files"), QStringLiteral("Fbinst Carved Files"));
            }

            if (result.cancelled) {
                updateProgress(m_progressBar ? m_progressBar->value() : 0, QStringLiteral("Internal signature carving cancelled"));
                appendLog(result.message);
                QMessageBox::information(this, QStringLiteral("Carving cancelled"), result.message);
            } else if (result.ok) {
                updateProgress(100, QStringLiteral("Internal signature carving complete"));
                appendLog(result.message);
                QMessageBox::information(this, QStringLiteral("Carving complete"), result.message);
            } else {
                updateProgress(m_progressBar ? m_progressBar->value() : 0, QStringLiteral("Internal signature carving failed"));
                appendLog(result.message);
                QMessageBox::critical(this, QStringLiteral("Carving failed"), result.message);
            }
        }, Qt::QueuedConnection);
    });
    connect(m_carvingThread, &QThread::finished, m_carvingThread, &QObject::deleteLater);
    m_carvingThread->start();
    return;

    QSqlQuery create(*m_fbinstDb);
    if (!create.exec(QStringLiteral(
            "CREATE TABLE IF NOT EXISTS Fbinst_Carved_Files ("
            "Id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "Area_Type TEXT,"
            "Source_Start_Sector INTEGER,"
            "Source_End_Sector INTEGER,"
            "Logical_Image_Path TEXT,"
            "Logical_Start_Offset INTEGER,"
            "Logical_End_Offset INTEGER,"
            "File_Name TEXT,"
            "File_Extension TEXT,"
            "File_Size INTEGER,"
            "Sha256 TEXT,"
            "Output_Path TEXT,"
            "Carver TEXT,"
            "Validation_Result TEXT,"
            "Confidence TEXT,"
            "Status TEXT,"
            "Notes TEXT)"))) {
        QMessageBox::critical(this, QStringLiteral("Carving failed"), create.lastError().text());
        return;
    }

    const QStringList requiredColumns{
        QStringLiteral("Logical_Start_Offset"),
        QStringLiteral("Logical_End_Offset"),
        QStringLiteral("Carver"),
        QStringLiteral("Validation_Result"),
        QStringLiteral("Confidence"),
        QStringLiteral("Output_Path")
    };
    const QSqlRecord carvedSchema = m_fbinstDb->record(QStringLiteral("Fbinst_Carved_Files"));
    for (const QString &column : requiredColumns) {
        if (carvedSchema.indexOf(column) >= 0) {
            continue;
        }
        const QString type = column == QStringLiteral("Logical_Start_Offset") || column == QStringLiteral("Logical_End_Offset")
            ? QStringLiteral("INTEGER")
            : QStringLiteral("TEXT");
        QSqlQuery alter(*m_fbinstDb);
        if (!alter.exec(QStringLiteral("ALTER TABLE Fbinst_Carved_Files ADD COLUMN %1 %2").arg(column, type))) {
            QMessageBox::critical(this, QStringLiteral("Carving failed"), alter.lastError().text());
            return;
        }
    }

    QSqlQuery clear(*m_fbinstDb);
    if (!clear.exec(QStringLiteral("DELETE FROM Fbinst_Carved_Files"))) {
        QMessageBox::critical(this, QStringLiteral("Carving failed"), clear.lastError().text());
        return;
    }

    QList<FbinstCarveRange> ranges;
    QSqlQuery query(*m_fbinstDb);
    if (!query.exec(QStringLiteral(
            "SELECT Area_Type, Sector_Number FROM Fbinst_Remaining_Sectors "
            "ORDER BY CASE Area_Type WHEN 'Primary' THEN 0 WHEN 'Extended' THEN 1 ELSE 2 END, Sector_Number"))) {
        QMessageBox::critical(this, QStringLiteral("Carving failed"), query.lastError().text());
        return;
    }

    QString currentArea;
    quint64 rangeStart = 0;
    quint64 rangeEnd = 0;
    bool haveRange = false;
    auto flushRange = [&]() {
        if (haveRange) {
            ranges.append(FbinstCarveRange{currentArea, rangeStart, rangeEnd});
        }
    };

    while (query.next()) {
        const QString area = query.value(0).toString();
        const quint64 sector = query.value(1).toULongLong();
        if (!haveRange) {
            currentArea = area;
            rangeStart = sector;
            rangeEnd = sector;
            haveRange = true;
            continue;
        }
        if (area == currentArea && sector == rangeEnd + 1) {
            rangeEnd = sector;
            continue;
        }
        flushRange();
        currentArea = area;
        rangeStart = sector;
        rangeEnd = sector;
        haveRange = true;
    }
    flushRange();

    if (ranges.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("Carving complete"), QStringLiteral("No remaining Fbinst sectors were found."));
        return;
    }

    std::unique_ptr<ImageReader> reader = ImageReader::create(m_currentSourcePath);
    QString readerError;
    if (!reader || !reader->open(&readerError)) {
        QMessageBox::critical(this, QStringLiteral("Carving failed"), QStringLiteral("Unable to open source image: %1").arg(readerError));
        return;
    }

    appendLog(QStringLiteral("Structure-aware carving enabled: signatures identify candidates, then format-specific H/Len, H/F, or FSB parsers determine file boundaries."));
    const QList<FbinstCarveRange> carvingRanges = ranges;
    appendLog(QStringLiteral("Fbinst carving ranges: %1 contiguous remaining ranges will be scanned internally.").arg(carvingRanges.size()));

    const QString baseDir = QDir(m_outputDirEdit->text().trimmed()).filePath(QStringLiteral("fbinsttool_carving"));
    const QString runName = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"));
    const QString logicalDir = QDir(baseDir).filePath(QStringLiteral("logical_images/%1").arg(runName));
    const QString recoveryDir = QDir(baseDir).filePath(QStringLiteral("internal/%1").arg(runName));
    QDir().mkpath(logicalDir);
    QDir().mkpath(recoveryDir);

    auto insertCarvedRow = [&](const FbinstCarveRange &range,
                               const QString &logicalImage,
                               const QFileInfo &fileInfo,
                               quint64 logicalStart,
                               quint64 logicalEnd,
                               const QString &carver,
                               const QString &validationResult,
                               const QString &confidence,
                               const QString &status,
                               const QString &notes) -> bool {
        QSqlQuery insert(*m_fbinstDb);
        insert.prepare(QStringLiteral(
            "INSERT INTO Fbinst_Carved_Files("
            "Area_Type, Source_Start_Sector, Source_End_Sector, Logical_Image_Path, Logical_Start_Offset, Logical_End_Offset, "
            "File_Name, File_Extension, File_Size, Sha256, Output_Path, Carver, Validation_Result, Confidence, Status, Notes"
            ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"));
        insert.addBindValue(range.areaType);
        insert.addBindValue(range.startSector);
        insert.addBindValue(range.endSector);
        insert.addBindValue(QFileInfo(logicalImage).absoluteFilePath());
        insert.addBindValue(logicalStart);
        insert.addBindValue(logicalEnd);
        insert.addBindValue(fileInfo.exists() ? fileInfo.fileName() : QString());
        insert.addBindValue(fileInfo.exists() ? fileInfo.suffix().toLower() : QString());
        insert.addBindValue(fileInfo.exists() ? fileInfo.size() : 0);
        insert.addBindValue(fileInfo.exists() ? sha256ForFile(fileInfo.absoluteFilePath()) : QString());
        insert.addBindValue(fileInfo.exists() ? fileInfo.absoluteFilePath() : QString());
        insert.addBindValue(carver);
        insert.addBindValue(validationResult);
        insert.addBindValue(confidence);
        insert.addBindValue(status);
        insert.addBindValue(notes);
        if (!insert.exec()) {
            appendLog(QStringLiteral("Failed to record carving result: %1").arg(insert.lastError().text()));
            return false;
        }
        return true;
    };

    auto formatMiB = [](quint64 bytes) -> QString {
        return QString::number(double(bytes) / (1024.0 * 1024.0), 'f', 1);
    };

    auto rangeProgress = [](int startProgress, int endProgress, int rangeIndex, int rangeCount, double fraction) -> int {
        if (rangeCount <= 0) {
            return startProgress;
        }
        const double clamped = std::max(0.0, std::min(1.0, fraction));
        const double perRange = double(endProgress - startProgress) / double(rangeCount);
        const double value = double(startProgress) + perRange * double(rangeIndex - 1) + perRange * clamped;
        return qBound(startProgress, int(value), endProgress);
    };

    auto appendCarvedNonOverlapping = [](QVector<CarvedFile> *target, QVector<CarvedFile> source) {
        std::sort(source.begin(), source.end(), [](const CarvedFile &left, const CarvedFile &right) {
            if (left.logicalStart == right.logicalStart) {
                return left.logicalEnd > right.logicalEnd;
            }
            return left.logicalStart < right.logicalStart;
        });

        for (const CarvedFile &file : source) {
            if (!target->isEmpty() && file.logicalStart <= target->last().logicalEnd) {
                const quint64 fileSize = file.logicalEnd >= file.logicalStart ? file.logicalEnd - file.logicalStart : 0;
                const CarvedFile &last = target->last();
                const quint64 lastSize = last.logicalEnd >= last.logicalStart ? last.logicalEnd - last.logicalStart : 0;
                if (file.logicalStart == last.logicalStart && fileSize > lastSize) {
                    target->last() = file;
                }
                continue;
            }
            target->append(file);
        }
    };

    auto buildLogicalImage = [&](const FbinstCarveRange &range, const QString &logicalImage, int rangeIndex, int rangeCount, QString *errorMessage) -> bool {
        QFile output(logicalImage);
        if (!output.open(QIODevice::WriteOnly)) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Unable to create logical carving image: %1").arg(output.errorString());
            }
            return false;
        }

        const quint64 totalSectors = range.endSector >= range.startSector ? range.endSector - range.startSector + 1 : 0;
        quint64 builtSectors = 0;
        for (quint64 chunkStart = range.startSector; chunkStart <= range.endSector;) {
            QApplication::processEvents();
            const quint64 sectorsToRead = qMin<quint64>(CarvingChunkSectors, range.endSector - chunkStart + 1);
            const QByteArray chunkData = reader->read(chunkStart * ShowcaseAnalyzer::SectorSize, sectorsToRead * ShowcaseAnalyzer::SectorSize, errorMessage);
            if (quint64(chunkData.size()) != sectorsToRead * ShowcaseAnalyzer::SectorSize) {
                if (errorMessage) {
                    if (errorMessage->isEmpty()) {
                        *errorMessage = QStringLiteral("Unable to read source sectors %1-%2.").arg(chunkStart).arg(chunkStart + sectorsToRead - 1);
                    }
                }
                return false;
            }

            if (range.areaType == QStringLiteral("Primary")) {
                for (quint64 index = 0; index < sectorsToRead; ++index) {
                    const char *sectorPtr = chunkData.constData() + qsizetype(index * ShowcaseAnalyzer::SectorSize);
                    if (output.write(sectorPtr, 510) != 510) {
                        if (errorMessage) {
                            *errorMessage = QStringLiteral("Unable to write logical carving image: %1").arg(output.errorString());
                        }
                        return false;
                    }
                }
            } else if (output.write(chunkData) != chunkData.size()) {
                if (errorMessage) {
                    *errorMessage = QStringLiteral("Unable to write logical carving image: %1").arg(output.errorString());
                }
                return false;
            }
            chunkStart += sectorsToRead;
            builtSectors += sectorsToRead;

            const quint64 builtBytes = builtSectors * ShowcaseAnalyzer::SectorSize;
            const quint64 totalBytes = totalSectors * ShowcaseAnalyzer::SectorSize;
            updateProgress(rangeProgress(0, 35, rangeIndex, rangeCount, totalSectors == 0 ? 1.0 : double(builtSectors) / double(totalSectors)),
                QStringLiteral("Building %1 carving image: %2/%3 MiB")
                    .arg(rangeName(range), formatMiB(builtBytes), formatMiB(totalBytes)));
        }
        return true;
    };

    QApplication::setOverrideCursor(Qt::WaitCursor);
    m_carveButton->setEnabled(false);
    updateProgress(0, QStringLiteral("Preparing internal signature carving..."));
    appendLog(QStringLiteral("Internal signature carver enabled."));

    int recoveredCount = 0;
    int processedRanges = 0;
    SignatureCarver carver;
    for (const FbinstCarveRange &range : carvingRanges) {
        ++processedRanges;
        const QString name = rangeName(range);
        const QString logicalImage = QDir(logicalDir).filePath(QStringLiteral("%1.dd").arg(name));
        const QString rangeRecoveryDir = QDir(recoveryDir).filePath(name);
        QDir().mkpath(rangeRecoveryDir);

        updateProgress(rangeProgress(0, 35, processedRanges, int(carvingRanges.size()), 0.0), QStringLiteral("Building %1 carving image...").arg(name));
        QString errorMessage;
        if (!buildLogicalImage(range, logicalImage, processedRanges, int(carvingRanges.size()), &errorMessage)) {
            appendLog(QStringLiteral("Carving image failed for %1: %2").arg(name, errorMessage));
            insertCarvedRow(range, logicalImage, QFileInfo(), 0, 0, QStringLiteral("LogicalImageBuild"), QStringLiteral("Source read/write failed"), QStringLiteral("None"), QStringLiteral("Failed"), errorMessage);
            continue;
        }

        QFile logical(logicalImage);
        if (!logical.open(QIODevice::ReadOnly)) {
            errorMessage = QStringLiteral("Unable to read logical carving image: %1").arg(logical.errorString());
            appendLog(errorMessage);
            insertCarvedRow(range, logicalImage, QFileInfo(), 0, 0, QStringLiteral("LogicalImageRead"), QStringLiteral("Logical image unavailable"), QStringLiteral("None"), QStringLiteral("Failed"), errorMessage);
            continue;
        }

        const qsizetype scanStride = range.areaType == QStringLiteral("Primary") ? 510 : qsizetype(ShowcaseAnalyzer::SectorSize);
        QVector<CarvedFile> carvedFiles;
        const qint64 logicalSize = logical.size();
        const int totalWindows = qMax(1, int((logicalSize + CarvingScanWindowBytes - 1) / CarvingScanWindowBytes));
        int windowNumber = 0;
        for (qint64 readOffset = 0; readOffset < logicalSize; readOffset += CarvingScanWindowBytes) {
            ++windowNumber;
            const qint64 primaryBytes = qMin(CarvingScanWindowBytes, logicalSize - readOffset);
            const qint64 bytesToRead = qMin(primaryBytes + CarvingScanOverlapBytes, logicalSize - readOffset);
            if (!logical.seek(readOffset)) {
                errorMessage = QStringLiteral("Unable to seek logical carving image to %1: %2").arg(readOffset).arg(logical.errorString());
                appendLog(errorMessage);
                break;
            }

            updateProgress(rangeProgress(35, 95, processedRanges, int(carvingRanges.size()), double(readOffset) / double(qMax<qint64>(1, logicalSize))),
                QStringLiteral("Scanning %1: window %2/%3, %4/%5 MiB")
                    .arg(name)
                    .arg(windowNumber)
                    .arg(totalWindows)
                    .arg(formatMiB(quint64(readOffset)))
                    .arg(formatMiB(quint64(logicalSize))));
            QApplication::processEvents();

            const QByteArray windowData = logical.read(bytesToRead);
            if (windowData.size() != bytesToRead) {
                errorMessage = QStringLiteral("Unable to read logical carving window at %1: %2").arg(readOffset).arg(logical.errorString());
                appendLog(errorMessage);
                break;
            }

            appendLog(QStringLiteral("Scanning window detail: range=%1 window=%2/%3 logical_offset=%4 bytes=%5 stride=%6 overlap=%7")
                .arg(name)
                .arg(windowNumber)
                .arg(totalWindows)
                .arg(readOffset)
                .arg(windowData.size())
                .arg(scanStride)
                .arg(qMax<qint64>(0, bytesToRead - primaryBytes)));
            QVector<CarvedFile> windowFiles = carver.carve(windowData, scanStride, quint64(readOffset), [this](const QString &message) {
                appendLog(message);
            });
            const quint64 primaryEnd = quint64(readOffset + primaryBytes);
            const int beforeTrimCount = windowFiles.size();
            for (int i = windowFiles.size() - 1; i >= 0; --i) {
                if (windowFiles[i].logicalStart >= primaryEnd) {
                    windowFiles.removeAt(i);
                }
            }
            appendLog(QStringLiteral("Window scan complete: range=%1 window=%2/%3 recovered_candidates=%4 retained_in_primary_window=%5")
                .arg(name)
                .arg(windowNumber)
                .arg(totalWindows)
                .arg(beforeTrimCount)
                .arg(windowFiles.size()));
            appendCarvedNonOverlapping(&carvedFiles, windowFiles);
        }
        logical.close();

        if (carvedFiles.isEmpty()) {
            insertCarvedRow(range, logicalImage, QFileInfo(), 0, 0, QStringLiteral("CandidateScanner"), QStringLiteral("No validated candidates"), QStringLiteral("None"), QStringLiteral("No files recovered"), QStringLiteral("No supported candidate was validated from this range."));
            appendLog(QStringLiteral("Internal carving completed for %1: no files recovered.").arg(name));
            continue;
        }

        int index = 0;
        for (const CarvedFile &carvedFile : carvedFiles) {
            updateProgress(rangeProgress(95, 99, processedRanges, int(carvingRanges.size()), carvedFiles.isEmpty() ? 1.0 : double(index) / double(carvedFiles.size())),
                QStringLiteral("Writing carved files for %1: %2/%3").arg(name).arg(index).arg(carvedFiles.size()));
            QApplication::processEvents();
            const QString fileName = QStringLiteral("%1_%2_%3.%4")
                .arg(name)
                .arg(index++, 4, 10, QLatin1Char('0'))
                .arg(carvedFile.logicalStart, 10, 10, QLatin1Char('0'))
                .arg(carvedFile.extension);
            const QString outputPath = QDir(rangeRecoveryDir).filePath(fileName);
            QFile output(outputPath);
            if (!output.open(QIODevice::WriteOnly) || output.write(carvedFile.data) != carvedFile.data.size()) {
                errorMessage = QStringLiteral("Unable to write carved file: %1").arg(output.errorString());
                insertCarvedRow(range, logicalImage, QFileInfo(), carvedFile.logicalStart, carvedFile.logicalEnd, carvedFile.carvingMethod, carvedFile.validationResult, carvedFile.confidence, QStringLiteral("Failed"), errorMessage);
                continue;
            }
            output.close();
            const QFileInfo fileInfo(outputPath);
            insertCarvedRow(range, logicalImage, fileInfo, carvedFile.logicalStart, carvedFile.logicalEnd, carvedFile.carvingMethod, carvedFile.validationResult, carvedFile.confidence, QStringLiteral("Recovered"), carvedFile.notes);
            ++recoveredCount;
        }
        appendLog(QStringLiteral("Internal carving completed for %1: %2 files recovered.").arg(name).arg(carvedFiles.size()));
    }

    reader->close();
    if (m_tableModel && m_currentDbKey == QStringLiteral("fbinst")) {
        m_tableModel->select();
    }
    rebuildNavigation();
    QApplication::restoreOverrideCursor();
    m_carveButton->setEnabled(m_currentDbKey == QStringLiteral("fbinst") && m_currentTableName == QStringLiteral("Fbinst_Remaining_Sectors"));
    updateProgress(100, QStringLiteral("Internal signature carving complete"));

    const QString message = QStringLiteral("Internal signature carving complete. %1 files recovered from %2 candidates.").arg(recoveredCount).arg(carvingRanges.size());
    appendLog(message);
    QMessageBox::information(this, QStringLiteral("Carving complete"), message);
}

void ShowcaseApp::applyFilter()
{
    if (!m_tableModel) {
        return;
    }
    const QString text = m_filterEdit->text().trimmed();
    if (text.isEmpty()) {
        m_tableModel->setFilter(QString());
        m_tableModel->select();
        m_statusLabel->setText(QStringLiteral("Loaded %1 rows").arg(m_tableModel->rowCount()));
        return;
    }

    QString escaped = text;
    escaped.replace('\'', QStringLiteral("''"));
    QStringList clauses;
    const QSqlRecord record = m_tableModel->record();
    for (int i = 0; i < record.count(); ++i) {
        clauses << QStringLiteral("CAST(%1 AS TEXT) LIKE '%%").arg(record.fieldName(i)) + escaped + QStringLiteral("%%'");
    }
    m_tableModel->setFilter(clauses.join(QStringLiteral(" OR ")));
    m_tableModel->select();
    m_statusLabel->setText(QStringLiteral("Filtered to %1 rows").arg(m_tableModel->rowCount()));
}

void ShowcaseApp::runAnalysis()
{
    const QString outputPath = m_outputDirEdit->text().trimmed();
    if (outputPath.isEmpty() || !QDir(outputPath).exists()) {
        QMessageBox::warning(this, QStringLiteral("Invalid output folder"), QStringLiteral("Please choose an existing output folder."));
        return;
    }

    QString sourcePath;
    if (m_imageMode->isChecked()) {
        sourcePath = m_imagePathEdit->text().trimmed();
        if (sourcePath.isEmpty()) {
            QMessageBox::warning(this, QStringLiteral("Missing image"), QStringLiteral("Please select an image file."));
            return;
        }
        if (!QFileInfo::exists(sourcePath)) {
            QMessageBox::warning(this, QStringLiteral("Invalid image"), QStringLiteral("The selected image file does not exist."));
            return;
        }
    } else {
        if (!RawDevice::isUserAdmin()) {
            QMessageBox::warning(this, QStringLiteral("Administrator required"), QStringLiteral("Physical drive analysis requires administrator rights and uses read-only access to the source device."));
            return;
        }
        const QString driveValue = m_physicalDriveCombo->currentData().toString().trimmed();
        if (driveValue.isEmpty()) {
            QMessageBox::warning(this, QStringLiteral("Missing drive"), QStringLiteral("Please detect and select a physical drive from the list."));
            return;
        }
        sourcePath = RawDevice::normalizePhysicalDrive(driveValue);
    }

    m_currentSourcePath = sourcePath;
    const QString partitionPath = QDir(outputPath).filePath(QStringLiteral("partition.db"));
    const QString booticePath = QDir(outputPath).filePath(QStringLiteral("bootice.db"));
    const QString fbinstPath = QDir(outputPath).filePath(QStringLiteral("fbinsttool.db"));

    updateProgress(0, QStringLiteral("Preparing analysis..."));
    appendLog(QStringLiteral("Evidence source queued: %1").arg(sourcePath));
    appendLog(QStringLiteral("Partition DB: %1").arg(QFileInfo(partitionPath).absoluteFilePath()));
    appendLog(QStringLiteral("Bootice DB: %1").arg(QFileInfo(booticePath).absoluteFilePath()));
    appendLog(QStringLiteral("Fbinst DB: %1").arg(QFileInfo(fbinstPath).absoluteFilePath()));
    m_statusLabel->setText(QStringLiteral("Running analysis..."));
    m_sourceLabel->setText(sourcePath);
    m_runButton->setEnabled(false);
    QApplication::setOverrideCursor(Qt::WaitCursor);

    closeDatabases();
    *m_partitionDb = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), m_partitionConnectionName);
    *m_booticeDb = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), m_booticeConnectionName);
    *m_fbinstDb = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), m_fbinstConnectionName);
    m_partitionDb->setDatabaseName(partitionPath);
    m_booticeDb->setDatabaseName(booticePath);
    m_fbinstDb->setDatabaseName(fbinstPath);

    QString statusMessage;
    bool ok = false;

    if (!m_partitionDb->open()) {
        statusMessage = QStringLiteral("Unable to open partition.db: %1").arg(m_partitionDb->lastError().text());
    } else if (!m_booticeDb->open()) {
        statusMessage = QStringLiteral("Unable to open bootice.db: %1").arg(m_booticeDb->lastError().text());
    } else if (!m_fbinstDb->open()) {
        statusMessage = QStringLiteral("Unable to open fbinsttool.db: %1").arg(m_fbinstDb->lastError().text());
    } else {
        ShowcaseAnalyzer analyzer(sourcePath);
        analyzer.setProgressCallback([this](int value, const QString &message) {
            updateProgress(value, message);
        });
        ok = analyzer.analyze(*m_partitionDb, *m_booticeDb, *m_fbinstDb, &statusMessage);
        if (ok) {
            statusMessage = QStringLiteral("Acquisition complete. Results stored in partition.db, bootice.db, and fbinsttool.db.");
            rebuildNavigation();
        }
    }

    QApplication::restoreOverrideCursor();
    m_runButton->setEnabled(true);
    appendLog(statusMessage);
    if (ok) {
        updateProgress(100, QStringLiteral("Analysis complete"));
    } else {
        updateProgress(m_progressBar ? m_progressBar->value() : 0, QStringLiteral("Analysis failed"));
    }
    m_statusLabel->setText(ok ? QStringLiteral("Acquisition completed") : QStringLiteral("Acquisition failed"));

    if (ok) {
        QMessageBox::information(this, QStringLiteral("Analysis complete"), statusMessage);
    } else {
        QMessageBox::critical(this, QStringLiteral("Analysis failed"), statusMessage);
    }
}






















