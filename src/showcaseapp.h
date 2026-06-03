#pragma once

#include <QMainWindow>
#include <QString>

#include <atomic>
#include <memory>

class QComboBox;
class QLabel;
class QLineEdit;
class QModelIndex;
class QProgressBar;
class QPushButton;
class QRadioButton;
class QSqlDatabase;
class QSqlTableModel;
class QTableView;
class QTextEdit;
class QThread;
class QTimer;
class QTreeWidget;
class QTreeWidgetItem;

class ShowcaseApp final : public QMainWindow
{
public:
    ShowcaseApp();
    ~ShowcaseApp() override;

private:
    void browseImage();
    void browseOutputDirectory();
    void detectPhysicalDrives();
    void updateInputMode();
    void runAnalysis();
    void appendLog(const QString &message);
    void rebuildNavigation();
    void showTable(const QString &dbKey, const QString &tableName, const QString &title);
    void updateRecordDetails();
    void applyFilter();
    void closeDatabases();
    void extractSelectedCurrentFile();
    void extractSelectedBooticeFile();
    void extractSelectedFbinstFile();
    void carveFbinstRemainingSectors();
    void handleResultTableActivated(const QModelIndex &index);
    void updateProgress(int value, const QString &message);
    void enqueueLog(const QString &message);
    void flushPendingLogs();
    bool canExtractCurrentRecord() const;
    bool canExtractCurrentBooticeRecord() const;
    bool canExtractCurrentFbinstRecord() const;
    QSqlDatabase *databaseForKey(const QString &dbKey) const;

    QRadioButton *m_imageMode = nullptr;
    QRadioButton *m_physicalMode = nullptr;
    QLineEdit *m_imagePathEdit = nullptr;
    QPushButton *m_imageBrowseButton = nullptr;
    QComboBox *m_physicalDriveCombo = nullptr;
    QPushButton *m_detectDriveButton = nullptr;
    QLineEdit *m_outputDirEdit = nullptr;
    QPushButton *m_runButton = nullptr;
    QPushButton *m_extractButton = nullptr;
    QPushButton *m_carveButton = nullptr;
    QLabel *m_statusLabel = nullptr;
    QLabel *m_sourceLabel = nullptr;
    QLabel *m_viewTitleLabel = nullptr;
    QLabel *m_progressLabel = nullptr;
    QLineEdit *m_filterEdit = nullptr;
    QTreeWidget *m_navigationTree = nullptr;
    QTableView *m_resultTable = nullptr;
    QTextEdit *m_detailView = nullptr;
    QTextEdit *m_logView = nullptr;
    QProgressBar *m_progressBar = nullptr;

    QSqlDatabase *m_partitionDb = nullptr;
    QSqlDatabase *m_booticeDb = nullptr;
    QSqlDatabase *m_fbinstDb = nullptr;
    QSqlTableModel *m_tableModel = nullptr;
    QString m_partitionConnectionName;
    QString m_booticeConnectionName;
    QString m_fbinstConnectionName;
    QString m_currentDbKey;
    QString m_currentTableName;
    QString m_currentSourcePath;
    QString m_photoRecPath;
    QThread *m_carvingThread = nullptr;
    QTimer *m_logFlushTimer = nullptr;
    QStringList m_pendingLogs;
    std::shared_ptr<std::atomic_bool> m_carvingCancel;
};
