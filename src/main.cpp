#include "showcaseapp.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("FBBForensics"));
    app.setApplicationVersion(QStringLiteral("1.0.0"));

    ShowcaseApp window;
    window.show();
    return app.exec();
}
