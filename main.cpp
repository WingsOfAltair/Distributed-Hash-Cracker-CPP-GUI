#include <QApplication>
#include "gui/MainWindow.h"
#include <QStyleFactory>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setWindowIcon(QIcon(":/icons/appicon.png"));
    QApplication::setStyle(QStyleFactory::create("Fusion"));

    MainWindow window;
    window.setWindowTitle("ScrutaNet - Server GUI");
    window.resize(800, 600); // Optional: default window size
    window.show();

    return app.exec();
}
