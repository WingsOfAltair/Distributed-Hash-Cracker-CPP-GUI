#include <QApplication>
#include "gui/MainWindow.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    MainWindow window;
    window.setWindowTitle("Distributed Hash Cracker - Server GUI");
    window.resize(800, 600); // Optional: default window size
    window.show();

    return app.exec();
}