// MainWindow.cpp
#include "MainWindow.h"
#include "ui_MainWindow.h"
#include <QMessageBox>

bool started = false;

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , serverManager(new ServerManager(this))
{
    ui->setupUi(this);

    connect(ui->buttonReload, &QPushButton::clicked, this, &MainWindow::reloadClients);
    connect(ui->buttonSendHash, &QPushButton::clicked, this, &MainWindow::sendHash);

    connect(serverManager, &ServerManager::clientConnected, this, &MainWindow::onClientConnected);
    connect(serverManager, &ServerManager::clientReadyStateChanged, this, &MainWindow::onClientReadyStateChanged);
    connect(serverManager, &ServerManager::logMessage, this, &MainWindow::onLogMessage);
    connect(serverManager, &ServerManager::clientsStatusChanged, this, &MainWindow::RefreshList);
    connect(serverManager, &ServerManager::StartCracking, this, &MainWindow::TurnOnCracking);
    connect(serverManager, &ServerManager::StopCracking, this, &MainWindow::TurnOffCracking);

    ui->comboBoxHashType->addItems({
        "bcrypt", "scrypt", "argon2",
        "md5", "sha1", "sha256", "sha384", "sha512",
        "sha3-224", "sha3-256", "sha3-384", "sha3-512"
        });
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::startServer() {
    int port = 1337;
    if (port <= 0 || port > 65535) {
        QMessageBox::warning(this, "Invalid Port", "Please enter a valid port number.");
        return;
    }
    serverManager->startServer(port);
    onLogMessage("Server started on port " + QString::number(port));
}

void MainWindow::stopServer() {
    serverManager->stopServer();
    onLogMessage("Server stopped.");
    ui->listWidgetClients->clear();
}

void MainWindow::reloadClients() {
    serverManager->reloadClients();
    onLogMessage("Reload message sent to ready clients.");
}

void MainWindow::sendHash() {
    QString type = ui->comboBoxHashType->currentText();
    QString hash = ui->lineEditHash->text().trimmed();
    QString salt = ui->lineEditSalt->text().trimmed();

    if (hash.isEmpty()) {
        QMessageBox::warning(this, "Missing Hash", "You must enter a hash.");
        return;
    }

    if (!started) {
        this->TurnOnCracking();
        serverManager->sendHashToClients(type, hash, salt);
    }
    else {
        this->TurnOffCracking();
    }
}

void MainWindow::TurnOnCracking() {
    started = true;
    ui->buttonSendHash->setText("Stop Cracking!");
}

void MainWindow::TurnOffCracking() {
    started = false;
    ui->buttonSendHash->setText("Send to Clients");
    serverManager->StopCrackingClients();
}

void MainWindow::RefreshList() {
    ui->listWidgetClients->clear();

    std::unordered_map<std::string, bool> connectedClients = serverManager->getConnectedClientsStatus();

    // Re-add all clients
    for (const auto& [clientIdStd, ready] : connectedClients) {
        QString clientId = QString::fromStdString(clientIdStd);
        if (ready) {
            ui->listWidgetClients->addItem(clientId + " [Ready]");
        } else {
            ui->listWidgetClients->addItem(clientId + " [Not Ready]");
        }
    }
}

void MainWindow::onClientConnected(const QString& clientId) {
    this->RefreshList();
}

void MainWindow::onClientReadyStateChanged(const QString& clientId, bool isReady) {
    this->RefreshList();
}

void MainWindow::onLogMessage(const QString& msg) {
    ui->textEditLogs->append("[LOG] " + msg);
    QTextCursor c = ui->textEditLogs->textCursor();
    c.movePosition(QTextCursor::End);
    ui->textEditLogs->setTextCursor(c);
}
