// MainWindow.cpp
#include "MainWindow.h"
#include "ui_MainWindow.h"
#include <QMessageBox>
#include <QCloseEvent>
#include <boost/regex.hpp>
#include "ClientListWidget.h"

bool started = false;

void MainWindow::closeEvent(QCloseEvent* event) {
    // Optionally ask user for confirmation or do cleanup here
    // e.g. stop your server properly before exiting

    this->stopServer();

    event->accept();  // accept close event to let window close

    // Or call QApplication::quit() if you want to quit immediately:
    // QApplication::quit();
}

void MainWindow::showClientContextMenu(const QPoint &pos) {
    QListWidgetItem *item = ui->listWidgetClients->itemAt(pos);
    if (!item) return;

    QMenu contextMenu(this);
    QAction *shutdownAction = contextMenu.addAction("Shutdown Client");

    QAction *selectedAction = contextMenu.exec(ui->listWidgetClients->mapToGlobal(pos));
    if (selectedAction == shutdownAction) {
        QString clientLabel = item->text(); // e.g. "127.0.0.1:2345 [Ready]"
        QString clientId = clientLabel.section(' ', 0, 0); // split off status
        serverManager->shutdownClient(clientId.toStdString());
        onLogMessage("Sent shutdown command to: " + clientId);
    }
}

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , serverManager(new ServerManager(this))
{
    ui->setupUi(this);

    connect(ui->buttonReload, &QPushButton::clicked, this, &MainWindow::reloadClients);
    connect(ui->buttonSendHash, &QPushButton::clicked, this, &MainWindow::sendHash);
    connect(ui->buttonCheckHashType, &QPushButton::clicked, this, &MainWindow::checkHashType);

    ui->listWidgetClients->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->listWidgetClients, &QListWidget::customContextMenuRequested,
            this, &MainWindow::showClientContextMenu);

    connect(serverManager, &ServerManager::clientConnected, this, &MainWindow::onClientConnected);
    connect(serverManager, &ServerManager::clientReadyStateChanged, this, &MainWindow::onClientReadyStateChanged);
    connect(serverManager, &ServerManager::logMessage, this, &MainWindow::onLogMessage);
    connect(serverManager, &ServerManager::clientsStatusChanged, this, &MainWindow::RefreshList);
    connect(serverManager, &ServerManager::StartCracking, this, &MainWindow::TurnOnCracking);
    connect(serverManager, &ServerManager::StopCracking, this, &MainWindow::TurnOffCracking);
    connect(serverManager, &ServerManager::StopCrackingNotStop, this, &MainWindow::TurnOffCrackingNotStop);
    connect(serverManager, &ServerManager::StopCrackingZeroClients, this, &MainWindow::TurnOffCrackingZeroClients);

    ui->comboBoxHashType->addItems({
        "bcrypt", "scrypt", "argon2",
        "md5", "sha1", "sha256", "sha384", "sha512",
        "sha3-224", "sha3-256", "sha3-384", "sha3-512"
        });
}

bool isPhpScryptHash(const std::string& hash) {
    boost::regex scryptPattern(R"(^\d+\$\d+\$\d+\$[A-Za-z0-9./]+\$[A-Za-z0-9./+=]+$)");
    return boost::regex_match(hash, scryptPattern);
}

// Check bcrypt hash format
bool isBcryptHash(const std::string& hash) {
    boost::regex bcryptPattern(R"(^\$(2[aby])\$\d{2}\$[./A-Za-z0-9]{53}$)");
    return boost::regex_match(hash, bcryptPattern);
}

// Determine hash type by length
std::string getHashType(const std::string& hash) {
    if (hash.rfind("$argon2id$", 0) == 0) return "Argon2id";
    if (hash.rfind("$argon2i$", 0) == 0) return "Argon2i";
    if (hash.rfind("$argon2d$", 0) == 0) return "Argon2d";

    std::map<std::string, size_t> hashTypes = {
                                               {"MD5", 32}, {"SHA-1 or RIPEMD-160", 40}, {"SHA-224 or SHA3-224", 56},
                                               {"SHA-256 or SHA3-256", 64}, {"SHA-384 or SHA3-384", 96}, {"SHA-512 or SHA3-512", 128} };
    size_t hashLength = hash.length();
    for (const auto& [type, length] : hashTypes) {
        if (hashLength == length) return type;
    }
    return "Unknown hash type";
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::checkHashType() {
    QString hashQString = ui->lineEditHash->text().trimmed();
    std::string hash = hashQString.toStdString();  // Convert to std::string
    std::string hashType = getHashType(hash);
    if (hashType == "Unknown hash type") {
        bool isBcrypt = isBcryptHash(hash);
        bool isScrypt = isPhpScryptHash(hash);
        if (isBcrypt) {
            ui->textEditLogs->append("Hash Type: BCrypt");
        }
        else if (isScrypt) {
            ui->textEditLogs->append("Hash Type: Scrypt");
        }
        else {
            ui->textEditLogs->append("Unknown hash type.");
        }
    }
    else {
        ui->textEditLogs->append("Hash Type: " + QString::fromStdString(getHashType(hash)));
    }
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
        auto clientsReady = serverManager->getConnectedClientsStatus();
        if (clientsReady.size() < 1)
        {
            QMessageBox::warning(this, "No Connected Clients", "There must be at least one connected, ready client.");
            return;
        }

        bool allReady = std::all_of(clientsReady.begin(), clientsReady.end(),
                                    [](const auto& pair) {
                                        return pair.second; // second = is_ready
                                    });

        if (!allReady)
        {
            QMessageBox::warning(this, "Ready connected clients.", "All connected clients must be ready.");
            return;
        }

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

void MainWindow::TurnOffCrackingNotStop() {
    started = false;
    ui->buttonSendHash->setText("Send to Clients");
    serverManager->StopCrackingClients();
}

void MainWindow::TurnOffCracking() {
    started = false;
    ui->buttonSendHash->setText("Send to Clients");
    serverManager->StopCrackingClients();
    ui->textEditLogs->append("Sent stop command to client.");
}

void MainWindow::TurnOffCrackingZeroClients() {
    started = false;
    ui->buttonSendHash->setText("Send to Clients");
    serverManager->StopCrackingClients();
    ui->textEditLogs->append("Cracking has stopped because there are no connected clients.");
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
