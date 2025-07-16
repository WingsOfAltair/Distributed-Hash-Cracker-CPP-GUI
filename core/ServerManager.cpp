// ServerManager.cpp
#include "ServerManager.h"
#include <boost/algorithm/string/trim.hpp>
#include <fstream>
#include <sstream>
#include <chrono>

using boost::asio::ip::tcp;
using boost::asio::ip::udp;

ServerManager::ServerManager(QObject* parent) : QObject(parent) {
    readCrackedHashes("cracked.txt");
}

ServerManager::~ServerManager() {
    stopServer();
}

void ServerManager::startServer(int port) {
    if (serverRunning) return;
    serverRunning = true;
    serverPort = port;
    ioContext = std::make_unique<boost::asio::io_context>();
    acceptor = std::make_unique<tcp::acceptor>(*ioContext, tcp::endpoint(tcp::v4(), port));
    udpSocket = std::make_unique<boost::asio::ip::udp::socket>(*ioContext, udp::endpoint(udp::v4(), port));

    serverThreads.emplace_back([this]() { this->acceptClients(); });
    serverThreads.emplace_back([this]() { this->udpEchoServer(); });
    serverThreads.emplace_back([this]() { ioContext->run(); });

    emit logMessage("Server started on port " + QString::number(port));
}

void ServerManager::stopServer() {
    if (!serverRunning) return;
    serverRunning = false;

    if (ioContext) ioContext->stop();
    for (auto& thread : serverThreads) {
        if (thread.joinable()) thread.join();
    }
    serverThreads.clear();
    clients.clear();
    clientsReady.clear();
    totalClients = 0;

    emit logMessage("Server stopped.");
}

void ServerManager::readCrackedHashes(const QString& file) {
    std::ifstream in(file.toStdString());
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string h, s, p;
        if (std::getline(iss, h, ':') && std::getline(iss, s, ':') && std::getline(iss, p)) {
            crackedHashes.emplace_back(QString::fromStdString(h), QString::fromStdString(s), QString::fromStdString(p));
        }
    }
}

void ServerManager::acceptClients() {
    while (serverRunning) {
        try {
            auto socket = std::make_shared<tcp::socket>(*ioContext);
            acceptor->accept(*socket);
            serverThreads.emplace_back([this, socket]() { handleClient(socket); });
        }
        catch (...) {}
    }
}

void ServerManager::handleClient(std::shared_ptr<tcp::socket> socket) {
    std::string clientId = socket->remote_endpoint().address().to_string() + ":" + std::to_string(socket->remote_endpoint().port());

    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        clients[clientId] = socket;
        clientsReady[clientId] = false;
        ++totalClients;
    }

    emit clientConnected(QString::fromStdString(clientId));
    emit logMessage("Client connected: " + QString::fromStdString(clientId));

    try {
        boost::asio::streambuf buffer;
        while (serverRunning && socket->is_open()) {
            boost::asio::read_until(*socket, buffer, "\n");
            std::istream is(&buffer);
            std::string message;
            std::getline(is, message);
            boost::algorithm::trim(message);

            if (message == "Ready") {
                clientsMutex.lock();
                clientsReady[clientId] = true;
                clientsMutex.unlock();
                emit clientReadyStateChanged(QString::fromStdString(clientId), true);
            }
            else if (message.find("MATCH:") == 0) {
                matchFound = true;
                currentPassword = QString::fromStdString(message.substr(6)).split(' ').first();
                crackedHashes.emplace_back(currentHash, currentSalt, currentPassword);
                emit logMessage("Match from " + QString::fromStdString(clientId) + ": " + currentPassword);
                notifyStopAll();
            }
        }
    }
    catch (...) {
        emit logMessage("Client disconnected: " + QString::fromStdString(clientId));
    }

    std::lock_guard<std::mutex> lock(clientsMutex);
    clients.erase(clientId);
    clientsReady.erase(clientId);
    --totalClients;
}

void ServerManager::udpEchoServer() {
    char data[128];
    udp::endpoint sender;

    while (serverRunning) {
        boost::system::error_code ec;
        size_t len = udpSocket->receive_from(boost::asio::buffer(data), sender, 0, ec);
        if (!ec) {
            std::string received(data, len);
            std::string response = "pong";
            udpSocket->send_to(boost::asio::buffer(response), sender);
        }
    }
}

void ServerManager::sendHashToClients(const QString& hashType, const QString& hash, const QString& salt) {
    currentHashType = hashType;
    currentHash = hash;
    currentSalt = salt;
    matchFound = false;
    clientsResponded = 0;
    notifyClients();
}

void ServerManager::notifyClients() {
    std::string msg = currentHashType.toStdString() + ":" + currentHash.toStdString();
    if (!currentSalt.isEmpty()) msg += ":" + currentSalt.toStdString();
    msg += "\n";

    std::lock_guard<std::mutex> lock(clientsMutex);
    for (auto& [id, socket] : clients) {
        if (clientsReady[id] && socket && socket->is_open()) {
            try {
                boost::asio::write(*socket, boost::asio::buffer(msg));
                clientsReady[id] = false;
            }
            catch (...) {
                emit logMessage("Failed to notify client: " + QString::fromStdString(id));
            }
        }
    }
}

void ServerManager::notifyStopAll() {
    std::lock_guard<std::mutex> lock(clientsMutex);
    for (auto& [id, socket] : clients) {
        if (socket && socket->is_open()) {
            try {
                boost::asio::write(*socket, boost::asio::buffer("STOP\n"));
            }
            catch (...) {
                emit logMessage("Failed to send STOP to client: " + QString::fromStdString(id));
            }
        }
    }
}

void ServerManager::reloadClients() {
    std::lock_guard<std::mutex> lock(clientsMutex);
    for (auto& [id, socket] : clients) {
        if (clientsReady[id] && socket && socket->is_open()) {
            try {
                boost::asio::write(*socket, boost::asio::buffer("reload\n"));
                clientsReady[id] = false;
            }
            catch (...) {
                emit logMessage("Failed to reload client: " + QString::fromStdString(id));
            }
        }
    }
}