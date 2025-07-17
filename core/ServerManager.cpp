// ServerManager.cpp
#include "ServerManager.h"
#include <boost/algorithm/string/trim.hpp>
#include <fstream>
#include <sstream>
#include <chrono>

ServerManager::ServerManager(QObject* parent) : QObject(parent) {
    readCrackedHashes("cracked.txt");
    startServer(1337);
}

ServerManager::~ServerManager() {
    //stopServer();
}

void ServerManager::asyncAcceptClient() {
    if (!acceptor || !acceptor->is_open()) return;

    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(*ioContext);
    acceptor->async_accept(*socket, [this, socket](const boost::system::error_code& ec) {
        if (!serverRunning || ec == boost::asio::error::operation_aborted) return;
        if (!ec) {
            handleClient(socket);  // Or defer to a thread-safe queue if needed
        } else {
            emit logMessage("Accept error: " + QString::fromStdString(ec.message()));
        }
        asyncAcceptClient();  // loop again
    });
}

void ServerManager::asyncUdpReceive() {
    if (!udpSocket || !udpSocket->is_open()) return;

    udpSocketBuffer.resize(128);
    udpSocket->async_receive_from(
        boost::asio::buffer(udpSocketBuffer), udpSender,
        [this](const boost::system::error_code& ec, std::size_t bytes_recvd) {
            if (!serverRunning || ec == boost::asio::error::operation_aborted) return;
            if (!ec && bytes_recvd > 0) {
                std::string response = "pong";
                udpSocket->async_send_to(boost::asio::buffer(response), udpSender,
                                         [](const boost::system::error_code&, std::size_t) {});
            }
            asyncUdpReceive();  // loop again
        });
}

void ServerManager::startServer(int port) {
    if (serverRunning) return;
    serverRunning = true;
    serverPort = port;

    ioContext = std::make_unique<boost::asio::io_context>();
    workGuard.emplace(boost::asio::make_work_guard(*ioContext));

    acceptor = std::make_unique<boost::asio::ip::tcp::acceptor>(
        *ioContext, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port));

    udpSocket = std::make_unique<boost::asio::ip::udp::socket>(
        *ioContext, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), port));

    asyncAcceptClient();     // Start async accept loop
    asyncUdpReceive();       // Start async UDP receive loop

    serverThreads.emplace_back([this]() {
        try {
            ioContext->run();  // 🧵 Blocking run loop
        } catch (const std::exception& ex) {
            emit logMessage("io_context exception: " + QString::fromStdString(ex.what()));
        }
    });

    emit logMessage("Server started on port " + QString::number(port));
}

void ServerManager::stopServer() {
    if (!serverRunning) return;
    serverRunning = false;

    // Cancel async ops
    if (acceptor && acceptor->is_open()) {
        boost::system::error_code ec;
        acceptor->cancel(ec);
        acceptor->close(ec);
    }

    if (udpSocket && udpSocket->is_open()) {
        boost::system::error_code ec;
        udpSocket->cancel(ec);
        udpSocket->close(ec);
    }

    // Allow io_context to stop once all work is done
    if (workGuard.has_value()) {
        workGuard.reset();
    }

    if (ioContext) {
        ioContext->stop();
    }

    for (auto& thread : serverThreads) {
        if (thread.joinable() && thread.get_id() != boost::this_thread::get_id()) {
            thread.join();
        }
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
            auto socket = std::make_shared<boost::asio::ip::tcp::socket>(*ioContext);
            acceptor->accept(*socket);
            serverThreads.emplace_back([this, socket]() { handleClient(socket); });
        }
        catch (...) {}
    }
}

void ServerManager::handleClient(std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
    std::string clientId = socket->remote_endpoint().address().to_string() + ":" + std::to_string(socket->remote_endpoint().port());

    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        clients[clientId] = socket;
        clientsReady[clientId] = false;
        ++totalClients;
    }

    emit clientConnected(QString::fromStdString(clientId));
    emit logMessage("Client connected: " + QString::fromStdString(clientId));
    emit clientsStatusChanged();

    try {
        boost::asio::streambuf buffer;
        while (serverRunning && socket->is_open()) {
            boost::asio::read_until(*socket, buffer, "\n");
            std::istream is(&buffer);
            std::string message;
            std::getline(is, message);
            boost::algorithm::trim(message);

            if (message.find("Ready") == 0) {
                clientsMutex.lock();
                clientsReady[clientId] = true;
                clientsMutex.unlock();
                emit clientReadyStateChanged(QString::fromStdString(clientId), true);
                emit clientsStatusChanged();
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

        std::lock_guard<std::mutex> lock(clientsMutex);
        clients.erase(clientId);
        clientsReady.erase(clientId);
        --totalClients;

        emit clientsStatusChanged();
    }
}

std::unordered_map<std::string, bool> ServerManager::getConnectedClientsStatus() {
    return clientsReady;
}

void ServerManager::udpEchoServer() {
    char data[128];
    boost::asio::ip::udp::endpoint sender;

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
