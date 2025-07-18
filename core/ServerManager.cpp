// ServerManager.cpp
#include "ServerManager.h"
#include <boost/algorithm/string/trim.hpp>
#include <fstream>
#include <iostream>
#include <sstream>
#include <chrono>
#include <boost/filesystem.hpp>

AsyncLogger serverLogger("server.txt");
AsyncStorageLogger crackedLogger("cracked.txt");

int SERVER_PORT = 0;

auto start = std::chrono::high_resolution_clock::now();
auto end = std::chrono::high_resolution_clock::now();

// Read config file
std::map<std::string, std::string> readConfig(const std::string& filename) {
    std::map<std::string, std::string> configMap;
    boost::filesystem::path fullPath = boost::filesystem::absolute(filename);
    std::ifstream configFile(fullPath.string());

    if (boost::filesystem::exists(fullPath)) {
        std::string line;
        while (std::getline(configFile, line)) {
            size_t delimiterPos = line.find('=');
            if (delimiterPos != std::string::npos) {
                std::string key = line.substr(0, delimiterPos);
                std::string value = line.substr(delimiterPos + 1);
                configMap[key] = value;
            }
        }
        configFile.close();
    }
    else {
        std::cerr << "Config file does not exist.\n";
    }

    return configMap;
}

ServerManager::ServerManager(QObject* parent) : QObject(parent) {
    readCrackedHashes("cracked.txt");
    //auto config = readConfig("server.ini");
    //SERVER_PORT = std::stoi(config["SERVER_PORT"]);
    startServer(1337);
}

ServerManager::~ServerManager() {
    //stopServer();
}

void ServerManager::logServer(const std::string& message) {
    serverLogger.log(message);
}

void ServerManager::asyncAcceptClient() {
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(*ioContext);

    acceptor->async_accept(*socket, [this, socket](const boost::system::error_code& ec) {
        if (!serverRunning || ec == boost::asio::error::operation_aborted)
            return;

        if (!ec) {
            std::thread(&ServerManager::handleClient, this, socket).detach();
        } else {
            emit logMessage("Accept error: " + QString::fromStdString(ec.message()));
            logServer(std::string("Accept error: ") + ec.message());
        }

        // Start accepting the next client immediately
        asyncAcceptClient();
    });
}

void ServerManager::StopCrackingClients() {
    this->notifyStopAll();
}

void ServerManager::udpEchoServer() {
    // Already initialized in startServer()
    if (!udpSocket || !udpSocket->is_open()) {
        emit logMessage("UDP socket is not open.");
        return;
    }

    char data[128];  // buffer for incoming data
    boost::asio::ip::udp::endpoint sender_endpoint;

    std::cout << "Ping echo server is listening on port " << serverPort << " UDP..." << std::endl;

    while (serverRunning) {
        boost::system::error_code ec;

        std::size_t length = udpSocket->receive_from(
            boost::asio::buffer(data), sender_endpoint, 0, ec
            );

        if (ec && ec != boost::asio::error::message_size) {
            emit logMessage("Receive error: " + QString::fromStdString(ec.message()));
            logServer(std::string("Receive error: ") + ec.message());
            continue;
        }

        QString msg = "Received: " +
                      QString::fromStdString(std::string(data, length)) +
                      " from " +
                      QString::fromStdString(sender_endpoint.address().to_string()) +
                      ":" +
                      QString::number(sender_endpoint.port());
        emit logMessage(msg);

        logServer(msg.toStdString());

        // Send response
        std::string response = "pong";
        udpSocket->send_to(boost::asio::buffer(response), sender_endpoint, 0, ec);
        if (ec) {
            emit logMessage("Send error: " + QString::fromStdString(ec.message()));
        }
    }
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

    std::thread([this]() {
        udpEchoServer();
    }).detach();

    std::thread([this]() {
        asyncAcceptClient();
    }).detach();

    serverThreads.emplace_back([this]() {
        try {
            ioContext->run();  // 🧵 Blocking run loop
        } catch (const std::exception& ex) {
            emit logMessage("io_context exception: " + QString::fromStdString(ex.what()));
            logServer(std::string("io_context exception: ") + ex.what());
        }
    });

    emit logMessage("Server started on port " + QString::number(port));
    logServer("Server started on port " + std::to_string(port));
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
    logServer(std::string("Server stopped."));
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
        emit clientsStatusChanged();
    }

    emit clientConnected(QString::fromStdString(clientId));
    emit logMessage("Client connected: " + QString::fromStdString(clientId));
    logServer(std::string("Client connected: ") + clientId);
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
                auto end = std::chrono::high_resolution_clock::now();
                std::chrono::duration<double, std::milli> duration_ms = end - start;

                std::string match_info = message.substr(6); // Remove "MATCH:"
                logServer("Match: " + match_info + " by Client " + clientId + " Elapsed time: " + std::to_string(duration_ms.count()) + " ms.");
                matchFound = true;
                currentPassword = QString::fromStdString(message.substr(6)).split(' ').first();
                bool found = false;
                for (const auto& pair : crackedHashes) {
                    if (std::get<0>(pair) == currentHash && std::get<1>(pair) == currentSalt) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    crackedHashes.emplace_back(currentHash, currentSalt, currentPassword);
                    crackedLogger.log(currentHash.toStdString() + ":" + currentSalt.toStdString() + ":" + currentPassword.toStdString());
                }
                emit logMessage("Match from " + QString::fromStdString(clientId) + ": " + currentPassword);
                emit logMessage("Match: " + QString::fromStdString(match_info) +
                                " by Client " + QString::fromStdString(clientId) +
                                " Elapsed time: " + QString::number(duration_ms.count(), 'f', 3) + " ms.");
                this->StopCrackingClients();
            }
        }
    }
    catch (...) {
        emit logMessage("Client disconnected: " + QString::fromStdString(clientId));
        logServer(std::string("Client disconnected: ") + clientId);

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

void ServerManager::sendHashToClients(const QString& hashType, const QString& hash, const QString& salt) {
    start = std::chrono::high_resolution_clock::now();
    currentHashType = hashType;
    currentHash = hash;
    currentSalt = salt;
    matchFound = false;
    clientsResponded = 0;
    QString decoded;
    emit StartCracking();

    bool found = false;
    for (const auto& pair : crackedHashes) {
        if (std::get<0>(pair) == currentHash && std::get<1>(pair) == currentSalt) {
            found = true;
            decoded = std::get<2>(pair);
            break;
        }
    }
    if (found) {
        serverLogger.log("Found pre-cracked Hash: " + currentHash.toStdString() +
                         " Salt: " + currentSalt.toStdString() +
                         " Decoded: " + decoded.toStdString());

        emit logMessage("Found pre-cracked Hash: " + currentHash +
                        " Salt: " + currentSalt +
                        " Decoded: " + decoded);
        emit StopCracking();
    } else {
        notifyClients();
    }
}

void ServerManager::notifyClients() {
    std::string msg = currentHashType.toStdString() + ":" + currentHash.toStdString();
    if (!currentSalt.isEmpty()) msg += ":" + currentSalt.toStdString();
    msg += "\n";

    emit logMessage("Processing entered hash, please wait...");
    std::lock_guard<std::mutex> lock(clientsMutex);
    for (auto& [id, socket] : clients) {
        if (clientsReady[id] && socket && socket->is_open()) {
            try {
                boost::asio::write(*socket, boost::asio::buffer(msg));
                clientsReady[id] = false;

                emit clientsStatusChanged();
            }
            catch (...) {
                emit logMessage("Failed to notify client: " + QString::fromStdString(id));
                logServer(std::string("Failed to notify client: ") + id);
            }
        }
    }
}

void ServerManager::notifyStopAll() {
    std::lock_guard<std::mutex> lock(clientsMutex);
    for (const auto& [client_id, is_ready] : clientsReady) {
        if (!is_ready) {
            auto it = clients.find(client_id);
            if (it != clients.end() && it->second && it->second->is_open()) {
                try {
                    boost::asio::write(*it->second, boost::asio::buffer("STOP\n"));
                } catch (const boost::system::system_error& e) {
                    std::cerr << "Failed to send reload to client " << client_id << ": " << e.what() << "\n";
                }
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
                logServer(std::string("Failed to reload client: ") + id);
            }
        }
    }
}
