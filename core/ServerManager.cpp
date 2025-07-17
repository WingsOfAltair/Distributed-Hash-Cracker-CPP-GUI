// ServerManager.cpp
#include "ServerManager.h"
#include <boost/algorithm/string/trim.hpp>
#include <fstream>
#include <iostream>
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
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(*ioContext);

    acceptor->async_accept(*socket, [this, socket](const boost::system::error_code& ec) {
        if (!serverRunning || ec == boost::asio::error::operation_aborted)
            return;

        if (!ec) {
            std::thread(&ServerManager::handleClient, this, socket).detach();
        } else {
            emit logMessage("Accept error: " + QString::fromStdString(ec.message()));
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
            continue;
        }

        emit logMessage("Received: " +
                        QString::fromStdString(std::string(data, length)) +
                        " from " +
                        QString::fromStdString(sender_endpoint.address().to_string()) +
                        ":" +
                        QString::number(sender_endpoint.port()));

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
                this->StopCrackingClients();
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

void ServerManager::sendHashToClients(const QString& hashType, const QString& hash, const QString& salt) {
    currentHashType = hashType;
    currentHash = hash;
    currentSalt = salt;
    matchFound = false;
    clientsResponded = 0;
    notifyClients();

    /*bool found = false;
    for (const auto& [stored_hash, stored_salt, decoded] : cracked_hashes_storage) {
        if (stored_hash == hash && stored_salt == salt) {
            std::cout << "Found pre-cracked Hash: " << stored_hash
                      << " Salt: " << stored_salt
                      << " Decoded: " << decoded << std::endl;

            logger.log("Found pre-cracked Hash: " + stored_hash +
                       " Salt: " + stored_salt +
                       " Decoded: " + decoded);

            found = true;
            break;
        }
    }

    if (!found) {
        notifyClients();
    }*/
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

                emit clientsStatusChanged();
            }
            catch (...) {
                emit logMessage("Failed to notify client: " + QString::fromStdString(id));
            }
        }
    }
}

void ServerManager::notifyStopAll() {
    emit StopCracking();

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
            }
        }
    }
}
