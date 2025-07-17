// ServerManager.h
#pragma once

#include <QObject>
#include <QThread>
#include <QMap>
#include <QString>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <atomic>
#include <boost/asio.hpp>
#include <boost/thread.hpp>

class ServerManager : public QObject {
    Q_OBJECT

public:
    explicit ServerManager(QObject* parent = nullptr);
    ~ServerManager();

    void startServer(int port);
    void stopServer();
    void sendHashToClients(const QString& hashType, const QString& hash, const QString& salt);
    void reloadClients();
    void asyncAcceptClient();
    void asyncUdpReceive();
    void StopCrackingClients();
    std::unordered_map<std::string, bool> getConnectedClientsStatus();

    std::vector<char> udpSocketBuffer;
    boost::asio::ip::udp::endpoint udpSender;
    std::optional<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> workGuard;

signals:
    void clientConnected(const QString& clientId);
    void clientReadyStateChanged(const QString& clientId, bool isReady);
    void logMessage(const QString& message);
    void clientsStatusChanged();
    void StopCracking();

private:
    std::unique_ptr<boost::asio::io_context> ioContext;
    std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor;
    std::unique_ptr<boost::asio::ip::udp::socket> udpSocket;
    std::unordered_map<std::string, std::shared_ptr<boost::asio::ip::tcp::socket>> clients;
    std::unordered_map<std::string, bool> clientsReady;
    std::mutex clientsMutex;
    std::atomic<bool> serverRunning{ false };
    std::atomic<bool> matchFound{ false };
    std::atomic<int> clientsResponded{ 0 };
    int totalClients = 0;
    int serverPort = 0;

    QString currentHashType;
    QString currentHash;
    QString currentSalt;
    QString currentPassword;

    std::vector<std::tuple<QString, QString, QString>> crackedHashes;
    std::vector<boost::thread> serverThreads;

    void acceptClients();
    void handleClient(std::shared_ptr<boost::asio::ip::tcp::socket> socket);
    void udpEchoServer();

    void readCrackedHashes(const QString& file);
    void notifyClients();
    void notifyStopAll();
};
