// MainWindow.h
#pragma once

#include <QMainWindow>
#include <QTimer>
#include <QString>
#include <QListWidgetItem>
#include "core/ServerManager.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

protected:
    void closeEvent(QCloseEvent* event) override;

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

private slots:
    void stopServer();
    void reloadClients();
    void checkHashType();
    void sendHash();
    void onClientConnected(const QString&);
    void onClientReadyStateChanged(const QString&, bool);
    void onLogMessage(const QString&);
    void RefreshList();
    void TurnOnCracking();
    void TurnOffCracking();
    void TurnOffCrackingNotStop();
    void TurnOffCrackingZeroClients();
    void showClientContextMenu(const QPoint &pos);

private:
    Ui::MainWindow* ui;
    ServerManager* serverManager;
    void updateClientList();
};
