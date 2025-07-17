/********************************************************************************
** Form generated from reading UI file 'MainWindow.ui'
**
** Created by: Qt User Interface Compiler version 6.9.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralwidget;
    QVBoxLayout *verticalLayout;
    QGroupBox *groupBoxHash;
    QFormLayout *formLayout;
    QLabel *labelHashType;
    QComboBox *comboBoxHashType;
    QLabel *labelHash;
    QLineEdit *lineEditHash;
    QLabel *labelSalt;
    QLineEdit *lineEditSalt;
    QPushButton *buttonSendHash;
    QPushButton *checkHashType;
    QGroupBox *groupBoxClients;
    QVBoxLayout *vboxLayout;
    QListWidget *listWidgetClients;
    QPushButton *buttonReload;
    QGroupBox *groupBoxLogs;
    QVBoxLayout *vboxLayout1;
    QTextEdit *textEditLogs;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName("MainWindow");
        MainWindow->resize(800, 600);
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName("centralwidget");
        verticalLayout = new QVBoxLayout(centralwidget);
        verticalLayout->setObjectName("verticalLayout");
        groupBoxHash = new QGroupBox(centralwidget);
        groupBoxHash->setObjectName("groupBoxHash");
        formLayout = new QFormLayout(groupBoxHash);
        formLayout->setObjectName("formLayout");
        labelHashType = new QLabel(groupBoxHash);
        labelHashType->setObjectName("labelHashType");

        formLayout->setWidget(0, QFormLayout::ItemRole::LabelRole, labelHashType);

        comboBoxHashType = new QComboBox(groupBoxHash);
        comboBoxHashType->setObjectName("comboBoxHashType");

        formLayout->setWidget(0, QFormLayout::ItemRole::FieldRole, comboBoxHashType);

        labelHash = new QLabel(groupBoxHash);
        labelHash->setObjectName("labelHash");

        formLayout->setWidget(1, QFormLayout::ItemRole::LabelRole, labelHash);

        lineEditHash = new QLineEdit(groupBoxHash);
        lineEditHash->setObjectName("lineEditHash");

        formLayout->setWidget(1, QFormLayout::ItemRole::FieldRole, lineEditHash);

        labelSalt = new QLabel(groupBoxHash);
        labelSalt->setObjectName("labelSalt");

        formLayout->setWidget(2, QFormLayout::ItemRole::LabelRole, labelSalt);

        lineEditSalt = new QLineEdit(groupBoxHash);
        lineEditSalt->setObjectName("lineEditSalt");

        formLayout->setWidget(2, QFormLayout::ItemRole::FieldRole, lineEditSalt);

        buttonSendHash = new QPushButton(groupBoxHash);
        buttonSendHash->setObjectName("buttonSendHash");

        formLayout->setWidget(3, QFormLayout::ItemRole::FieldRole, buttonSendHash);

        checkHashType = new QPushButton(groupBoxHash);
        checkHashType->setObjectName("checkHashType");

        formLayout->setWidget(4, QFormLayout::ItemRole::FieldRole, checkHashType);


        verticalLayout->addWidget(groupBoxHash);

        groupBoxClients = new QGroupBox(centralwidget);
        groupBoxClients->setObjectName("groupBoxClients");
        vboxLayout = new QVBoxLayout(groupBoxClients);
        vboxLayout->setObjectName("vboxLayout");
        listWidgetClients = new QListWidget(groupBoxClients);
        listWidgetClients->setObjectName("listWidgetClients");

        vboxLayout->addWidget(listWidgetClients);

        buttonReload = new QPushButton(groupBoxClients);
        buttonReload->setObjectName("buttonReload");

        vboxLayout->addWidget(buttonReload);


        verticalLayout->addWidget(groupBoxClients);

        groupBoxLogs = new QGroupBox(centralwidget);
        groupBoxLogs->setObjectName("groupBoxLogs");
        vboxLayout1 = new QVBoxLayout(groupBoxLogs);
        vboxLayout1->setObjectName("vboxLayout1");
        textEditLogs = new QTextEdit(groupBoxLogs);
        textEditLogs->setObjectName("textEditLogs");
        textEditLogs->setReadOnly(true);

        vboxLayout1->addWidget(textEditLogs);


        verticalLayout->addWidget(groupBoxLogs);

        MainWindow->setCentralWidget(centralwidget);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "Distributed Hash Cracker - Server", nullptr));
        groupBoxHash->setTitle(QCoreApplication::translate("MainWindow", "Hash Input", nullptr));
        labelHashType->setText(QCoreApplication::translate("MainWindow", "Hash Type:", nullptr));
        labelHash->setText(QCoreApplication::translate("MainWindow", "Hash:", nullptr));
        labelSalt->setText(QCoreApplication::translate("MainWindow", "Salt:", nullptr));
        buttonSendHash->setText(QCoreApplication::translate("MainWindow", "Send to Clients", nullptr));
        checkHashType->setText(QCoreApplication::translate("MainWindow", "Check Hash Type", nullptr));
        groupBoxClients->setTitle(QCoreApplication::translate("MainWindow", "Connected Clients", nullptr));
        buttonReload->setText(QCoreApplication::translate("MainWindow", "Reload Clients", nullptr));
        groupBoxLogs->setTitle(QCoreApplication::translate("MainWindow", "Logs", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
