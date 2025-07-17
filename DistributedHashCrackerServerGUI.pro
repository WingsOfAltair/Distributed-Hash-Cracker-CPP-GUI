QT       += core gui widgets

CONFIG   += c++17 console
CONFIG   -= app_bundle

TEMPLATE = app
TARGET = DistributedHashCrackerServerGUI

# ---- Source and Header Files ----
SOURCES += \
    main.cpp \
    gui/MainWindow.cpp \
    core/ServerManager.cpp \
    shared/AsyncLogger.cpp \
    shared/AsyncStorageLogger.cpp

HEADERS += \
    gui/MainWindow.h \
    core/ServerManager.h \
    shared/BaseAsyncLogger.h \
    shared/AsyncLogger.h \
    shared/AsyncStorageLogger.h \
    shared/BaseAsyncLogger.h

FORMS += gui/MainWindow.ui

# ---- Include Paths ----
INCLUDEPATH += \
    include \
    gui \
    core \
    shared \
    "C:/boost" \
    "C:/Program Files/OpenSSL-Win64/include"

# ---- Libraries ----
LIBS += -LC:/boost/lib64-msvc-14.3 \
        -lboost_thread-vc143-mt-x64-1_85 \
        -lboost_filesystem-vc143-mt-x64-1_85 \
        -lboost_locale-vc143-mt-x64-1_85

LIBS += -L"C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD" \
        -llibssl \
        -llibcrypto

# ---- Windows Target ----
DEFINES += _WIN32_WINNT=0x0601

# ---- MSVC-specific Compiler Flags ----
QMAKE_CXXFLAGS += /W4