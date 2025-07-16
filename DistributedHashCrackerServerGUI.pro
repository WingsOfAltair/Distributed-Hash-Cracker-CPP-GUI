QT       += core gui widgets

CONFIG   += c++17 console
CONFIG   -= app_bundle    # Not for macOS app bundle

TEMPLATE = app
TARGET = DistributedHashCrackerServerGUI

# Include your source and header files here
SOURCES += \
    main.cpp \
    gui/MainWindow.cpp \
    core/ServerManager.cpp \
    shared/AsyncLogger.cpp \
    shared/AsyncStorageLogger.cpp


HEADERS += \
    gui/MainWindow.h \
    core/ServerManager.h \
    shared/SomeSharedFile.h \
    shared/BaseAsyncLogger.h \
    shared/AsyncLogger.h \
    shared/AsyncStorageLogger.h

# Include directories
INCLUDEPATH += \
    include \
    gui \
    core \
    shared

# Boost and OpenSSL include dirs (adjust paths)
INCLUDEPATH += C:/boost/include
INCLUDEPATH += C:/Program\ Files/OpenSSL-Win64/include

# Link libraries (adjust paths and names)
LIBS += -LC:/boost/lib64-msvc-14.3 -lboost_thread-vc143-mt-x64-1_85 \
        -LC:/Program\ Files/OpenSSL-Win64/lib/VC/x64/MD -llibssl -llibcrypto

# Define Windows version target
DEFINES += _WIN32_WINNT=0x0601

# Compiler flags (optional)
QMAKE_CXXFLAGS += -Wall -Wextra

# For deployment, you can add a post-build step to copy DLLs or plugins if needed
