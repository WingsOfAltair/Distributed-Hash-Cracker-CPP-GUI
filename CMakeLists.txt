cmake_minimum_required(VERSION 3.16)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

project(DistributedHashCrackerServerGUI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(WIN32)
# Set Qt path (same effect as -DCMAKE_PREFIX_PATH=...)
set(CMAKE_PREFIX_PATH "C:/Qt/6.9.1/msvc2022_64" CACHE PATH "Qt installation prefix path")
endif()

if(WIN32)
# Libsodium integration
set(SODIUM_INCLUDE_DIRS "${PROJECT_SOURCE_DIR}/include/scrypt")
set(SODIUM_LIBRARIES "${PROJECT_SOURCE_DIR}/include/scrypt/libsodium.lib")
endif()

# Find libsodium using pkg-config (only on UNIX)
if(UNIX)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED libsodium)
    include_directories(${SODIUM_INCLUDE_DIRS})
    link_directories(${SODIUM_LIBRARY_DIRS})
endif()

find_package(Qt6 REQUIRED COMPONENTS Widgets)     

set(SRC_DIR ${CMAKE_SOURCE_DIR})

file(GLOB_RECURSE SOURCES
    ${SRC_DIR}/include/*.cpp
    ${SRC_DIR}/main.cpp
    ${SRC_DIR}/gui/*.cpp
    ${SRC_DIR}/core/*.cpp
    ${SRC_DIR}/shared/*.cpp
)

qt_standard_project_setup()

link_directories(${CMAKE_SOURCE_DIR}/lib)

# ------------------------------
# Boost
# ------------------------------
find_package(Boost REQUIRED COMPONENTS system filesystem thread chrono locale)
if(Boost_FOUND)
    message(STATUS "Boost version: ${Boost_VERSION}")
    link_directories("C:/boost/lib64-msvc-14.3")
else()
    message(FATAL_ERROR "Boost not found")
endif()

# ------------------------------
# OpenSSL
# ------------------------------
find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    message(STATUS "OpenSSL include directory: ${OPENSSL_INCLUDE_DIR}")
else()
    message(FATAL_ERROR "OpenSSL not found")
endif()

# ------------------------------
# Windows-specific argon2 and bcrypt libs
# ------------------------------
if(WIN32)
    # Full path to argon2.lib
    set(ARGON2_LIB_PATH "${CMAKE_SOURCE_DIR}/include/argon2/argon2.lib")      
    set(BCRYPT_LIB_PATH "${CMAKE_SOURCE_DIR}/include/bcrypt/bcrypt.lib")

    # Check if file actually exists
    if(NOT EXISTS "${ARGON2_LIB_PATH}")
        message(FATAL_ERROR "argon2.lib not found at ${ARGON2_LIB_PATH}")
    endif()    

    if(NOT EXISTS "${BCRYPT_LIB_PATH}")
        message(FATAL_ERROR "bcrypt.lib not found at ${BCRYPT_LIB_PATH}")
    endif()
endif()

# ------------------------------
# Client executable
# ------------------------------
add_executable(DistributedHashCrackerClient 
    Distributed-Hash-Cracker-CPP-Client/Distributed-Hash-Cracker-CPP-Client.cpp
)

target_compile_definitions(DistributedHashCrackerClient PRIVATE SODIUM_STATIC)

target_include_directories(DistributedHashCrackerClient PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

if (WIN32)
target_link_libraries(DistributedHashCrackerClient PRIVATE 
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    "${BCRYPT_LIB_PATH}"
    "${ARGON2_LIB_PATH}"  
    ${SODIUM_LIBRARIES}  
)
else()
target_link_libraries(DistributedHashCrackerClient PRIVATE 
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    bcrypt
    argon2
    crypt      
    ${SODIUM_LIBRARIES}
)
endif()

# ------------------------------
# Server CLI executable
# ------------------------------
add_executable(DistributedHashCrackerServer 
    Distributed-Hash-Cracker-CPP/Distributed-Hash-Cracker-CPP-Server.cpp
)

target_link_libraries(DistributedHashCrackerServer PRIVATE 
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)

# ------------------------------
# Server GUI executable
# ------------------------------

include_directories(
    ${SRC_DIR}
    ${SRC_DIR}/include
    ${SRC_DIR}/gui
    ${SRC_DIR}/core
    ${SRC_DIR}/shared
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

qt_add_executable(DistributedHashCrackerServerGUI WIN32
    ${SOURCES}
    ${UIS_HDRS}
)

target_compile_definitions(DistributedHashCrackerServerGUI PRIVATE _WIN32_WINNT=0x0601)

# Use target_include_directories instead of global include_directories
target_include_directories(DistributedHashCrackerServerGUI PRIVATE
    ${SRC_DIR}/include
    ${SRC_DIR}/gui
    ${SRC_DIR}/core
    ${SRC_DIR}/shared
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

if (WIN32)
    target_link_libraries(DistributedHashCrackerServerGUI PRIVATE
        Qt6::Widgets
        ${Boost_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto
    )
else()
    target_link_libraries(DistributedHashCrackerServerGUI PRIVATE
        Qt6::Widgets
        ${Boost_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto
    )
endif()

# ------------------------------
# Copy DLLs and config files (Windows)
# ------------------------------
if(WIN32)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(BOOST_DLLS
            "C:/boost/lib64-msvc-14.3/boost_thread-vc143-mt-gd-x64-1_85.dll"
            "C:/boost/lib64-msvc-14.3/boost_filesystem-vc143-mt-gd-x64-1_85.dll"
            "C:/boost/lib64-msvc-14.3/boost_locale-vc143-mt-gd-x64-1_85.dll"

            "C:/boost/lib64-msvc-14.3/boost_thread-vc143-mt-x64-1_85.dll"
            "C:/boost/lib64-msvc-14.3/boost_filesystem-vc143-mt-x64-1_85.dll"
            "C:/boost/lib64-msvc-14.3/boost_locale-vc143-mt-x64-1_85.dll"
        )
    else()
        set(BOOST_DLLS
            "C:/boost/lib64-msvc-14.3/boost_thread-vc143-mt-gd-x64-1_85.dll"
            "C:/boost/lib64-msvc-14.3/boost_filesystem-vc143-mt-gd-x64-1_85.dll"
            "C:/boost/lib64-msvc-14.3/boost_locale-vc143-mt-gd-x64-1_85.dll"
            "C:/boost/lib64-msvc-14.3/boost_thread-vc143-mt-x64-1_85.dll"
            "C:/boost/lib64-msvc-14.3/boost_filesystem-vc143-mt-x64-1_85.dll"
            "C:/boost/lib64-msvc-14.3/boost_locale-vc143-mt-x64-1_85.dll"
        )
    endif()

    foreach(target DistributedHashCrackerServerGUI)
        foreach(dll ${BOOST_DLLS})
            add_custom_command(TARGET ${target} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different "${dll}" $<TARGET_FILE_DIR:${target}>
            )
        endforeach()
    endforeach()

    set(QT_PLUGINS_PLATFORM_DIR "${Qt6_DIR}/../../../plugins/platforms")

    add_custom_command(TARGET DistributedHashCrackerServerGUI POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:DistributedHashCrackerServerGUI>/platforms"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${QT_PLUGINS_PLATFORM_DIR}/qwindows.dll"
            "$<TARGET_FILE_DIR:DistributedHashCrackerServerGUI>/platforms"
    )

    set(QT_DLLS
        "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Widgetsd.dll"
        "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Guid.dll"
        "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Cored.dll"
        "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Widgets.dll"
        "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Gui.dll"
        "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Core.dll"
    )
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(QT_DLLS
            "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Widgetsd.dll"
            "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Guid.dll"
            "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Cored.dll"
            "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Widgets.dll"
            "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Gui.dll"
            "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Core.dll"
        )
    else()
        set(QT_DLLS
            "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Widgets.dll"
            "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Gui.dll"
            "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Core.dll"
            "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Widgetsd.dll"
            "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Guid.dll"
            "C:/Qt/6.9.1/msvc2022_64/bin/Qt6Cored.dll"
        )
    endif()

    foreach(dll ${QT_DLLS})
        add_custom_command(TARGET DistributedHashCrackerServerGUI POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${dll}"
                $<TARGET_FILE_DIR:DistributedHashCrackerServerGUI>
        )
    endforeach()

    add_custom_command(TARGET DistributedHashCrackerClient POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/include/argon2/argon2.dll"
            "$<TARGET_FILE_DIR:DistributedHashCrackerClient>"
    )             
    add_custom_command(TARGET DistributedHashCrackerClient POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/include/scrypt/libsodium.dll"
            "$<TARGET_FILE_DIR:DistributedHashCrackerClient>"
    )

endif()

set(CONFIG_SRC_DIR "${CMAKE_SOURCE_DIR}/resources")
set(CONFIG_FILES config.ini server.ini wordlist.txt mutation_list.txt mutation_list_generator_upto_n_times.py)

foreach(FILE ${CONFIG_FILES})
    foreach(target DistributedHashCrackerClient DistributedHashCrackerServerGUI)
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CONFIG_SRC_DIR}/${FILE}" $<TARGET_FILE_DIR:${target}>
        )
    endforeach()
endforeach()