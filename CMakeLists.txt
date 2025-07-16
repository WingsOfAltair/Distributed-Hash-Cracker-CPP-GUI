cmake_minimum_required(VERSION 3.16)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

project(DistributedHashCrackerServerGUI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find libsodium using pkg-config
if(UNIX)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED libsodium)
    include_directories(${SODIUM_INCLUDE_DIRS})
    link_directories(${SODIUM_LIBRARY_DIRS})
endif()

find_package(Qt6 REQUIRED COMPONENTS Widgets)     

set(SRC_DIR ${CMAKE_SOURCE_DIR})

include_directories(
    ${SRC_DIR}/include
    ${SRC_DIR}/gui
    ${SRC_DIR}/core
    ${SRC_DIR}/shared
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

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
# Include internal headers
# ------------------------------
include_directories(${CMAKE_SOURCE_DIR}/include)

# ------------------------------
# Boost
# ------------------------------
find_package(Boost REQUIRED COMPONENTS system filesystem thread chrono locale)
if(Boost_FOUND)
    message(STATUS "Boost version: ${Boost_VERSION}")
    include_directories(${Boost_INCLUDE_DIRS})
    link_directories("C:/boost/lib64-msvc-14.3")
else()
    message(FATAL_ERROR "Boost not found")
endif()

# ------------------------------
# OpenSSL
# ------------------------------
find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
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

    # Check if file actually exists
    if(NOT EXISTS "${BCRYPT_LIB_PATH}")
        message(FATAL_ERROR "bcrypt.lib not found at ${BCRYPT_LIB_PATH}")
    endif()
endif()

# ------------------------------
# Build scrypt static library from source files
# ------------------------------

file(GLOB_RECURSE SCRYPT_SRC
    ${CMAKE_SOURCE_DIR}/include/scrypt/*.c
)

# Exclude ARM-only test files that break build on non-ARM systems
# Remove ARM and X86-specific files
foreach(cpu_file ${SCRYPT_SRC})
    if(cpu_file MATCHES ".*(ARM|X86|RDRAND).*\\.c$")
        message(STATUS "Excluding CPU-specific file: ${cpu_file}")
        list(REMOVE_ITEM SCRYPT_SRC ${cpu_file})
    endif()
endforeach()

add_library(scrypt STATIC ${SCRYPT_SRC})

target_compile_definitions(scrypt PUBLIC HAVE_CONFIG_H)

target_include_directories(scrypt PUBLIC
    ${CMAKE_SOURCE_DIR}/include/scrypt   
    ${CMAKE_SOURCE_DIR}/include/scrypt/lib-platform/crypto
    ${CMAKE_SOURCE_DIR}/include/scrypt/lib-platform/util
    ${CMAKE_SOURCE_DIR}/include/scrypt/lib-platform   
    ${CMAKE_SOURCE_DIR}/include/scrypt/libcperciva       
    ${CMAKE_SOURCE_DIR}/include/scrypt/libcperciva/alg   
    ${CMAKE_SOURCE_DIR}/include/scrypt/libcperciva/cpusupport   
    ${CMAKE_SOURCE_DIR}/include/scrypt/libcperciva/crypto     
    ${CMAKE_SOURCE_DIR}/include/scrypt/libcperciva/POSIX
    ${CMAKE_SOURCE_DIR}/include/scrypt/libcperciva/util
    ${CMAKE_SOURCE_DIR}/include/scrypt/lib
)

# Ensure warnp.c is included
list(APPEND SCRYPT_SRC
    ${CMAKE_SOURCE_DIR}/include/scrypt/libcperciva/util/warnp.c
)

# ------------------------------
# Server executable
# ------------------------------
qt_add_executable(DistributedHashCrackerServerGUI
    ${SOURCES}
    ${UIS_HDRS}
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
    set(BOOST_DLLS
        "C:/boost/lib64-msvc-14.3/boost_thread-vc143-mt-gd-x64-1_85.dll"
        "C:/boost/lib64-msvc-14.3/boost_filesystem-vc143-mt-gd-x64-1_85.dll"
        "C:/boost/lib64-msvc-14.3/boost_locale-vc143-mt-gd-x64-1_85.dll"
    )

    foreach(target DistributedHashCrackerServerGUI)
        foreach(dll ${BOOST_DLLS})
            add_custom_command(TARGET ${target} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different "${dll}" $<TARGET_FILE_DIR:${target}>
            )
        endforeach()
    endforeach()
endif()