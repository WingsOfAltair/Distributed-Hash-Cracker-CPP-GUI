cmake_minimum_required(VERSION 3.30.4)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

project(ScrutaNet-Server-GUI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(SRC_DIR ${CMAKE_SOURCE_DIR})
set(RESOURCE_FILE "${SRC_DIR}/resources/resources.qrc")

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

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)     

file(GLOB_RECURSE SOURCES
    ${SRC_DIR}/include/*.cpp
    ${SRC_DIR}/main.cpp
    ${SRC_DIR}/gui/*.cpp
    ${SRC_DIR}/core/*.cpp
    ${SRC_DIR}/shared/*.cpp
)

qt_add_resources(RESOURCE_SOURCES
    ${RESOURCE_FILE}
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
add_executable(ScrutaNet-Client-CLI 
    ScrutaNet-Client-CLI/ScrutaNet-Client-CLI.cpp
)

target_compile_definitions(ScrutaNet-Client-CLI PRIVATE SODIUM_STATIC)

target_include_directories(ScrutaNet-Client-CLI PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

if (WIN32)
target_link_libraries(ScrutaNet-Client-CLI PRIVATE 
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    "${BCRYPT_LIB_PATH}"
    "${ARGON2_LIB_PATH}"  
    ${SODIUM_LIBRARIES}  
)
else()
target_link_libraries(ScrutaNet-Client-CLI PRIVATE 
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
add_executable(ScrutaNet-Server-CLI 
    ScrutaNet-Server-CLI/ScrutaNet-Server-CLI.cpp
)

target_link_libraries(ScrutaNet-Server-CLI PRIVATE 
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

if (WIN32)
    set(WINDOWS_ICON_RESOURCE "${SRC_DIR}/resources/app_icon.rc")
    qt_add_executable(ScrutaNet-Server-GUI WIN32
        ${SOURCES}
        ${UIS_HDRS}
        ${RESOURCE_SOURCES}
        ${WINDOWS_ICON_RESOURCE}
    )
else()
    qt_add_executable(ScrutaNet-Server-GUI WIN32
        ${SOURCES}
        ${UIS_HDRS}
        ${RESOURCE_SOURCES}
    )
endif()

target_compile_definitions(ScrutaNet-Server-GUI PRIVATE _WIN32_WINNT=0x0601)

# Use target_include_directories instead of global include_directories
target_include_directories(ScrutaNet-Server-GUI PRIVATE
    ${SRC_DIR}/include
    ${SRC_DIR}/gui
    ${SRC_DIR}/core
    ${SRC_DIR}/shared
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

if (WIN32)
    target_link_libraries(ScrutaNet-Server-GUI PRIVATE
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        ${Boost_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto
    )
else()
    target_link_libraries(ScrutaNet-Server-GUI PRIVATE
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

    foreach(target ScrutaNet-Server-GUI)
        foreach(dll ${BOOST_DLLS})
            add_custom_command(TARGET ${target} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different "${dll}" $<TARGET_FILE_DIR:${target}>
            )
        endforeach()
    endforeach()

    get_target_property(QtCore_location Qt6::Core IMPORTED_LOCATION_RELEASE)
    get_filename_component(QtCore_bin_dir "${QtCore_location}" DIRECTORY)
    
    # Create the platforms directory once
    add_custom_command(TARGET ScrutaNet-Server-GUI POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:ScrutaNet-Server-GUI>/platforms"
    )

    # Debug config: copy qwindowsd.dll
    add_custom_command(TARGET ScrutaNet-Server-GUI POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${QtCore_bin_dir}/../plugins/platforms/qwindowsd.dll"
            "$<TARGET_FILE_DIR:ScrutaNet-Server-GUI>/platforms/qwindowsd.dll"
        COMMENT "Copying qwindowsd.dll for Debug"
        CONFIGURATIONS Debug
    )

    # Release config: copy qwindows.dll
    add_custom_command(TARGET ScrutaNet-Server-GUI POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${QtCore_bin_dir}/../plugins/platforms/qwindows.dll"
            "$<TARGET_FILE_DIR:ScrutaNet-Server-GUI>/platforms/qwindows.dll"
        COMMENT "Copying qwindows.dll for Release"
        CONFIGURATIONS Release
    )

    set(QT_DLLS
        "Qt6Widgets.dll"
        "Qt6Gui.dll"
        "Qt6Core.dll"
        "Qt6Widgetsd.dll"
        "Qt6Guid.dll"
        "Qt6Cored.dll"
    )

    foreach(dll ${QT_DLLS})
        add_custom_command(TARGET ScrutaNet-Server-GUI POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${QtCore_bin_dir}/${dll}"
                $<TARGET_FILE_DIR:ScrutaNet-Server-GUI>
        )
    endforeach()

    add_custom_command(TARGET ScrutaNet-Client-CLI POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/include/argon2/argon2.dll"
            "$<TARGET_FILE_DIR:ScrutaNet-Client-CLI>"
    )             
    add_custom_command(TARGET ScrutaNet-Client-CLI POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/include/scrypt/libsodium.dll"
            "$<TARGET_FILE_DIR:ScrutaNet-Client-CLI>"
    )
elseif(UNIX)
    # Linux: copy libqxcb.so
    get_target_property(QtCore_imported_location Qt6::Core IMPORTED_LOCATION_RELEASE)
    get_filename_component(QtCore_lib_dir "${QtCore_imported_location}" DIRECTORY)
    get_filename_component(Qt_plugins_dir "${QtCore_lib_dir}/../plugins/platforms" ABSOLUTE)
    set(PLATFORM_PLUGIN_FOLDER "/usr/lib/x86_64-linux-gnu/qt6/plugins/platforms")
    set(PLATFORM_PLUGIN "libqxcb.so")

    add_custom_command(TARGET ScrutaNet-Server-GUI POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:ScrutaNet-Server-GUI>/platforms"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${PLATFORM_PLUGIN_FOLDER}/${PLATFORM_PLUGIN}"
            "$<TARGET_FILE_DIR:ScrutaNet-Server-GUI>/platforms"
    )
endif()

set(CONFIG_SRC_DIR "${CMAKE_SOURCE_DIR}/resources")
set(CONFIG_FILES config.ini server.ini wordlist.txt mutation_list.txt mutation_list_generator_upto_n_times.py)

foreach(FILE ${CONFIG_FILES})
    foreach(target ScrutaNet-Client-CLI ScrutaNet-Server-GUI)
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CONFIG_SRC_DIR}/${FILE}" $<TARGET_FILE_DIR:${target}>
        )
    endforeach()
endforeach()

############################
### ICON SETUP FOR LINUX ###
############################

# Paths to your resources
set(APP_ICON_SOURCE "${CMAKE_SOURCE_DIR}/resources/icons/appicon.png")
set(DESKTOP_FILE_SOURCE "${CMAKE_SOURCE_DIR}/resources/scrutanet.desktop.in")  # template desktop file

# Executable info
set(EXECUTABLE_NAME "ScrutaNet-Server-GUI")          # your executable target name
set(INSTALL_BIN_DIR "bin")                            # relative to install prefix
set(INSTALL_ICON_NAME "scrutanet")                    # icon base name (without extension)

# Full executable path for desktop Exec= entry
set(EXECUTABLE_PATH "${CMAKE_INSTALL_PREFIX}/${INSTALL_BIN_DIR}/${EXECUTABLE_NAME}")

# Configure the desktop file (replace placeholders)
configure_file(
    "${DESKTOP_FILE_SOURCE}"
    "${CMAKE_CURRENT_BINARY_DIR}/scrutanet.desktop"
    @ONLY
)

# Install executable (assumes target already defined)
install(TARGETS ${EXECUTABLE_NAME}
    RUNTIME DESTINATION ${INSTALL_BIN_DIR}
)

# Install icon to icon theme directory with rename
install(FILES ${APP_ICON_SOURCE}
    DESTINATION "${CMAKE_INSTALL_PREFIX}/share/icons/hicolor/64x64/apps"
    RENAME "${INSTALL_ICON_NAME}.png"
)

# Install the configured desktop file
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/scrutanet.desktop"
    DESTINATION "${CMAKE_INSTALL_PREFIX}/share/applications"
)