@echo off
setlocal

:: CONFIGURE THESE PATHS ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
set QT_PATH=C:\Qt\6.9.1\msvc2022_64\lib\cmake
set BUILD_TYPE=Release

:: Optional: vcpkg toolchain
:: set VCPKG_TOOLCHAIN=C:/vcpkg/scripts/buildsystems/vcpkg.cmake

:: CLEAN OLD BUILD
if exist build rmdir /s /q build
mkdir build
cd build

:: GENERATE PROJECT FILES
cmake .. -G "NMake Makefiles" ^
  -DCMAKE_PREFIX_PATH=%QT_PATH% ^
  -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
  :: -DCMAKE_TOOLCHAIN_FILE=%VCPKG_TOOLCHAIN%  (uncomment if using vcpkg)

:: COMPILE
nmake

cd ..
echo.
echo ✅ Build complete.
echo Output: build\\DistributedHashCrackerServerGUI.exe
pause