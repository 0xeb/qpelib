@echo off

:: checkout the Batchography book

setlocal

if not exist build cmake -B build -A Win32
if not exist build64 cmake -B build64 -A x64

if "%1"=="build" (
    cmake --build build --config Release
    cmake --build build64 --config Release
)

echo.
echo All done!
echo.