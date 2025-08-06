@echo off
REM Build script for flatten on Windows
REM Usage: build.bat [version]

setlocal enabledelayedexpansion

set VERSION=%1
if "%VERSION%"=="" set VERSION=dev

set BINARY_NAME=flatten
set BUILD_DIR=build
set PKG_PATH=./cmd/flatten

echo Building %BINARY_NAME% version: %VERSION%

REM Clean build directory
if exist %BUILD_DIR% rmdir /s /q %BUILD_DIR%
mkdir %BUILD_DIR%

REM Platform and architecture combinations for Windows
set PLATFORMS=windows/amd64 windows/386 windows/arm64 linux/amd64 linux/386 linux/arm64 linux/arm darwin/amd64 darwin/arm64

for %%P in (%PLATFORMS%) do (
    for /f "tokens=1,2 delims=/" %%A in ("%%P") do (
        set GOOS=%%A
        set GOARCH=%%B
        
        set OUTPUT_NAME=%BINARY_NAME%-%VERSION%-%%A-%%B
        
        if "%%A"=="windows" (
            set OUTPUT_NAME=!OUTPUT_NAME!.exe
        )
        
        set OUTPUT_PATH=%BUILD_DIR%\!OUTPUT_NAME!
        
        echo Building for %%A/%%B...
        
        set CGO_ENABLED=0
        set GOOS=%%A
        set GOARCH=%%B
        
        go build -ldflags="-s -w -X main.version=%VERSION%" -o !OUTPUT_PATH! %PKG_PATH%
        
        if !errorlevel! equ 0 (
            echo Built: !OUTPUT_NAME!
        ) else (
            echo Failed to build for %%A/%%B
            exit /b 1
        )
    )
)

echo Build complete! Artifacts are in the %BUILD_DIR% directory.
