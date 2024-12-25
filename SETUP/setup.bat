@echo off
set "SCRIPT_DIR=%~dp0"
set "OS_DIR=%SCRIPT_DIR%..\OS"

if "%1" == "install" (
    cd /d "%OS_DIR%" || (echo OS directory not found & exit /b 1)
    docker build -t p0f .
    echo Docker image 'p0f' built successfully.
) else if "%1" == "remove" (
    docker rmi -f p0f
    echo Docker image 'p0f' removed successfully.
) else (
    echo Usage: %~nx0 {install^|remove}
)