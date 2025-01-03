@echo off
setlocal enabledelayedexpansion
echo Checking For Update...
echo Downloading Update In Desktop
curl -g -k -L -# -o "%temp%\repo.zip" https://github.com/shubhamgupta1024/Software-and-tweaks/archive/refs/heads/main.zip
if %errorlevel% neq 0 (
    echo Failed to download the repository.
    pause
    exit /b 1
)
powershell -NoProfile Expand-Archive '%temp%\repo.zip' -DestinationPath 'C:\bat\' >nul 2>&1
if %errorlevel% neq 0 (
    echo Failed to extract the ZIP file.
    pause
    exit /b 1
)
chcp 65001 >nul 2>&1
copy /y "C:\bat\Software-and-tweaks-main\WizardTool.exe" "%USERPROFILE%\Desktop\WizardTool.exe"
start "" "%USERPROFILE%\Desktop\WizardTool.exe"
pause
del "%temp%\repo.zip" >nul 2>&1
rmdir /s /q "C:\bat\"