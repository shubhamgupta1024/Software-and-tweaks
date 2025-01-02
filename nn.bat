@echo off
REM Step 1: Download repository as ZIP
curl -L -o repo.zip https://github.com/shubhamgupta1024/Software-and-tweaks/archive/refs/heads/main.zip

REM Step 2: Create a temp folder and extract ZIP
mkdir temp_folder
tar -xf repo.zip -C temp_folder

REM Step 3: Find the .bat file
for /r temp_folder %%F in (*.bat) do set "newfile=%%F"

REM Step 4: Compare the new file with v1.bat
fc "%newfile%" "v1.bat" >nul
if %errorlevel%==0 (
    echo Files are identical. No update needed.
) else (
    echo New update found. Replacing v1.bat...
    copy "%newfile%" "v1.bat" /Y
    echo Update completed.
)

REM Cleanup
pause
rmdir /s /q temp_folder
del repo.zip
pause

