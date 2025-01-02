@Echo Off
Set Version=4.1
MODE 30,20
setlocal
cd %systemroot%\system32
call :IsAdmin
REM ;System Priorities
set w=[97m
set p=[95m
set b=[96m
::Enable Delayed Expansion
setlocal EnableDelayedExpansion > nul
setlocal
:: Enable ANSI Escape Sequences
Reg.exe add "HKCU\CONSOLE" /v "VirtualTerminalLevel" /t REG_DWORD /d "1" /f  > nul

if exist "C:\power\autoruns.exe" (
goto exm
) else (
        chcp 437 >nul 2>&1
curl -g -k -L -# -o "%temp%\power.zip" "https://www.dropbox.com/scl/fi/5z5r9z60iz8cx6c29o23i/power.zip?rlkey=lu3htw50w6iir8rpl51k608sd&st=bdg9pxhu&dl=0"
powershell -NoProfile Expand-Archive '%temp%\power.zip' -DestinationPath 'C:\power\' >nul 2>&1 
chcp 65001 >nul 2>&1
)

Title Shubham Tweak
cls
:exm
cls
echo Made By Shubham
echo %p%Discord (Wizard1024)%w%
echo.**********************
echo Use ZeroLatency Tweak
echo.----------------------
echo. %p%1 Latency Tweak%w%
echo.----------------------
echo. %w%2 Revert Tweak%b%
echo.----------------------
echo. %w%3 Set Game Priority %b%
echo.----------------------
echo.%w%4 Check Current latency%b%
echo.----------------------
echo.%w%5 Activate Windows%b%
echo.----------------------
echo.%w%6 Disk serial changer%b%
echo.----------------------


set /p input=Enter option number
if /i %input% == 1 goto rrrrON
if /i %input% == 2 goto disss
if /i %input% == 3 goto gameBooster
if /i %input% == 4 goto lete
if /i %input% == 5 goto Acti
if /i %input% == 6 goto disskk

) ELSE (
echo Invalid Input & goto MisspellRedirect

:MisspellRedirect
cls
echo Misspell Detected
timeout 2
goto RedirectMenu

:RedirectMenu
goto exm


:disskk
copy /y "C:\power\Volumeid.exe" "C:\Windows\System32\Volumeid.exe"
cls

rem Define the characters for hexadecimal (0-9 and A-F)
set hexDigits=0123456789ABCDEF

rem Function to generate a random 4-digit hexadecimal number
set "randomHex1="
set /a "randNum1=!random! %% 16"
set /a "randNum2=!random! %% 16"
set /a "randNum3=!random! %% 16"
set /a "randNum4=!random! %% 16"
set "randomHex1=!hexDigits:~%randNum1%,1!!hexDigits:~%randNum2%,1!!hexDigits:~%randNum3%,1!!hexDigits:~%randNum4%,1!"

set "randomHex2="
set /a "randNum1=!random! %% 16"
set /a "randNum2=!random! %% 16"
set /a "randNum3=!random! %% 16"
set /a "randNum4=!random! %% 16"
set "randomHex2=!hexDigits:~%randNum1%,1!!hexDigits:~%randNum2%,1!!hexDigits:~%randNum3%,1!!hexDigits:~%randNum4%,1!"

set "randomHex3="
set /a "randNum1=!random! %% 16"
set /a "randNum2=!random! %% 16"
set /a "randNum3=!random! %% 16"
set /a "randNum4=!random! %% 16"
set "randomHex3=!hexDigits:~%randNum1%,1!!hexDigits:~%randNum2%,1!!hexDigits:~%randNum3%,1!!hexDigits:~%randNum4%,1!"

set "randomHex4="
set /a "randNum1=!random! %% 16"
set /a "randNum2=!random! %% 16"
set /a "randNum3=!random! %% 16"
set /a "randNum4=!random! %% 16"
set "randomHex4=!hexDigits:~%randNum1%,1!!hexDigits:~%randNum2%,1!!hexDigits:~%randNum3%,1!!hexDigits:~%randNum4%,1!"
cls
volumeid C: !randomHex1!-!randomHex2!
volumeid D: !randomHex3!-!randomHex4!
pause
goto exm


:Acti
cls

rem Get the Windows edition using WMIC command
for /f "tokens=2 delims==" %%i in ('wmic os get Caption /value ^| find "="') do set "edition=%%i"

rem Display the detected Windows edition
echo Detected Windows Edition: %edition%
set "productKey="

rem Set the product key based on the detected edition
if /i "%edition%"=="Microsoft Windows 10 Home" set productKey=TX9XD-98N7V-6WMQ6-BX7FG-H8Q99
if /i "%edition%"=="Microsoft Windows 10 Home N" set productKey=3KHY7-WNT83-DGQKR-F7HPR-844BM 
if /i "%edition%"=="Microsoft Windows 10 Home Single Language" set productKey=7HNRX-D7KGG-3K4RQ-4WPJ4-YTDFH
if /i "%edition%"=="Microsoft Windows 10 Home Country Specific" set productKey=PVMJN-6DFY6-9CCP6-7BKTT-D3WVR
if /i "%edition%"=="Microsoft Windows 10 Pro" set productKey=W269N-WFGWX-YVC9B-4J6C9-T83GX
if /i "%edition%"=="Microsoft Windows 10 Pro N" set productKey=MH37W-N47XK-V7XM9-C7227-GCQG9
if /i "%edition%"=="Microsoft Windows 10 Pro for Workstations" set productKey=NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J
if /i "%edition%"=="Microsoft Windows 10 Pro for Workstations N" set productKey=9FNHH-K3HBT-3W4TD-6383H-6XYWF
if /i "%edition%"=="Microsoft Windows 10 Pro Education" set productKey=6TP4R-GNPTD-KYYHQ-7B7DP-J447Y
if /i "%edition%"=="Microsoft Windows 10 Pro Education N" set productKey=YVWGF-BXNMC-HTQYQ-CPQ99-66QFC
if /i "%edition%"=="Microsoft Windows 10 Education" set productKey=NW6C2-QMPVW-D7KKK-3GKT6-VCFB2
if /i "%edition%"=="Microsoft Windows 10 Education N" set productKey=2WH4N-8QGBV-H22JP-CT43Q-MDWWJ
if /i "%edition%"=="Microsoft Windows 10 Enterprise" set productKey=NPPR9-FWDCX-D2C8J-H872K-2YT43
if /i "%edition%"=="Microsoft Windows 10 Enterprise N" set productKey=DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4
if /i "%edition%"=="Microsoft Windows 10 Enterprise G" set productKey=YYVX9-NTFWV-6MDM3-9PT4T-4M68B
if /i "%edition%"=="Microsoft Windows 10 Enterprise G N" set productKey=44RPN-FTY23-9VTTB-MP9BX-T84FV
if /i "%edition%"=="Microsoft Windows 10 Enterprise LTSC 2019" set productKey=M7XTQ-FN8P6-TTKYV-9D4CC-J462D
if /i "%edition%"=="Microsoft Windows 10 Enterprise N LTSC 2019" set productKey=92NFX-8DJQP-P6BBQ-THF9C-7CG2H

rem If productKey is empty, the edition is not recognized
if "%productKey%"=="" (
    echo Detected edition not recognized or not supported for activation.
    pause
    exit /b
)

rem Now that the productKey variable has been set, we can proceed to the next step of the process
rem Activating Windows

echo Activating Windows...
cscript slmgr.vbs /ipk %productKey%
cscript slmgr.vbs /skms kms8.msguides.com
cls
cscript slmgr.vbs /ato
pause
goto exm

:lete
start C:\power\dpclat.exe
goto exm

:rrrrON


cls
echo.**********************
echo.Block privacy and
echo.Full screen optimization
echo.----------------------
echo.      %p%1 Yes%w%
echo.----------------------
echo.     %w%2 Skip%b%
echo.----------------------
set /p input=Enter option number
if /i %input% == 1 goto priv
if /i %input% == 2 goto spri

) ELSE (
echo Invalid Input & goto MisspellRedirect

:MisspellRedirect
cls
echo Misspell Detected
timeout 2
goto RedirectMenu

:RedirectMenu
goto exm
:priv
cls
start "" /wait "C:\power\OOSU10.exe" "C:\power\mine.cfg"
goto spri

:spri

echo Disabling Mitigations
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f 
:: Sub Mitigations
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f
PowerShell -Command "Get-AppxPackage Microsoft.YourPhone -AllUsers | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage Microsoft.XboxGamingOverlay | Remove-AppxPackage"
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dam" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
for /f "Delims=" %%k in ('Reg.exe Query hklm\SYSTEM\CurrentControlSet\Enum /f "{4d36e967-e325-11ce-bfc1-08002be10318}" /d /s^|Find "HKEY"') do (
  Reg.exe add "%%k\Device Parameters\Disk" /v UserWriteCacheSetting /t reg_dword /d 1 /f
)
for /f "Delims=" %%k in ('Reg.exe Query hklm\SYSTEM\CurrentControlSet\Enum /f "{4d36e967-e325-11ce-bfc1-08002be10318}" /d /s^|Find "HKEY"') do (
  Reg.exe add "%%k\Device Parameters\Disk" /v UserWriteCacheSetting /t reg_dword /d 1 /f
)
::Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f

start C:\power\autoruns.exe
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\bam" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dam" /v "Start" /t REG_DWORD /d "4" /f 
echo %w% - Disabling Fast Startup%b%
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f 
echo %w% - Disabling Hibernation%b%
powercfg /h off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SleepReliabilityDetailedDiagnostics" /t REG_DWORD /d "0" /f 
PowerShell -Command "Disable-MMAgent -MemoryCompression" > nul 2>&1



echo %w% - Disable Notifications%b%
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\QuietHours" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.AutoPlay" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.LowDisk" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Print.Notification" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.WiFiNetworkManager" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\acpipagr" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\AcpiPmi" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\CAD" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\CSC" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\luafv" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasAcd" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\Rasl2tp" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasPppoe" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasSstp" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpipreg" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\wanarpv6" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\PEAUTH" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\QWAVEdrv" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\cdrom" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\Beep" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\fileinfo" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\FileCrypt" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\IE" /v "CEIPEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\IE" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Reliability" /v "CEIPEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Reliability" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "DisableOptinExperience" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d "1" /f
sc stop WerSvc
sc config WerSvc start= disabled


::REG ADD "HKCU\Control Panel\Mouse" /v "MouseAccel" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "AutoApproveOSDumps" /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "AutoApproveOSDumps" /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC" /v Start /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineCore" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineUA" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "StartupBoostEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f

::Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "UseDpiScaling" /t REG_DWORD /d "0" /f

Reg.exe add "HKCU\Software\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d "3" /f

Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" /v "DisableStartupSound" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\VideoSettings" /v "VideoQualityOnBattery" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f
echo %w% - Delete Microsoft Edge %b%
PowerShell -Command "Get-AppxPackage -allusers *MicrosoftEdge* | Remove-AppxPackage" 
taskkill /im msedge.exe /t /f
taskkill /im msedgewebview2.exe /t /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft" /v DoNotUpdateToEdgeWithChromium /t REG_DWORD /d 1 /f

cd %PROGRAMFILES(X86)%\Microsoft\Edge\Application\1*\Installer
cd C:\Program Files (x86)\Microsoft\Edge\Application\125.0.2535.79\Installer
setup.exe --uninstall --system-level --verbose-logging --force-uninstall
rd /s /q "C:\Program Files (x86)\Microsoft\Edge"
rd /s /q "C:\Program Files (x86)\Microsoft\EdgeCore"
rd /s /q "C:\Program Files (x86)\Microsoft\EdgeUpdate"
rd /s /q "C:\Program Files (x86)\Microsoft\EdgeWebView"
rd /s /q "C:\Program Files (x86)\Microsoft\Temp"
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "HistoricalCaptureEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f



Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f
echo %w% - Disable Xbox Services%b%
sc config xbgm start= disabled >nul 2>&1
sc config XblAuthManager start= disabled
sc config XblGameSave start= disabled
sc config XboxGipSvc start= disabled
sc config XboxNetApiSvc start= disabled
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "0" /f 
echo %w% - Disable Popups, baloon tips and more%b%
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f


Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f

Reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaCapabilities" /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "IsAssignedAccess" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "IsWindowsHelloActive" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d 3 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchSafeSearch" /t REG_DWORD /d 3 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\SearchCompanion" /v "DisableContentFileUpdates" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DoNotUseWebResults" /t REG_DWORD /d "1" /f












echo Stopping Windows from Reinstalling Preinstalled apps
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f 
echo Disabling Windows Suggestions
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314559Enabled" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280815Enabled" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-202914Enabled" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d "0" /f

echo Removing Unnecessary Powershell Packages
PowerShell -Command "Get-AppxPackage -allusers *Microsoft.WindowsTerminal* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *3DBuilder* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *bing* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *bingfinance* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *bingsports* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *BingWeather* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *CommsPhone* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *Drawboard PDF* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *Facebook* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *Getstarted* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *Microsoft.Messaging* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *MicrosoftOfficeHub* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *Office.OneNote* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *OneNote* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *people* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *SkypeApp* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *solit* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *Sway* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *Twitter* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *WindowsAlarms* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *WindowsPhone* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *WindowsMaps* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *WindowsFeedbackHub* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *WindowsSoundRecorder* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *windowscommunicationsapps* | Remove-AppxPackage" 
PowerShell -Command "Get-AppxPackage -allusers *zune* | Remove-AppxPackage" 
echo Disabling Cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "0" /f 
Powershell -Command "Get-appxpackage -allusers *Microsoft.549981C3F5F10* | Remove-AppxPackage" 
echo Disabling OneDrive
start /wait "" "%SYSTEMROOT%\SYSWOW64\ONEDRIVESETUP.EXE" /UNINSTALL
rd C:\OneDriveTemp /q /s 
rd "%USERPROFILE%\OneDrive" /q /s 
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /q /s 
rd "%PROGRAMDATA%\Microsoft OneDrive" /q /s 
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v "Attributes" /t REG_DWORD /d "0" 
reg add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v "Attributes" /t REG_DWORD /d "0" 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d "0" /f 
desabling chrome
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TranslateEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TaskManagerEndProcessEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SpellCheckServiceEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SpellcheckEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MediaRouterCastAllowAllIPs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowDinosaurEasterEgg" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultGeolocationSetting" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultCookiesSetting" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultFileHandlingGuardSetting" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultFileSystemReadGuardSetting" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultFileSystemnv11GuardSetting" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultImagesSetting" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultPopupsSetting" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultSensorsSetting" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultSerialGuardSetting" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultWebBluetoothGuardSetting" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultWebUsbGuardSetting" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "EnableMediaRouter" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ShowCastIconInToolbar" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "CloudPrintProxyEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "PrintRasterizationMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "PrintingEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultPluginsSetting" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SafeBrowsingProtectionLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SafeBrowsingExtendedReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "HomepageIsNewTabPage" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "HomepageLocation" /t REG_SZ /d "google.com" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "NewTabPageLocation" /t REG_SZ /d "google.com" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome\Recommended" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome\Recommended" /v "DeviceMetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Google\Chrome\Recommended" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Google\Chrome\Recommended" /v "DeviceMetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DeviceMetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Google\Chrome" /v "DeviceMetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "Install{8A69D345-D564-463C-AFF1-A69D9E530F96}" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "TargetChannel{8A69D345-D564-463C-AFF1-A69D9E530F96}" /t REG_SZ /d "stable" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "Update{8A69D345-D564-463C-AFF1-A69D9E530F96}" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "Install{4CCED17F-7852-4AFC-9E9E-C89D8795BDD2}" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "AutoUpdateCheckPeriodMinutes" /t REG_DWORD /d "43200" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "DownloadPreference" /t REG_SZ /d "cacheable" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "UpdatesSuppressedStartHour" /t REG_DWORD /d "23" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "UpdatesSuppressedStartMin" /t REG_DWORD /d "48" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "UpdatesSuppressedDurationMin" /t REG_DWORD /d "55" /f

@printer deactivate
sc config PrintNotify start= disabled
sc config Spooler start= disabled
schtasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /Disable
schtasks /Change /TN "Microsoft\Windows\Printing\PrinterCleanupTask" /Disable





reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Discord.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Discord.exe\PerfOptions" /V IoPriority /T REG_DWORD /F /D 0


reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrafficMonitor.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrafficMonitor.exe\PerfOptions" /V IoPriority /T REG_DWORD /F /D 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /V IoPriority /T REG_DWORD /F /D 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\regedit.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\regedit.exe\PerfOptions" /V IoPriority /T REG_DWORD /F /D 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\EKSAAudioCenter_x64.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\EKSAAudioCenter_x64.exe\PerfOptions" /V IoPriority /T REG_DWORD /F /D 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\NVIDIA Web Helper.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\NVIDIA Web Helper.exe\PerfOptions" /V IoPriority /T REG_DWORD /F /D 0

sc config wlidsvc start= disabled
sc config DiagTrack start= disabled
sc config DusmSvc start= disabled
sc config RetailDemo start= disabled
sc config Fax start= disabled
sc config SharedAccess start= disabled
sc config lfsvc start= disabled
sc config WpcMonSvc start= disabled
sc config SessionEnv start= disabled
sc config MicrosoftEdgeElevationService start= disabled
sc config edgeupdate start= disabled
sc config edgeupdatem start= disabled
sc config autotimesvc start= disabled
sc config CscService start= disabled
sc config TermService start= disabled
sc config SensorDataService start= disabled
sc config SensorService start= disabled
sc config SensrSvc start= disabled
sc config shpamsvc start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config PhoneSvc start= disabled
sc config TapiSrv start= disabled
sc config UevAgentService start= disabled
sc config WalletService start= disabled
sc config WebClient start= disabled
sc config MixedRealityOpenXRSvc start= disabled
sc config stisvc start= disabled
sc config WbioSrvc start= disabled
sc config icssvc start= disabled
sc config Wecsvc start= disabled
sc config XboxGipSvc start= disabled
sc config XblAuthManager start= disabled
sc config XboxNetApiSvc start= disabled
sc config XblGameSave start= disabled
sc config SEMgrSvc start= disabled
sc config iphlpsvc start= disabled
sc config Backupper Service start= disabled
sc config BDESVC start= disabled

sc config CDPSvc start= disabled
sc config CDPUserSvc start= disabled
sc config DevQueryBroker start= disabled

sc config dmwappushservice start= disabled
sc config DispBrokerDesktopSvc start= disabled
sc config TrkWks start= disabled
sc config dLauncherLoopback start= disabled
sc config EFS start= disabled
sc config fdPHost start= disabled
sc config FDResPub start= disabled
sc config IKEEXT start= disabled
sc config NPSMSvc start= disabled
sc config WPDBusEnum start= disabled
sc config PcaSvc start= disabled
sc config RasMan start= disabled
sc config RetailDemo start=disabled
sc config SstpSvc start=disabled
sc config ShellHWDetection start= disabled
sc config SSDPSRV start= disabled
sc config SysMain start= disabled
sc config OneSyncSvc start= disabled
sc config lmhosts start= disabled
sc config UserDataSvc start= disabled
sc config UnistoreSvc start= disabled
::sc config Wcmsvc start= demand
sc config FontCache start= disabled
::sc config W32Time start= demand
sc config tzautoupdate start= demand
sc config DialogBlockingService start= disabled
sc config PimIndexMaintenanceSvc_5f1ad start= disabled
sc config MessagingService_5f1ad start= disabled
sc config AppVClient start= disabled
sc config MsKeyboardFilter start= disabled
sc config NetTcpPortSharing start= disabled
sc config ssh-agent start= disabled
sc config SstpSvc start= disabled
sc config OneSyncSvc_5f1ad start= disabled
sc config wercplsupport start= disabled
sc config WMPNetworkSvc start= disabled
sc config WerSvc start= disabled


sc config DsmSvc start= disabled

::sc config RemoteRegistry start= disabled
sc config WinRM start= disabled
sc config RmSvc start= disabled


schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device User" /disable
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /disable
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /disable
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /disable
schtasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /disable
schtasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /disable
schtasks /Change /TN "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /disable
schtasks /Change /TN "Microsoft\Windows\Input\MouseSyncDataAvailable" /disable
schtasks /Change /TN "Microsoft\Windows\Input\PenSyncDataAvailable" /disable
schtasks /Change /TN "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /disable
schtasks /Change /TN "Microsoft\Windows\International\Synchronize Language Settings" /disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /disable
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /disable
schtasks /Change /TN "Microsoft\Windows\MUI\LPRemove" /disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /disable
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /disable
schtasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /disable
schtasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /disable
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /disable
schtasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /disable
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /disable
schtasks /Change /TN "Microsoft\Windows\Setup\SnapshotCleanupTask" /disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /disable
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /disable
schtasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /disable
schtasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /disable
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /disable
schtasks /Change /TN "Microsoft\Windows\WDI\ResolutionHost" /disable
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Management" /disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Validation" /disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /disable
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /disable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /disable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\OobeDiscovery" /disable





schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" 
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable 
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" 
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable 
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" 
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable 
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" 
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable 

schtasks /end /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" 
schtasks /change /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable 

schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" 
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable 
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" 
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /disable 
schtasks /end /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" 
schtasks /change /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable 
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" 
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable 
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" 
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" /disable 
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" 
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" /disable 
schtasks /end /tn "\Microsoft\Windows\Autochk\Proxy" 
schtasks /change /tn "\Microsoft\Windows\Autochk\Proxy" /disable 
schtasks /end /tn "\Microsoft\Windows\Maintenance\WinSAT" 
schtasks /change /tn "\Microsoft\Windows\Maintenance\WinSAT" /disable 
schtasks /end /tn "\Microsoft\Windows\Application Experience\AitAgent" 
schtasks /change /tn "\Microsoft\Windows\Application Experience\AitAgent" /disable 
schtasks /end /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" 
schtasks /change /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable 
schtasks /end /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" 
schtasks /change /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable 

schtasks /end /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)" 
schtasks /change /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable 
schtasks /end /tn "\Microsoft\Windows\PI\Sqm-Tasks" 
schtasks /change /tn "\Microsoft\Windows\PI\Sqm-Tasks" /disable 
schtasks /end /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" 
schtasks /change /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable 
schtasks /end /tn "\Microsoft\Windows\AppID\SmartScreenSpecific" 
schtasks /change /tn "\Microsoft\Windows\AppID\SmartScreenSpecific" /disable 
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentFallBack2016" 
schtasks /change /tn "\Microsoft\Office\OfficeTelemetryAgentFallBack2016" /disable 
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn2016" 
schtasks /change /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn2016" /disable 
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn" 
schtasks /change /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn" /disable 
schtasks /end /tn "\Microsoftd\Office\OfficeTelemetryAgentFallBack" 
schtasks /change /TN "\Microsoftd\Office\OfficeTelemetryAgentFallBack" /disable 
schtasks /end /tn "\Microsoft\Office\Office 15 Subscription Heartbeat" 
schtasks /change /TN "\Microsoft\Office\Office 15 Subscription Heartbeat" /disable 
schtasks /end /tn "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" 
schtasks /change /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /disable
schtasks /end /tn "\Microsoft\Windows\Device Information\Device" 
schtasks /change /TN "\Microsoft\Windows\Device Information\Device" /disable 

echo Disabling Telemetry Through Registry
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f 
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowCommercialDataPipeline" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "MicrosoftEdgeDataOptIn" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\DeviceHealthAttestationService" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f 
reg add "HKLM\SYSTEM\DriverDatabase\Policies\Settings" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Reliability" /v "CEIPEnable" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Reliability" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "DisableOptinExperience" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\IE" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d "1" /f 
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Peernet" /v "Disabled" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f 

reg add "HKLM\SYSTEM\DriverDatabase\Policies\Settings" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f 
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f 

echo Disabling Auto Loggers
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Cellcore" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOobe" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DataMarket" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\HolographicDevice" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsClient" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsProxy" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Mellanox-Kernel" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-AssignedAccess-Trace" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Setup" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NBSMBLOGGER" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\PEAuthLog" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RdrLog" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\ReadyBoot" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatformTel" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SocketHeciServer" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TCPIPLOGGER" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TileStore" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Tpm" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TPMProvisioningService" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WFP-IPsec Trace" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSessionRepro" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WinPhoneCritical" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Credssp" /v "DebugLogLevel" /t REG_DWORD /d "0" /f 
echo Disabling Telemetry Services 
sc stop DiagTrack 
sc config DiagTrack start= disabled 
sc stop dmwappushservice 
 
sc config diagnosticshub.standardcollector.service start= disabled 











Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f


Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "20" /f


Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Taskmgr.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\VALORANT.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\VALORANT.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\VALORANT-Win64-Shipping.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f


Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\VALORANT-Win64-Shipping.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\UnrealCEFSubProcess.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\vgtray.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\vgc.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "4" /f

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenuExperienceHost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenuExperienceHost.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenu.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenu.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f



REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chkdsk.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chkdsk.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1

REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\defrag.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\defrag.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dism.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dism.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1

REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GameBar.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GameBar.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GameBarFT.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GameBarFT.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GameBarFTServer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GameBarFTServer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1

REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\discord.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\discord.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DiscordPTB.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DiscordPTB.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1

REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdgeUpdate.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdgeUpdate.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MRT.exe" /v "CFGOptions" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MRT.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MRT.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mscorsvw.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mscorsvw.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEng.exe" /v "CFGOptions" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEng.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEng.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ngen.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ngen.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ngentask.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ngentask.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe" /v "MinimumStackCommitInBytes" /t REG_DWORD /d "32768" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TiWorker.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TiWorker.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\UsoClient.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\UsoClient.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\usocoreworker.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\usocoreworker.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1

:: ThreadPriority tweaks (Questionable)



::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\monitor\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouhid\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1

Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer" /v "ThreadPriority" /t REG_DWORD /d "0" /f


Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\usbxhci\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f


Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Ndu" /v "start" /t REG_DWORD /d "4" /f

for /f "skip=1" %%i in ('wmic os get TotalVisibleMemorySize') do if not defined TOTAL_MEMORY set "TOTAL_MEMORY=%%i" & set /a SVCHOST=%%i+1024000  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "!SVCHOST!" /f 





reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x00000029 /f
copy /y "C:\power\dwm.bat" "C:\Windows\System32\dwm.bat"
copy /y "C:\power\DeleteTemp.bat" "C:\Windows\System32\DeleteTemp.bat"
cls

schtasks /f /create /sc onlogon /tn "clear" /tr "cmd /c start /min DeleteTemp.bat" /RL HIGHEST /ru users
schtasks /f /create /sc onlogon /tn "dwm" /tr "C:\Windows\System32\dwm.bat" /RL HIGHEST /ru system
schtasks /f /create /sc onlogon /tn "clash" /tr "%LOCALAPPDATA%\Clash Verge\Clash Verge.exe" /RL HIGHEST /ru system

Call "C:\Windows\System32\dwm.bat"

Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_ENABLE_UNSAFE_COMMAND_BUFFER_REUSE" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_ENABLE_RUNTIME_DRIVER_OPTIMIZATIONS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_RESOURCE_ALIGNMENT" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_MULTITHREADED" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_MULTITHREADED" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_DEFERRED_CONTEXTS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_DEFERRED_CONTEXTS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_ALLOW_TILING" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_ENABLE_DYNAMIC_CODEGEN" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_ALLOW_TILING" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_CPU_PAGE_TABLE_ENABLED" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_HEAP_SERIALIZATION_ENABLED" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_MAP_HEAP_ALLOCATIONS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_RESIDENCY_MANAGEMENT_ENABLED" /t REG_DWORD /d "1" /f


reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DpcWatchdogProfileOffset /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DpcTimeout /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v IdealDpcRate /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v MaximumDpcQueueDepth /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v MinimumDpcRate /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DpcWatchdogPeriod /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v UnlimitDpcQueue /t REG_DWORD /d 1 /f


Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaxDynamicTickDuration" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumSharedReadyQueueSize" /t REG_DWORD /d "128" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "BufferSize" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItem" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItemToNode" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItemEx" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueThreadIrp" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ExTryQueueWorkItem" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ExQueueWorkItem" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoEnqueueIrp" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "XMMIZeroingEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "UseNormalStack" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "UseNewEaBuffering" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "StackSubSystemStackSize" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ThreadDpcEnable" /t REG_DWORD /d "0" /f

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "PriorityControl" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableOverlappedExecution" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "TimeIncrement" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "QuantumLength" /t REG_DWORD /d "20" /f

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MMCSS" /v "Start" /t REG_DWORD /d "4" /f
cls

cls
echo.**********************
echo.Use TimerResolution
echo.----------------------
echo.   %p%1 Yes%w%
echo.----------------------
echo.   %w%2 No%b%
echo.----------------------
echo.   %w%X Menu%b%
echo.----------------------

set /p input=:
if /i %input% == 1 goto timmer
if /i %input% == 2 goto noTimmer
) ELSE (
echo Invalid Input & goto MisspellRedirect

:MisspellRedirect
cls
echo Misspell Detected
timeout 2
goto RedirectMenu

:RedirectMenu
goto exm 
:timmer
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f

::bcdedit /set configaccesspolicy Default
::bcdedit /set linearaddress57 optout
::bcdedit /set recoveryenabled No
::bcdedit /set vm No
::bcdedit /set isolatedcontext No
::bcdedit /set bootuxdisabled Yes
::bcdedit /set allowedinmemorysettings 0x0
::bcdedit /set increaseuserva 268435328
::bcdedit /set x2apicpolicy Enable
::bcdedit /set msi Default
::bcdedit /set bootmenupolicy Legacy
::bcdedit /set hypervisorlaunchtype Off
::bcdedit /set vsmlaunchtype Off
::bcdedit /set quietboot Yes
::bcdedit /set usephysicaldestination No
::bcdedit /set uselegacyapicmode No
::bcdedit /set usefirmwarepcisettings No
::bcdedit /set disableelamdrivers Yes


bcdedit /deletevalue useplatformclock
bcdedit /set nx AlwaysOff
bcdedit /set useplatformtick yes
bcdedit /set tscsyncpolicy enhanced
bcdedit /set disabledynamictick yes
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v GlobalTimerResolutionRequests /t REG_DWORD /d 00000001 /f
copy /y "C:\Power\SetTimerResolution.exe" "C:\Windows\System32\SetTimerResolution.exe"
copy /y "C:\power\timerresolution.bat" "C:\Windows\System32\timerresolution.bat"
cls
schtasks /f /create /sc onlogon /tn "TimerResolution" /tr "C:\Windows\System32\timerresolution.bat" /RL HIGHEST /ru system
Call "C:\Windows\System32\timerresolution.bat"

cls
echo Processor use Max
echo.----------------------
echo.      %p%1 Enable%w%
echo.----------------------
echo.     %w%2 Disable%b%
echo.----------------------
set /p input=Enter option number
if /i %input% == 1 goto idee
if /i %input% == 2 goto noTimmer

) ELSE (
echo Invalid Input & goto MisspellRedirect

:MisspellRedirect
cls
echo Misspell Detected
timeout 2
goto RedirectMenu

:RedirectMenu
goto exm

:idee
PowerCfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR IDLEDISABLE 001
PowerCfg /SETACTIVE SCHEME_CURRENT
goto noTimmer

:noTimmer

cls

echo.**********************
echo.   Use NvMe-SSD-HDD
echo.----------------------
echo.   %p%1 NvMe-SSD%w%
echo.----------------------
echo.   %w%2 HDD%b%
echo.----------------------
set /p input=:
if /i %input% == 1 goto oooON
if /i %input% == 2 goto hdd

) ELSE (
echo Invalid Input & goto MisspellRedirect

:MisspellRedirect
cls
echo Misspell Detected
timeout 2
goto RedirectMenu

:RedirectMenu
goto noTimmer

:HDD
fsutil behavior set memoryusage 2
fsutil behavior set mftzone 2
fsutil behavior set disabledeletenotify 0
fsutil behavior set encryptpagingfile 0
fsutil behavior set disable8dot3 1
Reg add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f
::Disable NTFS compression
fsutil behavior set disablecompression 1
::Disable Last Access information on directories, performance/privacy
fsutil behavior set disableLastAccess 1
Reg add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d "2147483648" /f

echo Optimized storage device %storageType%
goto ddiisss


:oooON

::Raise the limit of paged pool memory
fsutil behavior set memoryusage 2
fsutil behavior set mftzone 2
fsutil behavior set disabledeletenotify 0
fsutil behavior set encryptpagingfile 0
fsutil behavior set disable8dot3 1
Reg add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f
::Disable NTFS compression
fsutil behavior set disablecompression 1
::Disable Last Access information on directories, performance/privacy
fsutil behavior set disableLastAccess 0
Reg add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d "2147483648" /f



Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "QueueDepth" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "NvmeMaxReadSplit" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "NvmeMaxWriteSplit" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ForceFlush" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ImmediateData" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "MaxSegmentsPerCommand" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "MaxOutstandingCmds" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ForceEagerWrites" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "MaxQueuedCommands" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "MaxOutstandingIORequests" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "NumberOfRequests" /t REG_DWORD /d "1500" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "IoSubmissionQueueCount" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "IoQueueDepth" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "HostMemoryBufferBytes" /t REG_DWORD /d "1500" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ArbitrationBurst" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "QueueDepth" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "NvmeMaxReadSplit" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "NvmeMaxWriteSplit" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "ForceFlush" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "ImmediateData" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "MaxSegmentsPerCommand" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "MaxOutstandingCmds" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "ForceEagerWrites" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "MaxQueuedCommands" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "MaxOutstandingIORequests" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "NumberOfRequests" /t REG_DWORD /d "1500" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "IoSubmissionQueueCount" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "IoQueueDepth" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "HostMemoryBufferBytes" /t REG_DWORD /d "1500" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "ArbitrationBurst" /t REG_DWORD /d "256" /f
cls
goto ddiisss

:ddiisss

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ForegroundBoost" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ThreadBoostType" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ThreadSchedulingModel" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "AdjustDpcThreshold" /t REG_DWORD /d "800" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "DeepIoCoalescingEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IdealDpcRate" /t REG_DWORD /d "800" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "SchedulerAssistThreadFlagOverride" /t REG_DWORD /d "1" /f


Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NdisVirtualBus" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NetBIOS" /v "Start" /t REG_DWORD /d "4" /f

cls

echo.**********************
echo.    Use bluetooth
echo.----------------------
echo.   %p%1 Yes%w%
echo.----------------------
echo.   %w%2 No%b%
echo.----------------------
echo.   %w%X Menu%b%
echo.---------------------- 

set /p input=:
if /i %input% == 2 goto oON
if /i %input% == 1 goto ddisss

) ELSE (
echo Invalid Input & goto MisspellRedirect

:MisspellRedirect
cls
echo Misspell Detected
timeout 2
goto RedirectMenu

:RedirectMenu
goto ddiisss 

:oON

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BTHUSB" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BthMini" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserService_5bd9b" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserService_71f13" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BthA2dp" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BthEnum" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BthHFEnum" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BthLEEnum" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\bthserv" /v "Start" /t REG_DWORD /d "4" /f
cls

goto ddisss

:ddisss
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc_71f13" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc_5bd9b" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\xboxgip" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Latency" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f
::Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f
cls
cls
echo.**********************
echo.   Set power plan
echo.----------------------
echo.   %p%1 Yes%w%
echo.----------------------
echo.   %w%2 Skip%b%
echo.----------------------

set /p input=:
if /i %input% == 1 goto pow
if /i %input% == 2 goto ublock

) ELSE (
echo Invalid Input & goto MisspellRedirect

:MisspellRedirect
cls
echo Misspell Detected
timeout 2
goto RedirectMenu

:RedirectMenu
goto exm 
:pow
PowerCfg -import C:\power\l.pow
goto ublock
:ublock
cls
echo.**********************
echo.    Update Blocker
echo.----------------------
echo.   %p%1 Yes%w%
echo.----------------------
echo.   %w%2 No%b%
echo.----------------------

set /p input=:
if /i %input% == 1 goto upp
if /i %input% == 2 goto noupp

) ELSE (
echo Invalid Input & goto MisspellRedirect

:MisspellRedirect
cls
echo Misspell Detected
timeout 2
goto RedirectMenu

:RedirectMenu
goto exm 

:upp
start C:\power\Wub.exe
:noupp
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v SuperWetEnabled /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v SDRBoostPercentOverride /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v ResampleInLinearSpace /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v OneCoreNoDWMRawGameController /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v MPCInputRouterWaitForDebugger /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v InteractionOutputPredictionDisabled /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v InkGPUAccelOverrideVendorWhitelist /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableRenderPathTestMode /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v FlattenVirtualSurfaceEffectInput /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableCpuClipping /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisallowNonDrawListRendering /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableProjectedShadowsRendering /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableProjectedShadows /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableLockingMemory /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableHologramCompositor /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableDeviceBitmaps /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DebugFailFast /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DDisplayTestMode /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableLockingMemory /t REG_DWORD /d 1 /f
::Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "FrameLatency" /t REG_DWORD /d "2" /f
::Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "ForceDirectDrawSync" /t REG_DWORD /d "0" /f
::Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "MaxQueuedPresentBuffers" /t REG_DWORD /d "1" /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v UseHWDrawListEntriesOnWARP /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v ResampleModeOverride /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v RenderThreadWatchdogTimeoutMilliseconds /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v ParallelModePolicy /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableResizeOptimization /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableMegaRects /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableFrontBufferRenderChecks /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableEffectCaching /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableDesktopOverlays /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnablePrimitiveReordering /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v MaxD3DFeatureLevel /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v OverlayQualifyCount /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v OverlayDisqualifyCount /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v ResizeTimeoutModern /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v ResizeTimeoutGdi /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableResizeOptimization /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableEffectCaching /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v HighColor /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableDeviceBitmaps /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableCpuClipping /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableDrawListCaching /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v AnimationsShiftKey /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v AnimationAttributionEnabled /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableCommonSuperSets /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableAdvancedDirectFlip /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v Start /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v Start /t REG_DWORD /d 1 /f


::Disable Process Mitigations
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationAuditOptions /t Reg_BINARY /d "222222222222222222222222222222222222222222222222" /f
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationOptions /t Reg_BINARY /d "222222222222222222222222222222222222222222222222" /f



echo Disabling Paging Executive
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f >> APB_Log.txt

echo Setting Time Stamp Interval
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "IoPriority" /t REG_DWORD /d "3" /f >> APB_Log.txt
       
echo Forcing contiguous memory allocation in the DirectX Graphics Kernel
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f >> APB_Log.txt

::echo Deleting Microcode
::takeown /f "C:\Windows\System32\mcupdate_GenuineIntel.dll" /r /d y >> APB_Log.txt
::takeown /f "C:\Windows\System32\mcupdate_AuthenticAMD.dll" /r /d y >> APB_Log.txt
::del "C:\Windows\System32\mcupdate_GenuineIntel.dll" /s /f /q >> APB_Log.txt
::del "C:\Windows\System32\mcupdate_AuthenticAMD.dll" /s /f /q >> APB_Log.txt

echo Disabling Power Throttling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PlatformAoAcOverride" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CsEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >> APB_Log.txt

echo Enabling Hardware-Accelerated Gpu Scheduling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "2" /f >> APB_Log.txt

echo Enabling GameMode
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f >> APB_Log.txt

echo Disabling Windows Update Remediation

::reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RemediationRequired" /t REG_DWORD /d "0" /f >> APB_Log.txt
::reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
::reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
::reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "ExcludeWUDrivers" /t REG_DWORD /d "1" /f

echo Disabling Windows Defender tracking
::Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
::Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d "0" /f 
::Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f 
::Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
::Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t REG_SZ /d "Off" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f

::Disable MMCSS
rem extra settings incase MMCSS is reenabled
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "LazyModeTimeout" /t REG_DWORD /d "25000" /f


::reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingCombining" /t REG_DWORD /d "1" /f


echo show weakhost status
powershell "Get-NetIPInterface | ft interfacealias,weakhostreceive,weakhostsend"

powershell "Get-NetAdapter -IncludeHidden | Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue"

reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "1" /f

::wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False
::wmic pagefileset where name="C:\\pagefile.sys" delete
::wmic pagefileset where name="D:\\pagefile.sys" delete
::wmic pagefileset where name="E:\\pagefile.sys" delete
::wmic pagefileset where name="F:\\pagefile.sys" delete


reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Overwolf.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Overwolf.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\OverwolfBrowser.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\OverwolfBrowser.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\OverwolfHelper.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\OverwolfHelper.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\OverwolfHelper64.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\OverwolfHelper64.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1








reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\NordUpdateService.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\NordUpdateService.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\nordvpn-service.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\nordvpn-service.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\NordVPN.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\NordVPN.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\clash-verge-service.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\clash-verge-service.exe\PerfOptions" /V IoPriority /T REG_DWORD /F /D 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Clash Verge.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Clash Verge.exe\PerfOptions" /V IoPriority /T REG_DWORD /F /D 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\clash.exe\PerfOptions" /V CpuPriorityClass /T REG_DWORD /F /D 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\clash.exe\PerfOptions" /V IoPriority /T REG_DWORD /F /D 0

for %%a in (
	fontdrvhost.exe
	dwm.exe
	lsass.exe
	svchost.exe
	WmiPrvSE.exe
	winlogon.exe
	audiodg.exe
	ntoskrnl.exe
	services.exe
) do (
	Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%a" /v "MitigationOptions" /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f 
	Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%a" /v "MitigationAuditOptions" /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f 
)
cccc

Powercfg.cpl
tzutil /s "India Standard Time"

cls
echo.
echo.
echo. Operation Completed, Press any key to continue...
pause > nul
goto exm

:gameBooster
cls

echo.**********************
echo.----------------------
echo.%p%1 Set Priority%w%
echo.----------------------
echo.%w%2 Remove Priority %b%
echo.----------------------
echo.%w%3 Go Back %b%
echo.----------------------


set /p input=:
if /i %input% == 1 goto higgh
if /i %input% == 2 goto defa
if /i %input% == 3 goto exm

) ELSE (
echo Invalid Input & goto MisspellRedirect

:MisspellRedirect
cls
echo Misspell Detected
timeout 2
goto RedirectMenu

:RedirectMenu
goto exm
:defa
cls
cls
cls
set "file="
cls & echo Select the game location
set dialog="about:<input type=file id=FILE><script>FILE.click();new ActiveXObject
set dialog=%dialog%('Scripting.FileSystemObject').GetStandardStream(1).WriteLine(FILE.value);
set dialog=%dialog%close();resizeTo(0,0);</script>"
for /f "tokens=* delims=" %%p in ('mshta.exe %dialog%') do set "file=%%p"
MitigationOptions
cls & if "%file%"=="" goto gameBooster
for %%F in ("%file%") do Reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "%file%" >nul 2>&1 && (
	Reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "%file%" /f >nul 2>&1
	Reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF" /f >nul 2>&1
        Reg.exe delete "KLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF" /v "MitigationOptions" /f
        Reg.exe delete "KLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF" /v "MitigationOptions" /f
	Reg.exe delete "KLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF" /v "UseLargePages" /f
	echo Set graphics preference to default
	echo Enabled fullscreen optimizations
	echo Don't run as administrator by default
	echo Reset CPU priority
	echo Reset IO priority
	echo Enabled application mitigations
) || (
	Reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "%file%" /f >nul 2>&1
	Reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF" /f >nul 2>&1
        Reg.exe delete "KLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF" /v "MitigationOptions" /f
        Reg.exe delete "KLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF" /v "MitigationOptions" /f
	Reg.exe delete "KLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF" /v "UseLargePages" /f
	echo Disable fullscreen optimizations
	echo Run as administrator
	echo Set CPU priority to high
	echo Set IO priority to high
	echo Disabled application mitigations
)
cls
Cls
echo.
echo.
echo. Operation Completed, Press any key to continue...
pause > nul
goto gameBooster

:higgh
cls
set "file="
cls & echo Select the game location
set dialog="about:<input type=file id=FILE><script>FILE.click();new ActiveXObject
set dialog=%dialog%('Scripting.FileSystemObject').GetStandardStream(1).WriteLine(FILE.value);
set dialog=%dialog%close();resizeTo(0,0);</script>"
for /f "tokens=* delims=" %%p in ('mshta.exe %dialog%') do set "file=%%p"

cls & if "%file%"=="" goto gameBooster
for %%F in ("%file%") do Reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "%file%" >nul 2>&1 && (
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f >nul 2>&1
        Reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "%file%" /t REG_SZ /d "~ DISABLEDXMAXIMIZEDWINDOWEDMODE HIGHDPIAWARE" /f >nul 2>&1
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >nul 2>&1
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF" /v MitigationAuditOptions /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f >nul 2>&1
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF" /v MitigationOptions /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f >nul 2>&1
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF" /v "UseLargePages" /t REG_DWORD /d "1" /f
	echo Set graphics preference to default
	echo Enabled fullscreen optimizations
	echo Don't run as administrator by default
	echo Reset CPU priority
	echo Reset IO priority
	echo Enabled application mitigations
) || (
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f >nul 2>&1
        Reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "%file%" /t REG_SZ /d "~ DISABLEDXMAXIMIZEDWINDOWEDMODE HIGHDPIAWARE" /f >nul 2>&1
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >nul 2>&1
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF" /v MitigationAuditOptions /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f >nul 2>&1
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF" /v MitigationOptions /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f >nul 2>&1
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF" /v "UseLargePages" /t REG_DWORD /d "1" /f
	echo Set graphics preference to high performance
	echo Disable fullscreen optimizations
	echo Run as administrator
	echo Set CPU priority to high
	echo Set IO priority to high
	echo Disabled application mitigations
)
cls
Cls
echo.
echo.
echo. Operation Completed, Press any key to continue...
pause > nul
goto gameBooster


:disss



reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RemediationRequired" /f >> APB_Log.txt
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "ExcludeWUDrivers" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Beep" /v "Start" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\fileinfo" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FileCrypt" /v "Start" /t REG_DWORD /d "1" /f >> APB_Log.txt

::reset fsutil disk command
::Raise the limit of paged pool memory
::fsutil behavior set memoryusage  0
::fsutil behavior set mftzone 0
::fsutil behavior set disabledeletenotify 1
::fsutil behavior set encryptpagingfile 0
::fsutil behavior set disable8dot3 0
::Reg add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f
::Disable NTFS compression
::fsutil behavior set disablecompression 0
::Disable Last Access information on directories, performance/privacy
::fsutil behavior set disableLastAccess 0

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x0000002 /f

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer" /v "ThreadPriority" /t REG_DWORD /d - /f
REM EnableIOprioritycontrolforfasterinputhandling
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IoPriorityControl" /f
REM Enableboostforinputthreads
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "PriorityControl" /f
REM AllowoffloadingoftaskstosecondaryCPUcores
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "TaskOffload" /f
REM Optimizeprocessorschedulingforprograms
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ProcessorScheduling" /f
REM Enabledetectionandmitigationofdeadlocksinthreads
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ContextSwitchDeadlockDetection" /f
REM ImproveCPUcycleallocationforcriticalthreads
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ThreadCycleTimeOptimization" /f
REM Boostinput-relatedthreads
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "EnableInputThreadBoost" /f
REM Assignhigherprioritytoinputprocessorthreads
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "TimeCriticalThreads" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "InputProcessorPriority" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX" /v "D3D12_ENABLE_UNSAFE_COMMAND_BUFFER_REUSE" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX" /v "D3D12_ENABLE_RUNTIME_DRIVER_OPTIMIZATIONS" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX" /v "D3D12_RESOURCE_ALIGNMENT" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX" /v "D3D11_MULTITHREADED" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX" /v "D3D12_MULTITHREADED" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX" /v "D3D11_DEFERRED_CONTEXTS" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX" /v "D3D12_DEFERRED_CONTEXTS" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX" /v "D3D11_ALLOW_TILING" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX" /v "D3D11_ENABLE_DYNAMIC_CODEGEN" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX" /v "D3D12_ALLOW_TILING" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX" /v "D3D12_CPU_PAGE_TABLE_ENABLED" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX" /v "D3D12_HEAP_SERIALIZATION_ENABLED" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX" /v "D3D12_MAP_HEAP_ALLOCATIONS" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX" /v "D3D12_RESIDENCY_MANAGEMENT_ENABLED" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "1" /f >> APB_Log.txt

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" /v Start /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" /v Start /t REG_DWORD /d "2" /f

reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /f

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DpcWatchdogProfileOffset /t REG_DWORD /d 10000 /f

reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DpcTimeout /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v IdealDpcRate /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v MaximumDpcQueueDepth /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v MinimumDpcRate /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DpcWatchdogPeriod /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v UnlimitDpcQueue /f


reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "PriorityControl" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableOverlappedExecution" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "TimeIncrement" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "QuantumLength" /f

reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v ThreadDpcEnable /f

Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaxDynamicTickDuration" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumSharedReadyQueueSize" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "BufferSize" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItem" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItemToNode" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItemEx" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueThreadIrp" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ExTryQueueWorkItem" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ExQueueWorkItem" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoEnqueueIrp" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "XMMIZeroingEnable" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "UseNormalStack" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "UseNewEaBuffering" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "StackSubSystemStackSize" /f

Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "QueueDepth" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "NvmeMaxReadSplit" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "NvmeMaxWriteSplit" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ForceFlush" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ImmediateData" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "MaxSegmentsPerCommand" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "MaxOutstandingCmds" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ForceEagerWrites" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "MaxQueuedCommands" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "MaxOutstandingIORequests" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "NumberOfRequests" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "IoSubmissionQueueCount" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "IoQueueDepth" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "HostMemoryBufferBytes" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ArbitrationBurst" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "StorNVMeAllowZeroLatency" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "QueueDepth" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "NvmeMaxReadSplit" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "NvmeMaxWriteSplit" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "ForceFlush" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "ImmediateData" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "MaxSegmentsPerCommand" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "MaxOutstandingCmds" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "ForceEagerWrites" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "MaxQueuedCommands" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "MaxOutstandingIORequests" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "NumberOfRequests" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "IoSubmissionQueueCount" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "IoQueueDepth" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "HostMemoryBufferBytes" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "ArbitrationBurst" /f



Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "CriticalPriorityBoost" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "EnableBackgroundThreadScheduling" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ThreadAffinityBoost" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "BoostCriticalThreads" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "EnableIoPriority" /f

:: Optimize CPU Scheduling for Real-Time Tasks
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "SchedulerQuantumSize" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ProcessorScheduling" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "MaxWorkerThreads" /f

:: Optimize DPC (Deferred Procedure Calls)
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "DpcWatchdogEnabled" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "DpcWatchdogThreshold" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ForegroundBoost" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ThreadBoostType" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ThreadSchedulingModel" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "AdjustDpcThreshold" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "DeepIoCoalescingEnabled" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IdealDpcRate" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "SchedulerAssistThreadFlagOverride" /f
reg add "HKLM\System\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "3" /f

reg delete  "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /f


reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PlatformAoAcOverride" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CsEnabled" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RemediationRequired" /f


sc config wlidsvc start= demand
sc config DisplayEnhancementService start= demand
sc config DiagTrack start= demand
sc config DusmSvc start= demand
sc config TabletInputService start= demand
sc config RetailDemo start= demand
sc config Fax start= demand
sc config SharedAccess start= demand
sc config lfsvc start= demand
sc config WpcMonSvc start= demand
sc config SessionEnv start= demand
sc config MicrosoftEdgeElevationService start= demand
sc config edgeupdate start= demand
sc config edgeupdatem start= demand
sc config autotimesvc start= demand
sc config CscService start= demand
sc config TermService start= demand
sc config SensorDataService start= demand
sc config SensorService start= demand
sc config SensrSvc start= demand
sc config shpamsvc start= demand
sc config diagnosticshub.standardcollector.service start= demand
sc config PhoneSvc start= demand
sc config TapiSrv start= demand
sc config UevAgentService start= demand
sc config WalletService start= demand
sc config TokenBroker start= demand
sc config WebClient start= demand
sc config MixedRealityOpenXRSvc start= demand
sc config stisvc start= demand
sc config WbioSrvc start= demand
sc config icssvc start= demand
sc config Wecsvc start= demand
sc config XboxGipSvc start= demand
sc config XblAuthManager start= demand
sc config XboxNetApiSvc start= demand
sc config XblGameSave start= demand
sc config SEMgrSvc start= demand
sc config iphlpsvc start= demand
sc config Backupper Service start= demand
sc config BthAvctpSvc start= demand
sc config BDESVC start= demand
sc config cbdhsvc start= demand
sc config CDPSvc start= demand
sc config CDPUserSvc start= demand
sc config DevQueryBroker start= demand
sc config DevicesFlowUserSvc start= demand
sc config dmwappushservice start= demand
sc config DispBrokerDesktopSvc start= demand
sc config TrkWks start= demand
sc config dLauncherLoopback start= demand
sc config EFS start= demand
sc config fdPHost start= demand
sc config FDResPub start= demand
sc config IKEEXT start= demand
sc config NPSMSvc start= demand
sc config WPDBusEnum start= demand
sc config PcaSvc start= demand
sc config RasMan start= demand
sc config RetailDemo start=disabled
sc config SstpSvc start=disabled
sc config ShellHWDetection start= demand
sc config SSDPSRV start= demand
sc config SysMain start= demand
sc config OneSyncSvc start= demand
sc config lmhosts start= demand
sc config UserDataSvc start= demand
sc config UnistoreSvc start= demand
sc config Wcmsvc start= demand
sc config FontCache start= demand
sc config W32Time start= demand
sc config tzautoupdate start= demand
sc config DsSvc start= demand
sc config diagsvc start= demand
sc config DialogBlockingService start= demand
sc config PimIndexMaintenanceSvc_5f1ad start= demand
sc config MessagingService_5f1ad start= demand
sc config AppVClient start= demand
sc config MsKeyboardFilter start= demand
sc config NetTcpPortSharing start= demand
sc config ssh-agent start= demand
sc config SstpSvc start= demand
sc config OneSyncSvc_5f1ad start= demand
sc config wercplsupport start= demand
sc config WMPNetworkSvc start= demand
sc config WerSvc start= demand

sc config WinHttpAutoProxySvc start= demand
sc config DsmSvc start= demand
sc config BTAGService start= demand
sc config bthserv start= demand
sc config RemoteRegistry start= demand
sc config RemoteAccess start= demand
sc config WinRM start= demand
sc config RmSvc start= demand


Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "CreateGdiPrimaryOnSlaveGPU" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DriverSupportsCddDwmInterop" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddSyncDxAccess" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddSyncGPUAccess" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddWaitForVerticalBlankEvent" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCreateSwapChain" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkFreeGpuVirtualAddress" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkOpenSwapChain" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkShareSwapChainObject" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkWaitForVerticalBlankEvent" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkWaitForVerticalBlankEvent2" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "SwapChainBackBuffer" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "TdrResetFromTimeoutAsync" /f


schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Enable
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Enable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Enable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Enable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Enable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Enable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Enable
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Enable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /Enable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device User" /Enable
schtasks /Change /TN "Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /Enable
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Enable
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Enable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Enable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Enable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Enable
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Enable
schtasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Enable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Enable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Enable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Enable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /Enable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /Enable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /Enable
schtasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Enable
schtasks /Change /TN "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /Enable
schtasks /Change /TN "Microsoft\Windows\Input\MouseSyncDataAvailable" /Enable
schtasks /Change /TN "Microsoft\Windows\Input\PenSyncDataAvailable" /Enable
schtasks /Change /TN "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Enable
schtasks /Change /TN "Microsoft\Windows\International\Synchronize Language Settings" /Enable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Enable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Enable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Enable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Enable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Enable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /Enable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Enable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Enable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Enable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Enable
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Enable
schtasks /Change /TN "Microsoft\Windows\MUI\LPRemove" /Enable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Enable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Enable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Enable
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Enable
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Enable
schtasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Enable
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Enable
schtasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Enable
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Enable
schtasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Enable
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Enable
schtasks /Change /TN "Microsoft\Windows\Setup\SnapshotCleanupTask" /Enable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Enable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Enable
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Enable
schtasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /Enable
schtasks /Change /TN "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Enable
schtasks /Change /TN "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Enable
schtasks /Change /TN "Microsoft\Windows\Task Manager\Interactive" /Enable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Enable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Enable
schtasks /Change /TN "Microsoft\Windows\Time Zone\SynchronizeTimeZone" /Enable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Enable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /Enable
schtasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /Enable
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Enable
schtasks /Change /TN "Microsoft\Windows\WDI\ResolutionHost" /Enable
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Enable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Management" /Enable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Validation" /Enable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Enable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Enable
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Enable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /Enable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\OobeDiscovery" /Enable


reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "1" /f 
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "0" /f 
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "0" /f 
reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f 
reg add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f 
reg add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f 
reg add "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "0" /f

reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceMemory" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContext" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceOther" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceTimerPeriod" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Latency" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MiracastPerfTrackGraphicsLatency" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /f
::reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "TransitionLatency" /f
bcdedit /deletevalue nx
bcdedit /deletevalue tscsyncpolicy
bcdedit /deletevalue useplatformclock
bcdedit /deletevalue useplatformtick
bcdedit /deletevalue disabledynamictick
schtasks /Delete /TN "TimerResolution" /F
PowerCfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR IDLEDISABLE 000
PowerCfg /SETACTIVE SCHEME_CURRENT

schtasks /Delete /TN "dwm" /F
sc config BTAGService start= demand
sc config bthserv start= demand
sc config PrintNotify start= demand
sc config Spooler start= demand
schtasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /Enable
schtasks /Change /TN "Microsoft\Windows\Printing\PrinterCleanupTask" /Enable
sc config RemoteRegistry start= demand
sc config RemoteAccess start= demand
sc config WinRM start= demand
sc config RmSvc start= demand



taskkill /im SetTimerResolution.exe /t /f



reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v AnimationAttributionEnabled /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v UseHWDrawListEntriesOnWARP /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v ResampleModeOverride /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v RenderThreadWatchdogTimeoutMilliseconds /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v ParallelModePolicy /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableResizeOptimization /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableMegaRects /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableFrontBufferRenderChecks /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableEffectCaching /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableDesktopOverlays /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnablePrimitiveReordering /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v MaxD3DFeatureLevel /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v OverlayQualifyCount /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v OverlayDisqualifyCount /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v ResizeTimeoutModern /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v ResizeTimeoutGdi /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableResizeOptimization /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableEffectCaching /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v HighColor /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableDeviceBitmaps /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableCpuClipping /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableDrawListCaching /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v AnimationsShiftKey /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableCommonSuperSets /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableAdvancedDirectFlip /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v FrameLatency /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v ForceDirectDrawSync /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v MaxQueuedPresentBuffers /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v SuperWetEnabled /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v SDRBoostPercentOverride /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v ResampleInLinearSpace /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v OneCoreNoDWMRawGameController /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v MPCInputRouterWaitForDebugger /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v InteractionOutputPredictionDisabled /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v InkGPUAccelOverrideVendorWhitelist /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableRenderPathTestMode /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v FlattenVirtualSurfaceEffectInput /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v EnableCpuClipping /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisallowNonDrawListRendering /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableProjectedShadowsRendering /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableProjectedShadows /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableLockingMemory /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableHologramCompositor /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableDeviceBitmaps /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DebugFailFast /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DDisplayTestMode /f
reg delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v DisableLockingMemory /f
Reg.exe delete "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "UseDpiScaling" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingCombining" /f

Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "CapPercentage" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "SchedulingType" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "CapPercentage" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "SchedulingType" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "CapPercentage" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "SchedulingType" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "CapPercentage" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "SchedulingType" /t REG_DWORD /d "2" /f

Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\BackgroundDefault" /v "IsLowPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Frozen" /v "IsLowPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNCS" /v "IsLowPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNK" /v "IsLowPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenPPLE" /v "IsLowPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Paused" /v "IsLowPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PausedDNK" /v "IsLowPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Pausing" /v "IsLowPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PrelaunchForeground" /v "IsLowPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\ThrottleGPUInterference" /v "IsLowPriority" /t REG_DWORD /d "1" /f

Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "BasePriority" /t REG_DWORD /d "200" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "OverTargetPriority" /t REG_DWORD /d "80" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "BasePriority" /t REG_DWORD /d "200" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "OverTargetPriority" /t REG_DWORD /d "80" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "BasePriority" /t REG_DWORD /d "20" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "OverTargetPriority" /t REG_DWORD /d "20" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "BasePriority" /t REG_DWORD /d "150" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "OverTargetPriority" /t REG_DWORD /d "80" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "BasePriority" /t REG_DWORD /d "80" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "OverTargetPriority" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "BasePriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "OverTargetPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "BasePriority" /t REG_DWORD /d "130" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "OverTargetPriority" /t REG_DWORD /d "80" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "BasePriority" /t REG_DWORD /d "140" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "OverTargetPriority" /t REG_DWORD /d "80" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "BasePriority" /t REG_DWORD /d "160" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "OverTargetPriority" /t REG_DWORD /d "80" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "BasePriority" /t REG_DWORD /d "170" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "OverTargetPriority" /t REG_DWORD /d "80" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "BasePriority" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "OverTargetPriority" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap" /v "IOBandwidth" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitLimit" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitTarget" /t REG_DWORD /d "4294967295" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PassiveIntRealTimeWorkerPriority" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\KernelVelocity" /v "DisableFGBoostDecay" /t REG_DWORD /d "0" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /f
::bcdedit /deletevalue configaccesspolicy
::bcdedit /deletevalue linearaddress57
::bcdedit /deletevalue recoveryenabled
::bcdedit /deletevalue vm
::bcdedit /set isolatedcontext Yes
::bcdedit /deletevalue bootuxdisabled
::bcdedit /set allowedinmemorysettings 0x15000075
::bcdedit /deletevalue increaseuserva
::bcdedit /deletevalue x2apicpolicy
::bcdedit /deletevalue msi
::bcdedit /set bootmenupolicy Standard
::bcdedit /deletevalue hypervisorlaunchtype
::bcdedit /deletevalue vsmlaunchtype
::bcdedit /deletevalue quietboot
::bcdedit /deletevalue usephysicaldestination
::bcdedit /deletevalue uselegacyapicmode
::bcdedit /deletevalue usefirmwarepcisettings
::bcdedit /deletevalue disableelamdrivers


::bcdedit /deletevalue firstmegabytepolicy
::bcdedit /deletevalue avoidlowmemory
::bcdedit /deletevalue ems
::bcdedit /deletevalue nolowmem

reg delete "HKLM\SYSTEM\CurrentControlSet\Services\HidUsb\Parameters" /v "ThreadPriority" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters" /v "ThreadPriority" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\mouhid\Parameters" /v "ThreadPriority" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\usbccgp\Parameters" /v "ThreadPriority" /f

reg delete "HKLM\SYSTEM\CurrentControlSet\Services\usbhub\Parameters" /v "ThreadPriority" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\usbohci\Parameters" /v "ThreadPriority" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\usbuhci\Parameters" /v "ThreadPriority" /f


reg delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "ThreadPriority" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Audiosrv\Parameters" /v "ThreadPriority" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\disk\Parameters" /v "ThreadPriority" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\iaStorAC\Parameters" /v "ThreadPriority" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\iaStorAVC\Parameters" /v "ThreadPriority" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Ntfs\Parameters" /v "ThreadPriority" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters" /v "ThreadPriority" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ThreadPriority" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" /v "ThreadPriority" /f

::fsutil behavior set mftzone 2

Reg.exe delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /f 
Reg.exe delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /f 
Reg.exe delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /f
Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /f


Reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Latency Sensitive /f
Reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v NoLazyMode /f



Cls
echo.
echo.
echo. Operation Completed, Press any key to continue...
pause > nul
goto exm
:IsAdmin
Reg.exe query "HKU\S-1-5-19\Environment"
If Not %ERRORLEVEL% EQU 0 (
 Cls & Echo You must have administrator rights to continue ... 
 Pause & Exit
)
Cls
goto:eof