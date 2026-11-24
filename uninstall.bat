@echo off
chcp 65001 >nul
title Icefall / Suibing - Restore

set "REGKEY=HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"

cd /d "%~dp0"

echo.
echo  Stopping proxy...
taskkill /f /im icefall.exe >nul 2>&1

echo  Restoring proxy settings...
if exist "proxy-backup.reg" (
    reg import "proxy-backup.reg" >nul 2>&1
    echo        restored from proxy-backup.reg
) else (
    reg add "%REGKEY%" /v ProxyEnable /t REG_DWORD /d 0 /f >nul
    echo        system proxy disabled
)

echo  Removing autostart...
del /q "%STARTUP%\Icefall.vbs" >nul 2>&1

echo.
echo  Done. Press any key to close.
pause >nul
