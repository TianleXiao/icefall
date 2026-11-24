@echo off
setlocal
chcp 65001 >nul
title Icefall TUN cleanup

net session >nul 2>&1
if not "%errorlevel%"=="0" (
    echo.
    echo  Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

echo.
echo  Stopping Icefall...
taskkill /f /im icefall.exe >nul 2>&1

echo  Removing TUN routes (0.0.0.0/1, 128.0.0.0/1)...
netsh interface ipv4 delete route prefix=0.0.0.0/1 interface="Icefall" store=active >nul 2>&1
netsh interface ipv4 delete route prefix=128.0.0.0/1 interface="Icefall" store=active >nul 2>&1

echo  Re-enabling normal DNS/proxy state...
icefall.exe unsetproxy >nul 2>&1

echo.
echo  Done. Network should be back to normal.
timeout /t 5 >nul
