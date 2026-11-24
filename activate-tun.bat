@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
title Icefall TUN mode

net session >nul 2>&1
if not "%errorlevel%"=="0" (
    echo.
    echo  Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
set "PORT=8899"
set "UPSTREAM=127.0.0.1:7897"

echo.
echo  ==========================================================
echo    Icefall / Suibing   TUN mode
echo  ==========================================================
echo.

echo  [1/4] wintun.dll
if exist "wintun.dll" goto havewintun
if exist "%SystemRoot%\System32\wintun.dll" goto havewintun
if exist "C:\Program Files\Tailscale\wintun.dll" (
    copy /y "C:\Program Files\Tailscale\wintun.dll" "wintun.dll" >nul
    echo         copied from Tailscale
    goto havewintun
)
if exist "C:\Program Files (x86)\xunyou\wintun.dll" (
    copy /y "C:\Program Files (x86)\xunyou\wintun.dll" "wintun.dll" >nul
    echo         copied from Xunyou
    goto havewintun
)
if exist "C:\Program Files\WireGuard\wintun.dll" (
    copy /y "C:\Program Files\WireGuard\wintun.dll" "wintun.dll" >nul
    echo         copied from WireGuard
    goto havewintun
)
echo         NOT FOUND - copy wintun.dll from WireGuard/Tailscale into this folder
pause
exit /b 1
:havewintun
echo         ok

echo  [2/4] Clear system proxy (TUN already covers every app)
icefall.exe unsetproxy >nul 2>&1
echo         ok

echo  [3/4] Detect upstream proxy on 7897
set "ARGS=127.0.0.1:%PORT%"
powershell -NoProfile -Command "$c=New-Object Net.Sockets.TcpClient; try{$c.Connect('127.0.0.1',7897); exit 0}catch{exit 1}finally{$c.Close()}"
if "%errorlevel%"=="0" (
    set "ARGS=127.0.0.1:%PORT% %UPSTREAM%"
    echo         upstream %UPSTREAM% enabled
) else (
    echo         no upstream found, direct only
)

echo  [4/4] Start TUN mode
taskkill /f /im icefall.exe >nul 2>&1
start "Icefall TUN" /min icefall.exe tun %ARGS%
echo         started

echo.
echo  ==========================================================
echo   All traffic is now handled by Icefall TUN.
echo   Apps that ignore the system proxy (WeChat, games,
echo   cloud gaming) are covered.
echo.
echo   To stop: run stop-tun.bat, or close the Icefall window.
echo   If your network stays broken after a crash, run
echo   stop-tun.bat to remove the leftover routes.
echo  ==========================================================
timeout /t 8 >nul
