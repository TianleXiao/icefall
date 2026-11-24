@echo off
setlocal
chcp 65001 >nul
title Icefall TUN mode

rem Elevate if not admin. The elevated copy re-runs with the same %~dp0.
net session >nul 2>&1
if not "%errorlevel%"=="0" (
    echo.
    echo  Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
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
if not exist "C:\Program Files\Tailscale\wintun.dll" goto tryxunyou
copy /y "C:\Program Files\Tailscale\wintun.dll" "wintun.dll" >nul
echo         copied from Tailscale
goto havewintun
:tryxunyou
if not exist "C:\Program Files (x86)\xunyou\wintun.dll" goto trywg
copy /y "C:\Program Files (x86)\xunyou\wintun.dll" "wintun.dll" >nul
echo         copied from Xunyou
goto havewintun
:trywg
if not exist "C:\Program Files\WireGuard\wintun.dll" goto nowintun
copy /y "C:\Program Files\WireGuard\wintun.dll" "wintun.dll" >nul
echo         copied from WireGuard
goto havewintun
:nowintun
echo         NOT FOUND - copy wintun.dll from WireGuard/Tailscale into this folder
pause
exit /b 1
:havewintun
echo         ok

echo  [2/4] Clear system proxy (TUN already covers every app)
icefall.exe unsetproxy >nul 2>&1
echo         ok

rem Probe 7897 outside any parenthesised block, so %errorlevel% is the probe's
rem own exit code and nothing else's. Inside a block the delayed-expansion of a
rem variable set in the same block is what broke the last run.
echo  [3/4] Detect upstream proxy on 7897
powershell -NoProfile -Command "$c=New-Object Net.Sockets.TcpClient; try{$c.Connect('127.0.0.1',7897); exit 0}catch{exit 1}finally{$c.Close()}"
if errorlevel 1 goto noupstream
set "ARGS=127.0.0.1:%PORT% %UPSTREAM%"
echo         upstream %UPSTREAM% enabled
goto starttun
:noupstream
set "ARGS=127.0.0.1:%PORT%"
echo         no upstream found, direct only

:starttun
echo  [4/4] Start TUN mode
taskkill /f /im icefall.exe >nul 2>&1
rem Give the old process a moment to release the wintun adapter.
ping -n 3 127.0.0.1 >nul
start "Icefall TUN" /min icefall.exe tun %ARGS%
echo         command: icefall.exe tun %ARGS%
echo         started

echo.
echo  ==========================================================
echo   All traffic is now handled by Icefall TUN.
echo   Apps that ignore the system proxy (WeChat, Steam CM,
echo   games, cloud gaming) are covered.
echo.
echo   To stop: run stop-tun.bat, or close the Icefall window.
echo   If your network stays broken after a crash, run
echo   stop-tun.bat to remove the leftover routes.
echo  ==========================================================
timeout /t 8 >nul
