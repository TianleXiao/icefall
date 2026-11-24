@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
title Icefall / Suibing

set "HERE=%~dp0"
set "PORT=8899"
set "UPSTREAM=127.0.0.1:7897"
set "REGKEY=HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

cd /d "%HERE%"

echo.
echo  ==========================================================
echo    Icefall  /  Suibing    v1
echo  ==========================================================
echo.

echo  [1/4] Backup current proxy settings
reg export "%REGKEY%" "proxy-backup.reg" /y >nul 2>&1
if exist "proxy-backup.reg" echo        backup -^> proxy-backup.reg

echo  [2/4] Detect blocks on this network
if exist "strategy.json" goto havestrat
echo        scanning, about 10 seconds...
icefall.exe discover
goto checkup

:havestrat
echo        strategy.json found, skip scan
echo        delete strategy.json to rescan

:checkup
echo  [3/4] Check upstream proxy %UPSTREAM%
set "USE_UP="
powershell -NoProfile -Command "$c=New-Object Net.Sockets.TcpClient; try{$c.Connect('127.0.0.1',7897); exit 0}catch{exit 1}finally{$c.Close()}" >nul 2>&1
if not errorlevel 1 set "USE_UP=1"

if defined USE_UP (
    echo        found - non-blocked traffic goes through it
) else (
    echo        not found - running in direct mode
)

echo  [4/4] Start proxy
taskkill /f /im icefall.exe >nul 2>&1
if defined USE_UP (
    start "" /b icefall.exe proxy 127.0.0.1:%PORT% %UPSTREAM% > "proxy.log" 2>&1
) else (
    start "" /b icefall.exe proxy 127.0.0.1:%PORT% > "proxy.log" 2>&1
)
timeout /t 2 /nobreak >nul

reg add "%REGKEY%" /v ProxyServer /t REG_SZ /d "127.0.0.1:%PORT%" /f >nul
reg add "%REGKEY%" /v ProxyOverride /t REG_SZ /d "localhost;127.*;10.*;192.168.*;172.16.*;<local>" /f >nul
reg add "%REGKEY%" /v ProxyEnable /t REG_DWORD /d 1 /f >nul
echo        system proxy -^> 127.0.0.1:%PORT%

echo.
echo  ==========================================================
echo    READY
echo.
echo    Open bilibili / douyin / xiaohongshu in your browser
echo.
echo    restore : uninstall.bat
echo    log     : proxy.log
echo    rules   : strategy.json
echo  ==========================================================
echo.
echo  Press any key to close - proxy keeps running
pause >nul
endlocal
