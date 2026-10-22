@echo off
title CipherRoom (online)
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo  Node.js is not installed. Opening download page. Install the LTS version and run this again.
  start "" https://nodejs.org/en/download
  pause
  exit /b
)
where cloudflared >nul 2>nul
if errorlevel 1 (
  echo.
  echo  Installing the free Cloudflare tunnel tool, one time only...
  winget install --id Cloudflare.cloudflared -e --accept-source-agreements --accept-package-agreements
  echo.
  echo  Done. CLOSE this window and double-click SHARE-ONLINE-WINDOWS.bat again.
  pause
  exit /b
)
set TRUST_PROXY=1
start "CipherRoom server - keep open" cmd /k node server.js
timeout /t 2 /nobreak >nul
echo.
echo  ==========================================================
echo   Look below for a link like  https://xxxx.trycloudflare.com
echo   1. Open THAT link in your browser (not localhost).
echo   2. Create the room there, then use the Invite button.
echo   Keep both windows open. Close them to take the app offline.
echo  ==========================================================
echo.
cloudflared tunnel --url http://localhost:3000
pause
