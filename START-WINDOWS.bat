@echo off
title CipherRoom
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo  Node.js is not installed yet. It is free and needed once.
  echo  A download page will open now. Install the "LTS" version,
  echo  then double-click this file again.
  echo.
  start "" https://nodejs.org/en/download
  pause
  exit /b
)
echo.
echo  Starting CipherRoom...
echo  Keep this window open while you chat. Close it to stop the app.
echo.
start "" /b cmd /c "timeout /t 2 /nobreak >nul & start http://localhost:3000"
node server.js
echo.
pause
