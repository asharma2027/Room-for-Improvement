@echo off
setlocal EnableDelayedExpansion
title Room for Improvement — Setup

:: ─────────────────────────────────────────────
::  Room for Improvement — One-Click Windows Launcher
:: ─────────────────────────────────────────────

:: Change to project root (parent of this script's folder)
cd /d "%~dp0.."

cls
echo.
echo  ==========================================
echo    Room for Improvement -- Starting...
echo  ==========================================
echo.

:: ── 1. Install Node.js if missing ─────────────────────────────────────────────
where node >nul 2>&1
if %errorlevel% neq 0 (
  echo  Node.js not found. Installing now (this only happens once)...
  echo.

  :: Try winget first (available on Windows 10 1709+ and Windows 11)
  where winget >nul 2>&1
  if !errorlevel! equ 0 (
    echo  Installing Node.js via Windows Package Manager...
    winget install --id OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements --silent
    :: Refresh PATH
    for /f "tokens=*" %%i in ('where node 2^>nul') do set NODE_PATH=%%i
  )

  :: If winget failed or not available, download installer directly
  where node >nul 2>&1
  if !errorlevel! neq 0 (
    echo  Downloading Node.js installer...
    set NODE_INSTALLER=%TEMP%\node_installer.msi
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
      "Invoke-WebRequest -Uri 'https://nodejs.org/dist/v20.12.2/node-v20.12.2-x64.msi' -OutFile '!NODE_INSTALLER!'"
    echo  Running Node.js installer (follow the prompts)...
    msiexec /i "!NODE_INSTALLER!" /qb ADDLOCAL=ALL
    del "!NODE_INSTALLER!" >nul 2>&1
    :: Refresh PATH from registry
    for /f "tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul') do set "PATH=%%b;%PATH%"
    for /f "tokens=2*" %%a in ('reg query "HKCU\Environment" /v Path 2^>nul') do set "PATH=%%b;%PATH%"
  )
)

where node >nul 2>&1
if %errorlevel% neq 0 (
  echo.
  echo  ERROR: Could not install Node.js automatically.
  echo  Please install it from https://nodejs.org and run this again.
  echo.
  pause
  exit /b 1
)

for /f "tokens=*" %%i in ('node -v') do echo  [OK] Node.js %%i
echo.

:: ── 2. Copy .env if missing ────────────────────────────────────────────────────
if not exist ".env" (
  if exist "instructor_setup\.env.example" (
    copy "instructor_setup\.env.example" ".env" >nul
    echo  [OK] Created .env from example
  )
)

:: ── 3. Install npm dependencies ────────────────────────────────────────────────
echo  Installing dependencies (first run takes ~30 seconds)...
call npm install --prefer-offline --no-audit --no-fund
if %errorlevel% neq 0 (
  echo.
  echo  ERROR: npm install failed.
  pause
  exit /b 1
)
echo  [OK] Dependencies ready
echo.

:: ── 4. Kill any existing process on port 3000 ─────────────────────────────────
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":3000 " ^| findstr "LISTENING" 2^>nul') do (
  echo  Stopping previous server on port 3000...
  taskkill /PID %%a /F >nul 2>&1
  timeout /t 1 /nobreak >nul
)

:: ── 5. Start the server in background ─────────────────────────────────────────
echo  Starting server...
start /b node server.js

:: Wait for server to be ready (up to 15 seconds)
echo  Waiting for server to be ready...
set /a TRIES=0
:WAIT_LOOP
set /a TRIES+=1
if %TRIES% gtr 15 goto OPEN_BROWSER
timeout /t 1 /nobreak >nul
powershell -NoProfile -Command "try { Invoke-WebRequest -Uri 'http://localhost:3000' -UseBasicParsing -TimeoutSec 1 | Out-Null; exit 0 } catch { exit 1 }" >nul 2>&1
if %errorlevel% neq 0 goto WAIT_LOOP

:OPEN_BROWSER
:: ── 6. Open browser ────────────────────────────────────────────────────────────
start http://localhost:3000

echo.
echo  ==========================================
echo    [OK] Site is running!
echo    http://localhost:3000
echo.
echo    Login:    test@uchicago.edu
echo    Password: test
echo.
echo    Press Ctrl+C or close this window
echo    to stop the server.
echo  ==========================================
echo.

:: Keep window open (server runs in background tied to this window)
:: When user closes this window, the node process will be cleaned up
:KEEP_ALIVE
timeout /t 5 /nobreak >nul
powershell -NoProfile -Command "try { Invoke-WebRequest -Uri 'http://localhost:3000' -UseBasicParsing -TimeoutSec 2 | Out-Null; exit 0 } catch { exit 1 }" >nul 2>&1
if %errorlevel% equ 0 goto KEEP_ALIVE

echo.
echo  Server stopped. Press any key to close.
pause >nul
