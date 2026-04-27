@echo off
echo ================================
echo   Room for Improvement - Setup  
echo ================================
echo.

:: Check for Node.js
where node >nul 2>&1
if %errorlevel% neq 0 (
  echo ERROR: Node.js is not installed.
  echo Please download and install it from https://nodejs.org, then run this script again.
  pause
  exit /b 1
)

for /f "tokens=*" %%i in ('node -v') do echo Node.js found: %%i
echo.

echo Installing dependencies (this may take ~30 seconds the first time)...
call npm install

if %errorlevel% neq 0 (
  echo.
  echo ERROR: npm install failed. Make sure you're running this from the project root folder.
  pause
  exit /b 1
)

echo.
echo Starting server...
echo.
echo ================================
echo   Site is running!
echo   Open: http://localhost:3000
echo.
echo   Login with:
echo     Email:    test@uchicago.edu
echo     Password: test
echo.
echo   Press Ctrl+C to stop.
echo ================================
echo.

:: Open browser
start http://localhost:3000

call npm start
pause
