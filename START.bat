@echo off
cd /d "%~dp0"
echo ========================================
echo JPCars Personal Cabinet v1.1 Telegram
echo ========================================
echo.
if not exist "node_modules\express" (
  echo Dependencies are missing.
  echo Running npm install now...
  call npm.cmd install
  if errorlevel 1 (
    echo.
    echo INSTALL FAILED
    pause
    exit /b 1
  )
)
echo.
echo Local admin:
echo http://localhost:3000/admin
echo.
call npm.cmd start
pause
