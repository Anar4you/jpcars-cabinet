@echo off
cd /d "%~dp0"
echo JPCars v0.5 - first install
echo.
call npm.cmd install
if errorlevel 1 (
 echo INSTALL FAILED
 pause
 exit /b 1
)
echo INSTALL COMPLETE
pause
