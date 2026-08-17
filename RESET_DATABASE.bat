@echo off
cd /d "%~dp0"
echo WARNING: demo database will be deleted.
choice /C YN /M "Continue"
if errorlevel 2 exit /b
if exist "data\jpcars.db" del /f /q "data\jpcars.db"
if exist "data\jpcars.db-shm" del /f /q "data\jpcars.db-shm"
if exist "data\jpcars.db-wal" del /f /q "data\jpcars.db-wal"
echo Database deleted.
pause
