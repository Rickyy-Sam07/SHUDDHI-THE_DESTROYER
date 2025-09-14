@echo off
echo ========================================
echo    SHUDDH PRODUCTION DEPLOYMENT
echo ========================================
echo.
echo WARNING: This will create a PRODUCTION executable
echo that performs ACTUAL data destruction!
echo.
pause

echo Installing production requirements...
python -m pip install -r requirements_production.txt
if %errorlevel% neq 0 (
    echo Failed to install requirements
    pause
    exit /b 1
)

echo Building Shuddh executable...
pyinstaller --onefile --windowed --icon=shuddh_icon.ico --name=Shuddh shuddh.py
if %errorlevel% neq 0 (
    echo Build failed
    pause
    exit /b 1
)

echo.
echo ========================================
echo    DEPLOYMENT COMPLETED
echo ========================================
echo.
echo Executable location: dist\Shuddh.exe
echo.
echo CRITICAL WARNINGS:
echo - This executable performs REAL data destruction
echo - Test only on systems where data loss is acceptable
echo - Ensure proper authorization before use
echo - Certificates will be saved to user's Desktop
echo.
pause