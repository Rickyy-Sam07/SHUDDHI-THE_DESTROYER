@echo off
REM ============================================
REM Shuddh - Build Script
REM ============================================
REM This script builds the Shuddh EXE file
REM ============================================

echo.
echo ========================================
echo SHUDDH - THE DESTROYER - BUILD SCRIPT
echo ========================================
echo.

REM Check if PyInstaller is installed
python -c "import PyInstaller" 2>nul
if %errorlevel% neq 0 (
    echo ERROR: PyInstaller is not installed!
    echo.
    echo Installing PyInstaller...
    pip install pyinstaller
    if %errorlevel% neq 0 (
        echo Failed to install PyInstaller!
        pause
        exit /b 1
    )
)

echo Checking required dependencies...
echo.

REM Check for required packages
python -c "import wmi" 2>nul
if %errorlevel% neq 0 (
    echo Installing WMI...
    pip install wmi
)

python -c "import win32api" 2>nul
if %errorlevel% neq 0 (
    echo Installing pywin32...
    pip install pywin32
)

python -c "import cryptography" 2>nul
if %errorlevel% neq 0 (
    echo Installing cryptography...
    pip install cryptography
)

python -c "import Crypto" 2>nul
if %errorlevel% neq 0 (
    echo Installing pycryptodome...
    pip install pycryptodome
)

python -c "import reportlab" 2>nul
if %errorlevel% neq 0 (
    echo Installing reportlab...
    pip install reportlab
)

echo.
echo All dependencies are installed!
echo.

REM Clean previous build
echo Cleaning previous build...
if exist "dist" rmdir /s /q dist
if exist "build" rmdir /s /q build
echo.

REM Build the EXE
echo Building Shuddh.exe...
echo.
python -m PyInstaller production_shuddh.spec --clean

if %errorlevel% equ 0 (
    echo.
    echo ========================================
    echo BUILD SUCCESSFUL!
    echo ========================================
    echo.
    echo EXE Location: dist\Shuddh.exe
    echo.
    echo You can now run: dist\Shuddh.exe
    echo.
    echo NOTE: The EXE includes:
    echo   - Main application (production_shuddh.py)
    echo   - All backend engines
    echo   - Report generator (NEW!)
    echo   - Checksum verifier
    echo   - Emergency handler
    echo   - All dependencies
    echo.
    echo The report.json will be saved to Desktop
    echo (same location as certificates)
    echo.
    echo ========================================
) else (
    echo.
    echo ========================================
    echo BUILD FAILED!
    echo ========================================
    echo.
    echo Please check the error messages above.
    echo.
)

pause
