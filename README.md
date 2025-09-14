# Shuddh - OS-Safe Data Wiper

**Securely wipes user data while preserving Windows OS and system functionality.**

## ⚠️ WARNING
**This tool permanently destroys user data. Use only with proper authorization.**

## Core Files

### Production Files:
- **`shuddh.py`** - Main launcher with dependency checking
- **`shuddh_gui.py`** - Streamlined GUI with error display
- **`production_system_core.py`** - Hardware detection and admin management
- **`production_wipe_engine.py`** - Data destruction engine
- **`production_verification_engine.py`** - Certificate generation
- **`emergency_handler.py`** - Emergency quit system

### Build & Documentation:
- **`deploy_production.bat`** - Build script
- **`requirements_production.txt`** - Dependencies
- **`shuddh_icon.ico`** - Application icon

## Quick Start

### Build Executable:
```cmd
deploy_production.bat
```

### Run Application:
```cmd
dist\Shuddh.exe
```

## Features

### Error Handling:
- Comprehensive error logging with timestamps
- Copyable error display window
- Clear error messages for troubleshooting
- Dependency checking on startup

### GUI Features:
- Drive selection with detailed information
- Real-time status updates
- Progress tracking
- OS-safe vs complete wipe detection
- Emergency quit (ESC key)

### Data Destruction:
- **User files** (`C:\Users\`)
- **Downloads, Documents, Desktop**
- **Installed programs**
- **Temp files**
- **Browser data**

### OS Preservation:
- **Windows OS** (system files)
- **Boot partition**
- **Drivers**
- **Registry** (system entries)

## System Requirements:
- Windows 10/11
- Administrator rights
- 4GB+ RAM
- Python 3.8+ (for source)

## Error Troubleshooting:
1. Click "View Errors" button in GUI
2. Copy error log to clipboard
3. Review error details for specific issues
4. Check dependencies with launcher

## Security Notes:
- Windows Defender may flag this tool
- Add exclusion in Defender settings before use
- Certificates saved to Desktop
- All operations logged with timestamps

## Result:
**System boots normally but all user data permanently destroyed.**