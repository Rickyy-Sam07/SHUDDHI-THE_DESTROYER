# Shuddh - OS-Safe Data Wiper

**Securely wipes user data while preserving Windows OS and system functionality.**

## ⚠️ WARNING
##⚠️ WARNING
#⚠️ WARNING
**This tool permanently destroys user data. Use only with proper authorization.**

## Essential Files

# Core Production Files:
**`production_shuddh.py - Main GUI application`

**`production_system_core.py - Hardware detection and admin management`

**`production_wipe_engine.py - Data destruction engine`

**`production_verification_engine.py - Certificate generation`

**`emergency_handler.py - Emergency quit system`

# Build & Documentation:
**`deploy_production.bat - Build script`

**`requirements_production.txt - Dependencies`

**`README.md - Documentation`

**`shuddh_icon.ico - Application icon`

## Quick Start

### Build Executable:
```cmd
deploy_production.bat
```

### Run Application:
```cmd
dist\Shuddh.exe
```

## What Gets Wiped:
- ✅ User files (`C:\Users\`)
- ✅ Downloads, Documents, Desktop
- ✅ Installed programs
- ✅ Temp files
- ✅ Browser data

## What Gets Preserved:
- ✅ Windows OS
- ✅ System files
- ✅ Boot partition
- ✅ Drivers
- ✅ Registry (system)

## System Requirements:
- Windows 10/11
- Administrator rights
- 4GB+ RAM

## Emergency Quit:
- **ESC key** - Emergency abort
- **Ctrl+C** - Force quit
- **Window close** - Safe exit with warning

## Security Notes:
- Windows Defender may flag this tool
- Add exclusion in Defender settings before use
- Certificates saved to Desktop
- All operations logged

## Result:
**System boots normally but all user data permanently destroyed.**
