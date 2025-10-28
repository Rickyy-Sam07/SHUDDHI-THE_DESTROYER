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

# Shuddh - Data Overwrite Methods Explained

## Overview of Overwrite Techniques

### 🔐 Cryptographic Overwriting
**Definition:** Uses encryption key destruction to render data unrecoverable.

**Method in Shuddh:**
- ✅ **CRYPTOGRAPHIC_ERASE** - TRUE cryptographic method
  - Destroys encryption keys
  - Data remains encrypted but unrecoverable
  - Only works on Self-Encrypting Drives (SEDs)
  - Fastest method (instant)

---

### 🔢 Pattern-Based Overwriting
**Definition:** Overwrites data with specific bit patterns multiple times.

**Methods in Shuddh:**
- ❌ **DoD 5220.22-M** - NOT cryptographic, pattern-based
  - Pass 1: Write 0x00 (all zeros)
  - Pass 2: Write 0xFF (all ones)
  - Pass 3: Write random data
  - 3 passes total
  - **Pattern-based, NOT cryptographic**

- ❌ **AFSSI 5020** - NOT cryptographic, pattern-based
  - Pass 1: Write 0x00 (all zeros)
  - Pass 2: Write 0xFF (all ones)
  - Pass 3: Write random character
  - 3 passes total
  - **Pattern-based, NOT cryptographic**

---

### 📝 Single-Pass Overwriting
**Definition:** Overwrites data once with random or zero data.

**Methods in Shuddh:**
- ❌ **NIST SP 800-88 Clear** - NOT cryptographic (unless using CSPRNG)
  - Single pass with random data or zeros
  - May use pseudo-random (not cryptographically secure)
  - **Simple overwrite, NOT truly cryptographic**

- ⚠️ **NIST SP 800-88 Purge** - Can be cryptographic (depends on variant)
  - Hardware block erase OR
  - **Cryptographic erase** (if supported by drive)
  - **Only cryptographic if using crypto erase variant**

---

### ⚙️ Hardware-Level Erasing
**Definition:** Uses drive firmware to erase at hardware level.

**Methods in Shuddh:**
- ❌ **ATA Secure Erase** - NOT cryptographic, hardware-based
  - Uses ATA command to erase
  - Faster than software overwrite
  - **Hardware erase, NOT cryptographic**

- ❌ **NVMe Format** - NOT cryptographic, hardware-based
  - Uses NVMe format command
  - Very fast
  - **Hardware format, NOT cryptographic**

---

## Summary Table

| Method | Cryptographic? | Passes | Type | Speed |
|--------|---------------|--------|------|-------|
| **CRYPTOGRAPHIC_ERASE** | ✅ YES | 1 | Key destruction | Instant |
| **DoD 5220.22-M** | ❌ NO | 3 | Pattern-based | Slow |
| **AFSSI 5020** | ❌ NO | 3 | Pattern-based | Slow |
| **NIST Clear** | ❌ NO* | 1 | Random/Zero fill | Medium |
| **NIST Purge** | ⚠️ Maybe** | 1 | Block/Crypto erase | Fast |
| **ATA Secure Erase** | ❌ NO | 1 | Hardware erase | Fast |
| **NVMe Format** | ❌ NO | 1 | Hardware format | Very Fast |

\* Unless using cryptographically secure random number generator (CSPRNG)  
\*\* Only if using cryptographic erase variant

---

## Updated Report JSON Structure

Your report will now show:

```json
{
  "overwrite_evidence": {
    "method_used": "DoD 5220.22-M",
    "method_id": "DOD_5220_22_M",
    "overwrite_type": "3-pass pattern-based overwrite",
    "overwrite_passes": 3,
    "passes_completed": 3,
    "bytes_overwritten": 499858325,
    "overwrite_status": "COMPLETED",
    "cryptographic_overwrite": false,         // TRUE only for CRYPTOGRAPHIC_ERASE
    "pattern_based_overwrite": true,          // TRUE for DoD, AFSSI
    "multiple_passes": true,                  // TRUE for methods with 3+ passes
    "hardware_level_erase": false,            // TRUE for ATA/NVMe
    "secure_random_data": false               // TRUE for NIST methods
  }
}
```

---

## Conclusion

**ONLY** the **CRYPTOGRAPHIC_ERASE** method uses true cryptographic overwriting.

All other methods use:
- Pattern-based overwriting (DoD, AFSSI)
- Random data overwriting (NIST Clear)
- Hardware erasing (ATA, NVMe)
- Block erasing (NIST Purge)

**None of DoD, NIST Clear, or AFSSI use cryptographic overwriting.**