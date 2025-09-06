# Shuddh - Production Data Wiper

## ⚠️ CRITICAL WARNING ⚠️

**THIS IS THE PRODUCTION VERSION THAT PERFORMS ACTUAL DATA DESTRUCTION**

- **ALL SAFETY FEATURES HAVE BEEN REMOVED**
- **THIS WILL PERMANENTLY ERASE ALL DATA ON TARGET DRIVES**
- **DATA DESTRUCTION IS IRREVERSIBLE**
- **USE ONLY WITH PROPER AUTHORIZATION**

## Features

### Complete Data Destruction
- **NVMe Format**: Hardware-level secure erase for NVMe drives
- **ATA Secure Erase**: Hardware-level secure erase for SATA SSDs
- **AES-128-CTR Overwrite**: Cryptographically secure software overwrite

### Professional UI Workflow
1. **Warning & Consent Screen**: Clear warnings with mandatory checkboxes
2. **Progress Screen**: Real-time status updates during wiping
3. **Success Screen**: Confirmation with certificate information

### Tamper-Proof Certification
- **Cryptographic Signatures**: RSA-2048 signed certificates
- **JSON Format**: Machine-readable audit logs
- **PDF Format**: Human-readable certificates
- **Desktop Storage**: Certificates saved to user's Desktop

## System Requirements

- **OS**: Windows 10/11 (64-bit)
- **Privileges**: Administrator rights (automatic UAC elevation)
- **Python**: 3.8+ (for building from source)
- **Dependencies**: See `requirements_production.txt`

## Quick Deployment

### Option 1: Use Pre-built Executable
1. Run `Shuddh.exe` as Administrator
2. Follow the UI prompts
3. Certificates will be saved to Desktop

### Option 2: Build from Source
1. Run `deploy_production.bat`
2. Executable will be created in `dist/Shuddh.exe`

## Manual Build Process

```cmd
# Install requirements
pip install -r requirements_production.txt

# Create icon (optional)
python create_icon.py

# Build executable
python build_executable.py
```

## UI Workflow

### Screen 1: Warning & Consent
```
==========================================
            SHUDDH - DATA PURIFICATION
==========================================

WARNING: This tool will PERMANENTLY ERASE ALL DATA
on the following drive:

    Drive: \\.\PhysicalDrive0
    Model: Samsung SSD 870 EVO
    Serial: S59CNM0T123456
    Size: 465 GB

This action cannot be undone.

☐ I have backed up all my important data.
☐ I understand this is irreversible.

          [ I AGREE, START PURIFICATION ]
```

### Screen 2: Progress
```
==========================================
        PURIFICATION IN PROGRESS
==========================================

Please do not turn off your computer or disconnect power.

Current Stage: Executing secure erase... ⏳
Current Stage: Verifying wipe... [ ]

Estimated Time Remaining: ~2 minutes

[████████████████████████] 75%
```

### Screen 3: Success
```
==========================================
        PURIFICATION SUCCESSFUL!
==========================================

Your drive (S59CNM0T123456) has been successfully and securely wiped.

Your tamper-proof certificate has been saved to your Desktop.

    Shuddh_Certificate_S59CNM0T123456.pdf
    Shuddh_Certificate_S59CNM0T123456.json

You may now safely recycle or donate this device.

               [ EXIT ]
```

## Certificate Format

### JSON Certificate
- Complete audit trail with cryptographic signature
- Machine-readable for automated processing
- Includes verification hash and timing data

### PDF Certificate
- Human-readable summary
- Professional formatting
- Suitable for compliance documentation

## Wipe Methods

| Drive Type | Primary Method | Fallback | Compliance |
|------------|---------------|----------|------------|
| NVMe SSD | NVMe Format NVM | AES-128-CTR | NIST SP 800-88 Purge |
| SATA SSD | ATA Secure Erase | AES-128-CTR | NIST SP 800-88 Purge |
| HDD/USB | AES-128-CTR | - | NIST SP 800-88 Clear |

## Security Features

### Hardware Methods
- **Exit Code Verification**: Confirms successful hardware erase
- **Native Drive Commands**: Uses manufacturer-implemented secure erase
- **Fast Execution**: Typically completes in seconds to minutes

### Software Method
- **Cryptographic Overwrite**: AES-128-CTR with secure random data
- **Sector Sampling**: Reads random sectors to verify overwrite
- **Pattern Analysis**: Detects incomplete wipes or data remnants

### Certificate Security
- **RSA-2048 Signatures**: Industry-standard cryptographic signing
- **SHA-256 Hashing**: Tamper-evident audit trail integrity
- **Canonical JSON**: Deterministic serialization for verification

## File Locations

### Certificates
- **Location**: User's Desktop (`%USERPROFILE%\Desktop`)
- **Format**: `Shuddh_Certificate_[ID]_[Timestamp].json/pdf`
- **Permissions**: User-accessible, no special privileges required

### Logs
- **Application Logs**: Console output during execution
- **Audit Logs**: Embedded in certificate files
- **Error Logs**: Displayed in UI error dialogs

## Compliance Standards

### NIST SP 800-88 Rev. 1
- **Clear**: Single-pass overwrite (AES-128-CTR)
- **Purge**: Hardware secure erase (NVMe Format, ATA Secure Erase)
- **Destroy**: Physical destruction (not implemented)

### Audit Requirements
- **Tamper-Proof**: Cryptographically signed certificates
- **Traceable**: Unique certificate IDs and timestamps
- **Verifiable**: Public key verification of signatures

## Error Handling

### Common Issues
1. **No Admin Rights**: Automatic UAC elevation prompt
2. **Drive Access Denied**: Check for disk encryption or BitLocker
3. **Hardware Erase Failed**: Automatic fallback to software method
4. **Certificate Generation Failed**: Error displayed with details

### Troubleshooting
- **Run as Administrator**: Right-click → "Run as administrator"
- **Disable Antivirus**: Temporarily disable real-time protection
- **Check Drive Health**: Ensure drive is not failing
- **Free Space**: Ensure sufficient space on Desktop for certificates

## Legal and Compliance

### Authorization Required
- **Explicit Permission**: Only use on systems you own or have authorization to wipe
- **Data Backup**: Ensure all important data is backed up before use
- **Legal Compliance**: Follow local laws regarding data destruction

### Liability
- **No Warranty**: Software provided "as is" without warranty
- **User Responsibility**: Users are responsible for proper authorization
- **Data Loss**: Developers not liable for data loss or misuse

## Technical Architecture

### Core Components
- **SystemCore**: Hardware detection and admin privilege management
- **WipeEngine**: Execution of wipe methods with fallback support
- **VerificationEngine**: Post-wipe verification and certificate generation
- **GUI**: Tkinter-based user interface with progress tracking

### External Dependencies
- **WMI**: Windows Management Instrumentation for hardware detection
- **pywin32**: Windows API access for low-level disk operations
- **cryptography**: RSA key generation and digital signatures
- **reportlab**: PDF certificate generation

## Version History

### v2.0 Production
- Complete removal of all safety features
- Production-ready GUI implementation
- Tamper-proof certificate generation
- Desktop certificate storage
- Comprehensive error handling

### v1.0 Development
- Safety-first development version
- All operations simulated
- No actual data destruction
- Development and testing framework

---

## ⚠️ FINAL WARNING ⚠️

**THIS SOFTWARE WILL PERMANENTLY DESTROY ALL DATA ON TARGET DRIVES**

- Ensure you have proper authorization
- Verify all important data is backed up
- Test only on systems where data loss is acceptable
- Use only for legitimate data destruction purposes

**THE DEVELOPERS ARE NOT RESPONSIBLE FOR DATA LOSS OR MISUSE**