# OS Data Wiper - Core System Module

A professional-grade data wiping application for Windows systems that implements NIST-compliant secure erasure methods.

## � DEVELOPMENT SAFETY MODE ACTIVE 🔒

**YOUR COMPUTER IS COMPLETELY SAFE** during development! All potentially harmful operations are:
- ✅ **DISABLED** - Cannot execute destructive operations
- ✅ **SIMULATED** - Safe alternatives for testing  
- ✅ **LOGGED** - All operations print "test pass1" confirmations
- ✅ **PROTECTED** - Multiple safety barriers prevent harm

**Quick Safety Test:** Run `python safety_test.py` to verify all safety features are working.

## �🚨 Security Notice

This software performs **irreversible data destruction**. It is intended for authorized use only on systems where data destruction is explicitly required and authorized. **Currently in safe development mode** - no harm possible to your computer.

## Features

### Phase 1: Core System Interaction Module ✅

- **Admin Privilege Management**: Automatic UAC elevation for required system access
- **Hardware Detection**: Comprehensive drive enumeration using Windows WMI
- **Drive Analysis**: Intelligent detection of drive types (SSD, HDD, NVMe, USB)
- **Wipe Method Selection**: NIST-compliant method selection based on drive technology
- **HPA/DCO Detection**: Framework for detecting hidden storage areas (placeholder implementation)
- **Security Logging**: Comprehensive audit trail for all operations

### Step 1: Admin Check & Drive Enumeration ✅

- **Immediate Admin Check**: Launches with admin privilege verification
- **UAC Elevation**: Requests elevation if not running as administrator (safely blocked in dev mode)
- **WMI Drive Enumeration**: Lists all physical drives with detailed information
- **Boot Drive Identification**: Automatically identifies and presents the main boot drive
- **Data Gathering**: Collects Model, SerialNumber, Size, MediaType, InterfaceType
- **Safety Features**: All operations are read-only and completely safe in development mode

## System Requirements

- **Operating System**: Windows 10/11 (64-bit recommended)
- **Python**: 3.8 or higher
- **Privileges**: Administrator rights required for low-level disk access
- **Dependencies**: See `requirements.txt`

## Quick Start (Safe Development)

1. **Launch Shuddh Application** (Step 1):
   ```powershell
   python shuddh.py
   ```

2. **Verify Safety**:
   ```powershell
   python safety_test.py
   ```

3. **Test Core Module**:
   ```powershell
   python system_core.py
   ```

4. **Install Dependencies** (if needed):
   ```powershell
   pip install -r requirements.txt
   ```

All operations are **completely safe** and will show "test pass1" confirmations.

## Core Module Usage

### Step 1: Admin Check & Drive Enumeration

```python
from shuddh import ShuddApp

# Initialize Shuddh application
app = ShuddApp()

# Execute Step 1
success = app.run_step1()

# Get gathered data
data_summary = app.get_data_summary()
print(f"Boot Drive: {data_summary['boot_drive']['model']}")
print(f"Serial: {data_summary['boot_drive']['serial_number']}")
print(f"Size: {data_summary['boot_drive']['size_gb']} GB")
print(f"Recommended Method: {data_summary['boot_drive']['recommended_wipe_method']}")
```

### Basic Hardware Detection

```python
from system_core import SystemCore

# Initialize core system
core = SystemCore()

# Ensure admin privileges (will prompt UAC if needed - blocked in dev mode)
core.ensure_admin_privileges()

# Get all physical drives
drives = core.get_drive_info()

for drive in drives:
    print(f"Drive {drive['Index']}: {drive['Model']}")
    print(f"Serial: {drive['SerialNumber']}")
    print(f"Size: {drive['SizeGB']} GB")
    
    # Get recommended wipe method
    method = core.determine_wipe_method(drive)
    print(f"Recommended method: {method}")
```

### Admin Privilege Checking

```python
from system_core import check_admin

if check_admin():
    print("Running with admin privileges")
else:
    print("Admin privileges required")
```

### Drive Method Determination

```python
from system_core import determine_wipe_method

drive_info = {
    'Model': 'Samsung SSD 980 PRO',
    'InterfaceType': 'NVMe',
    'MediaType': 'Fixed hard disk media'
}

method = determine_wipe_method(drive_info)
print(f"Recommended method: {method}")  # Output: ATA_SECURE_ERASE
```

## Wipe Methods Supported

| Method | Description | Use Case |
|--------|-------------|----------|
| `ATA_SECURE_ERASE` | Hardware-based secure erase | SSDs, NVMe drives |
| `DOD_3_PASS` | DoD 5220.22-M 3-pass overwrite | Traditional HDDs |
| `NIST_SP800_88` | NIST SP 800-88 compliant | General purpose |
| `GUTMANN_35_PASS` | Gutmann 35-pass method | Maximum security (legacy) |

## Configuration

Edit `config.yml` to customize behavior:

```yaml
security:
  require_admin: true
  verify_drive_serial: true
  
hardware:
  enable_hpa_dco_detection: false  # Future implementation
  validate_drive_access: true
  
wipe_methods:
  default_ssd: "ATA_SECURE_ERASE"
  default_hdd: "DOD_3_PASS"
```

## Testing

Run the test suite:

```powershell
# Install test dependencies
pip install pytest pytest-cov

# Run tests
python -m pytest test_system_core.py -v
```

## Security Considerations

1. **Admin Rights**: The application requires and validates administrator privileges
2. **Drive Validation**: All drive access is validated before operations
3. **Audit Trail**: All operations are logged for compliance
4. **Serial Number Tracking**: Drive serial numbers are captured for certificates
5. **Safe Defaults**: Conservative wipe methods are used when drive type is uncertain

## Limitations (Phase 1)

- HPA/DCO detection is placeholder implementation (requires full ATA command implementation)
- No actual data wiping functionality (Phase 2)
- No certificate generation (Phase 3)
- Limited to Windows platform

## Development Status

- ✅ **Phase 1**: Core System Interaction Module (Current)
- ⏳ **Phase 2**: Data Wiping Engine (Next)
- ⏳ **Phase 3**: Certificate Generation & Compliance
- ⏳ **Phase 4**: User Interface & Reporting

## Error Handling

The module includes comprehensive error handling:

- `AdminPrivilegeError`: Raised when admin rights are required but not available
- `HardwareDetectionError`: Raised when hardware enumeration fails
- Graceful fallbacks for missing dependencies (WMI, pywin32)

## Logging

Logs are written to:
- Console output (configurable level)
- `os_data_wiper.log` file (when enabled)
- Windows Event Log (future implementation)

## Contributing

This is a security-critical application. All contributions must:
1. Pass comprehensive testing
2. Include security review
3. Follow secure coding practices
4. Include proper documentation

## License

[Specify your license here - consider GPL v3 for security tools]

## Disclaimer

This software is provided "as is" without warranty. Users are responsible for compliance with local laws and regulations regarding data destruction. The developers are not liable for data loss or misuse of this software.
