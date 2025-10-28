# Report Generation Feature

## Overview

The Shuddh data wiper now includes a comprehensive report generation feature that creates detailed JSON reports containing all information about the data wipe process.

## Report Contents

The generated report (`Shuddh_Wipe_Report_<SerialNumber>_<Timestamp>.json`) contains:

### 1. Report Metadata
- Report version
- Generation timestamp
- Drive serial number and model
- Report type

### 2. Drive Information Before Wipe
- **Basic Information:**
  - Drive index, letter, model, serial number
  - Size (bytes and GB)
  - Interface type (SATA, NVMe, USB, etc.)
  - Media type, drive type, firmware version
  
- **Partition Details:**
  - All partitions with their indexes, sizes, types
  - Drive letters, file systems, volume names
  - Bootable status, block sizes
  
- **Cluster & Sector Information:**
  - Sectors per cluster
  - Bytes per sector and per cluster
  - Total clusters, free clusters, used clusters
  
- **Volume Information:**
  - Volume name and serial number
  - Maximum component length
  - File system type
  - System flags
  
- **For USB Drives (FAT Information):**
  - File system type (FAT12, FAT16, FAT32, exFAT)
  - FAT cluster size
  - Total FAT clusters
  
- **Disk Geometry (HDD/SSD Parameters):**
  - Cylinders, tracks per cylinder
  - Sectors per track
  - Total heads, sectors, tracks
  - Bytes per sector
  
- **SSD/NVMe Specific Information:**
  - Model and interface
  - Firmware version
  - Capabilities
  
- **Pre-Wipe Statistics:**
  - File count before wipe
  - Used space before wipe (bytes)

### 3. Drive Information After Wipe
- Same structure as "Before" but captured after the wipe process
- Allows comparison to prove data deletion

### 4. Checksum Verification
- **Pre-Wipe Checksum:**
  - SHA-256 checksum of first 5MB of drive
  - Timestamp and data size
  - Status
  
- **Post-Wipe Checksum:**
  - SHA-256 checksum after wipe
  - Timestamp and data size
  - Status
  
- **Verification:**
  - Whether checksums are different
  - Data overwrite confirmation
  - Verification status (VERIFIED/FAILED)

### 5. Wipe Process Information
- Wipe method used
- Wipe method details
- Execution time
- Success status
- Files wiped count
- Bytes written/overwritten
- Partitions processed
- Command executed
- Forensic verification data (if available)

### 6. Footprint Deletion Proof
- **Footprints Scanned:**
  - Registry entries
  - Recent files
  - Prefetch files
  - Jump lists
  - Temp files
  
- **Deletion Proof:**
  - Files remaining count
  - Registry cleaned status
  - Recent files cleaned status
  - Prefetch cleaned status
  - Event logs cleared status

### 7. Data Deletion Proof
- **File Count Reduction:**
  - Files before wipe
  - Files after wipe
  - Total files deleted
  
- **Space Reclaimed:**
  - Used space before
  - Used space after
  - Total space reclaimed
  
- **Data Overwritten:**
  - Checksum changed confirmation
  - Bytes overwritten
  - Files wiped
  
- **Verification Status:**
  - Checksum verification result
  - Wipe success status
  - Overall status (VERIFIED/PARTIAL/FAILED)
  
- **Overwrite Evidence:**
  - Method used
  - Cryptographic overwrite (Yes/No)
  - Multiple passes (Yes/No)
  - Hardware-level erase (Yes/No)

## Report Location

All reports are saved to the user's **Desktop** for easy access:
- Path: `C:\Users\<Username>\Desktop\`
- Filename format: `Shuddh_Wipe_Report_<SerialNumber>_<Timestamp>.json`

## Report Features

### Dynamic Data Collection
- All data is collected dynamically from the system
- No hardcoded values
- Accurate real-time information

### Before and After Comparison
- Captures drive state before wipe
- Captures drive state after wipe
- Automatically compares to prove deletion

### Comprehensive Coverage
- File system parameters
- Hardware specifications
- Wipe process metrics
- Verification results
- Deletion evidence

### Proof of Data Destruction
- Checksum verification
- File count reduction
- Space reclamation
- Overwrite confirmation
- Cryptographic evidence

## Integration

The report generation is fully integrated into the main Shuddh workflow:

1. **Before Wipe:**
   - Collects drive information
   - Calculates pre-wipe checksum
   
2. **During Wipe:**
   - Tracks wipe process
   - Records metrics
   
3. **After Wipe:**
   - Collects post-wipe drive information
   - Calculates post-wipe checksum
   - Compares before/after states
   
4. **Report Generation:**
   - Compiles all data
   - Generates deletion proof
   - Saves comprehensive JSON report

## Usage

The report is automatically generated after every successful wipe operation. Users don't need to do anything special - the report will be saved to their Desktop along with the certificates.

## Example Report Structure

```json
{
  "report_metadata": {
    "report_version": "1.0",
    "generated_timestamp": "2025-10-28T...",
    "drive_serial": "WD-ABC123",
    "drive_model": "WDC WD10EZEX-08...",
    "report_type": "Data Wipe Comprehensive Report"
  },
  "drive_info_before": {
    "timestamp": "...",
    "drive_index": 1,
    "drive_letter": "E",
    "cluster_info": {
      "sectors_per_cluster": 8,
      "bytes_per_sector": 512,
      "bytes_per_cluster": 4096,
      "total_clusters": 244190625,
      "used_clusters": 1250000
    },
    "file_count_before": 1543,
    "used_space_before": 8547896320
  },
  "drive_info_after": {
    "file_count_after": 0,
    "used_space_after": 0
  },
  "checksum_verification": {
    "pre_wipe": {
      "checksum": "a1b2c3d4..."
    },
    "post_wipe": {
      "checksum": "e5f6g7h8..."
    },
    "verification": {
      "checksums_different": true,
      "verification_status": "VERIFIED"
    }
  },
  "data_deletion_proof": {
    "file_count_reduction": {
      "before": 1543,
      "after": 0,
      "deleted": 1543
    },
    "space_reclaimed": {
      "used_before": 8547896320,
      "used_after": 0,
      "reclaimed": 8547896320
    },
    "verification_status": {
      "overall_status": "VERIFIED"
    }
  }
}
```

## Technical Details

### Dependencies
- `wmi` - For WMI queries (drive/partition information)
- `win32file`, `win32api`, `win32con` - For Windows API access
- `pythoncom` - For COM initialization
- Standard library: `json`, `hashlib`, `datetime`, `pathlib`

### Classes
- **ReportGenerator** - Main class handling report generation
  - `collect_drive_info_before()` - Collects pre-wipe data
  - `collect_drive_info_after()` - Collects post-wipe data
  - `collect_checksum_data()` - Compiles checksum verification
  - `collect_wipe_process_info()` - Records wipe process details
  - `collect_footprint_deletion_proof()` - Evidence of footprint cleanup
  - `generate_data_deletion_proof()` - Comprehensive deletion proof
  - `save_report()` - Saves report to JSON file

### Error Handling
- All collection methods have try-except blocks
- Errors are logged but don't stop the process
- Missing data is marked with "error" status
- Partial reports are still generated even if some data fails

## Notes

- Report generation adds minimal overhead (a few seconds)
- Does not interfere with the wipe process
- Fully compatible with all wipe methods
- Works with USB, HDD, and SSD drives
- Automatically adapts to drive type (collects relevant parameters)
