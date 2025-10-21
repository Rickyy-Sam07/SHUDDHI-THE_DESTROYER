# Drive Detector v1.0

Modular terminal-based drive detection tool with separate scripts for different drive types.

## Scripts

- **`drive_detector.py`** - Main controller (runs all modules)
- **`physical_drives.py`** - Physical drive detection (HDD/SSD/NVMe)
- **`logical_drives.py`** - Logical drive detection (drive letters)
- **`usb_devices.py`** - USB storage device detection
- **`optical_drives.py`** - CD/DVD/Blu-ray drive detection
- **`system_info.py`** - System information and computer details
- **`malware_scanner.py`** - WMI-based malware detection (runs first)

## Usage

```cmd
# Install dependencies
pip install -r requirements.txt

# Run all detectors
python drive_detector.py

# Run individual detectors
python physical_drives.py
python logical_drives.py
python usb_devices.py
python optical_drives.py
python system_info.py
python malware_scanner.py
```

## Features

- **Modular Design**: Each drive type has its own script
- **Physical Drives**: Model, serial, size, interface, technology detection
- **Logical Drives**: File system, usage, free space percentages
- **USB Devices**: Removable storage with capacity and labels
- **Optical Drives**: CD/DVD detection with media status
- **System Info**: Computer name, RAM, OS, system drive details

## Requirements

- Windows 10/11
- Administrator privileges
- Python 3.6+
- WMI support

## Output

Each script displays organized terminal output with:
- Drive models and serial numbers
- Sizes in GB with usage percentages
- File systems and drive types
- Technology classification (SSD/HDD/USB)
- Real-time system detection (no hardcoded data)