"""
USB Device Detection
====================
Detects and displays USB storage devices information
"""

import wmi

def bytes_to_gb(bytes_val):
    """Convert bytes to GB"""
    if not bytes_val:
        return 0
    try:
        return round(int(bytes_val) / (1024**3), 2)
    except:
        return 0

def detect_usb_devices():
    """Detect USB storage devices"""
    print("USB STORAGE DEVICES:")
    print("-" * 50)
    
    try:
        c = wmi.WMI()
        usb_devices = c.Win32_Volume(DriveType=2)  # Removable drives
        usb_count = 0
        
        for usb in usb_devices:
            if usb.DriveLetter:
                usb_count += 1
                print(f"\nUSB Drive {usb.DriveLetter}:")
                print(f"  Label: {usb.Label or 'No Label'}")
                print(f"  File System: {usb.FileSystem or 'Unknown'}")
                print(f"  Size: {bytes_to_gb(usb.Capacity)} GB")
                print(f"  Serial: {usb.SerialNumber or 'Unknown'}")
        
        if usb_count == 0:
            print("  No USB storage devices detected")
        
        return usb_count
        
    except Exception as e:
        print(f"❌ Error detecting USB devices: {e}")
        return 0

if __name__ == "__main__":
    detect_usb_devices()
    input("Press Enter to exit...")