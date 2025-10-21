"""
Optical Drive Detection
=======================
Detects and displays CD/DVD/Blu-ray drives information
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

def detect_optical_drives():
    """Detect optical drives"""
    print("OPTICAL DRIVES:")
    print("-" * 50)
    
    try:
        c = wmi.WMI()
        optical_drives = c.Win32_LogicalDisk(DriveType=5)
        optical_count = 0
        
        for optical in optical_drives:
            optical_count += 1
            print(f"\nOptical Drive {optical.DeviceID}:")
            print(f"  Label: {optical.VolumeName or 'No Media'}")
            print(f"  File System: {optical.FileSystem or 'No Media'}")
            if optical.Size:
                print(f"  Media Size: {bytes_to_gb(optical.Size)} GB")
            else:
                print(f"  Media Size: No Media Inserted")
        
        if optical_count == 0:
            print("  No optical drives detected")
        
        return optical_count
        
    except Exception as e:
        print(f"❌ Error detecting optical drives: {e}")
        return 0

if __name__ == "__main__":
    detect_optical_drives()
    input("Press Enter to exit...")