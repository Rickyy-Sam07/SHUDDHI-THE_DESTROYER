"""
Logical Drive Detection
=======================
Detects and displays logical drives (drive letters) information
"""

import wmi

def get_drive_type_name(drive_type):
    """Convert numeric drive type to readable name"""
    types = {
        0: "Unknown",
        1: "No Root Directory", 
        2: "Removable (USB/Floppy)",
        3: "Fixed (HDD/SSD)",
        4: "Network Drive",
        5: "CD/DVD/Optical",
        6: "RAM Disk"
    }
    return types.get(drive_type, f"Unknown ({drive_type})")

def bytes_to_gb(bytes_val):
    """Convert bytes to GB"""
    if not bytes_val:
        return 0
    try:
        return round(int(bytes_val) / (1024**3), 2)
    except:
        return 0

def detect_logical_drives():
    """Detect all logical drives"""
    print("LOGICAL DRIVES (Drive Letters):")
    print("-" * 50)
    
    try:
        c = wmi.WMI()
        logical_drives = c.Win32_LogicalDisk()
        
        for drive in logical_drives:
            print(f"\nDrive {drive.DeviceID}:")
            print(f"  Label: {drive.VolumeName or 'No Label'}")
            print(f"  Type: {get_drive_type_name(drive.DriveType)}")
            print(f"  File System: {drive.FileSystem or 'Unknown'}")
            print(f"  Total Size: {bytes_to_gb(drive.Size)} GB")
            print(f"  Free Space: {bytes_to_gb(drive.FreeSpace)} GB")
            print(f"  Used Space: {bytes_to_gb(int(drive.Size or 0) - int(drive.FreeSpace or 0))} GB")
            
            # Calculate usage percentage
            if drive.Size and int(drive.Size) > 0:
                used_percent = ((int(drive.Size) - int(drive.FreeSpace or 0)) / int(drive.Size)) * 100
                print(f"  Usage: {used_percent:.1f}%")
        
        return len(list(logical_drives))
        
    except Exception as e:
        print(f"❌ Error detecting logical drives: {e}")
        return 0

if __name__ == "__main__":
    detect_logical_drives()
    input("Press Enter to exit...")