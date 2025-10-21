"""
Physical Drive Detection
========================
Detects and displays physical drive information (HDD, SSD, NVMe)
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

def get_media_type_name(media_type):
    """Convert media type to readable name"""
    if not media_type:
        return "Unknown"
    
    media_type = str(media_type).lower()
    if "fixed" in media_type:
        return "Fixed Disk"
    elif "removable" in media_type:
        return "Removable Disk"
    elif "external" in media_type:
        return "External Disk"
    else:
        return media_type.title()

def detect_physical_drives():
    """Detect all physical drives"""
    print("PHYSICAL DRIVES:")
    print("-" * 50)
    
    try:
        c = wmi.WMI()
        physical_drives = c.Win32_DiskDrive()
        
        for i, drive in enumerate(physical_drives):
            print(f"\nPhysical Drive {i}:")
            print(f"  Model: {drive.Model or 'Unknown'}")
            print(f"  Serial: {drive.SerialNumber or 'Unknown'}")
            print(f"  Size: {bytes_to_gb(drive.Size)} GB")
            print(f"  Interface: {drive.InterfaceType or 'Unknown'}")
            print(f"  Media Type: {get_media_type_name(drive.MediaType)}")
            print(f"  Partitions: {drive.Partitions or 0}")
            print(f"  Status: {drive.Status or 'Unknown'}")
            
            # Detect drive technology
            model_upper = str(drive.Model or '').upper()
            if any(ssd_indicator in model_upper for ssd_indicator in ['SSD', 'NVME', 'SOLID STATE']):
                tech = "SSD"
            elif 'USB' in str(drive.InterfaceType or '').upper():
                tech = "USB"
            else:
                tech = "HDD"
            print(f"  Technology: {tech}")
        
        return len(list(physical_drives))
        
    except Exception as e:
        print(f"❌ Error detecting physical drives: {e}")
        return 0

if __name__ == "__main__":
    detect_physical_drives()
    input("Press Enter to exit...")