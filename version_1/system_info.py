"""
System Information
==================
Displays system drive and computer information
"""

import wmi
import os

def bytes_to_gb(bytes_val):
    """Convert bytes to GB"""
    if not bytes_val:
        return 0
    try:
        return round(int(bytes_val) / (1024**3), 2)
    except:
        return 0

def get_system_info():
    """Get system information"""
    print("SYSTEM INFORMATION:")
    print("-" * 50)
    
    try:
        c = wmi.WMI()
        
        # System drive
        system_drive = os.environ.get('SystemDrive', 'C:')
        print(f"  System Drive: {system_drive}")
        
        # Get system drive details
        logical_drives = c.Win32_LogicalDisk()
        for drive in logical_drives:
            if drive.DeviceID == system_drive:
                print(f"  System Drive Size: {bytes_to_gb(drive.Size)} GB")
                print(f"  System Drive Free: {bytes_to_gb(drive.FreeSpace)} GB")
                break
        
        # Computer info
        computer_info = c.Win32_ComputerSystem()[0]
        print(f"  Computer Name: {computer_info.Name}")
        print(f"  Total RAM: {bytes_to_gb(computer_info.TotalPhysicalMemory)} GB")
        
        # OS info
        os_info = c.Win32_OperatingSystem()[0]
        print(f"  OS: {os_info.Caption}")
        print(f"  Architecture: {os_info.OSArchitecture}")
        
    except Exception as e:
        print(f"❌ Error getting system info: {e}")

if __name__ == "__main__":
    get_system_info()
    input("Press Enter to exit...")