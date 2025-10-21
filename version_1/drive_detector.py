"""
Drive Detector v1.0 - Main Controller
=====================================
Runs all drive detection modules and displays summary
"""

from malware_scanner import scan_for_malware
from physical_drives import detect_physical_drives
from logical_drives import detect_logical_drives
from usb_devices import detect_usb_devices
from optical_drives import detect_optical_drives
from system_info import get_system_info

def main():
    """Main function - runs all detection modules"""
    print("=" * 80)
    print("DRIVE DETECTION SYSTEM v1.0")
    print("=" * 80)
    
    try:
        # Run malware scan first
        print()
        malware_alerts = scan_for_malware()
        
        # Proceed with drive detection if system is clean or user confirms
        if malware_alerts > 0:
            print("\nWARNING: Malware indicators detected!")
            response = input("Continue with drive detection? (y/N): ")
            if response.lower() != 'y':
                print("Drive detection cancelled for security.")
                return
        
        # Run all detection modules
        print("\n" + "=" * 80)
        print("DRIVE DETECTION")
        print("=" * 80)
        print()
        physical_count = detect_physical_drives()
        
        print("\n")
        logical_count = detect_logical_drives()
        
        print("\n")
        usb_count = detect_usb_devices()
        
        print("\n")
        optical_count = detect_optical_drives()
        
        print("\n")
        get_system_info()
        
        # Summary
        print(f"\nSUMMARY:")
        print("-" * 50)
        print(f"  Malware Alerts: {malware_alerts}")
        print(f"  Physical Drives: {physical_count}")
        print(f"  Logical Drives: {logical_count}")
        print(f"  USB Drives: {usb_count}")
        print(f"  Optical Drives: {optical_count}")
        
    except KeyboardInterrupt:
        print("\n\nDetection interrupted by user")
    except Exception as e:
        print(f"\nFatal error: {e}")
    
    print("\n" + "=" * 80)
    input("Press Enter to exit...")

if __name__ == "__main__":
    main()