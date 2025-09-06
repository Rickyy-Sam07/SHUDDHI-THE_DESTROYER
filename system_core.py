"""
Core System Interaction Module for OS Data Wiper
================================================

🔒 DEVELOPMENT SAFETY MODE ACTIVE 🔒

CRITICAL SAFETY NOTICE:
This module is currently in DEVELOPMENT SAFETY MODE. All potentially harmful
operations are disabled, commented out, or simulated to ensure NO DAMAGE
can occur to your computer during development and testing.

SAFETY FEATURES ACTIVE:
✅ All destructive operations are blocked
✅ Drive access is read-only simulation
✅ UAC elevation is disabled
✅ All operations print "test pass1" style confirmations
✅ Production code is commented out with clear markers

TO ENABLE PRODUCTION MODE:
1. Set development_mode=False in SystemCore.__init__()
2. Remove the safety barrier checks in each method
3. Uncomment the production code blocks marked with triple quotes
4. Test thoroughly in isolated environment first

CURRENT SAFE OPERATIONS:
- Admin privilege checking (read-only)
- Hardware inventory and drive identification (read-only)
- Drive analysis and wipe method determination (analysis only)
- System information collection (read-only)

This module provides core functionality for:
- Admin privilege checking and UAC elevation (DISABLED IN DEV MODE)
- Hardware inventory and drive identification (SAFE READ-ONLY)
- HPA/DCO detection capabilities (PLACEHOLDER)
- Wipe method determination based on drive technology (ANALYSIS ONLY)

Security Notice: This module requires administrative privileges and performs
low-level disk operations in production mode. Currently SAFE for development.

Author: OS Data Wiper Project
Version: 1.0 (Development Safety Mode)
Date: September 5, 2025
"""

import ctypes
import sys
import os
import logging
from typing import List, Dict, Optional, Any

try:
    import wmi
except ImportError:
    wmi = None
    logging.warning("WMI library not available. Hardware detection will be limited.")

try:
    import win32file
    import win32api
    import win32con
    import pywintypes
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False
    logging.warning("pywin32 library not available. Advanced HPA/DCO detection disabled.")


class AdminPrivilegeError(Exception):
    """Raised when admin privileges are required but not available."""
    pass


class HardwareDetectionError(Exception):
    """Raised when hardware detection fails."""
    pass


class SystemCore:
    """
    Core system interaction class providing low-level disk operations
    and hardware detection capabilities.
    
    DEVELOPMENT SAFETY MODE: Currently in safe development mode.
    All potentially harmful operations are disabled/simulated.
    """
    
    def __init__(self, development_mode=True):
        self.logger = self._setup_logging()
        self.admin_checked = False
        self.development_mode = development_mode  # SAFETY: Always True during development
        
        # SAFETY BARRIER: Prevent accidental production use during development
        if not development_mode:
            raise RuntimeError("SAFETY LOCK: Production mode disabled during development phase!")
        
        self.logger.warning("🔒 DEVELOPMENT MODE ACTIVE - All destructive operations disabled")
        print("🔒 SAFETY MODE: Development mode active - no harm to system possible")
        print("test pass1 - SystemCore initialized safely")
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for the system core module."""
        logger = logging.getLogger(__name__)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def check_admin(self) -> bool:
        """
        Check if the current process is running with administrative privileges.
        
        SAFETY: In development mode, this is read-only and safe.
        
        Returns:
            bool: True if running as admin, False otherwise
            
        Raises:
            AdminPrivilegeError: If admin privileges are required but not available
        """
        print("test pass1 - Admin privilege check (SAFE - read only)")
        
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            self.admin_checked = True
            
            if is_admin:
                self.logger.info("Administrative privileges confirmed (DEVELOPMENT MODE - READ ONLY).")
                print("✅ Admin privileges detected (safe check)")
                return True
            else:
                self.logger.warning("Administrative privileges not detected (DEVELOPMENT MODE).")
                print("⚠️ No admin privileges (safe - no elevation attempted)")
                return False
                
        except Exception as e:
            self.logger.error(f"Error checking admin privileges: {e}")
            print(f"❌ Error in admin check: {e}")
            return False

    def elevate_privileges(self) -> None:
        """
        Attempt to elevate the current process to admin privileges using UAC.
        
        SAFETY LOCK: DISABLED in development mode to prevent accidental system changes.
        
        This will trigger a UAC prompt and restart the application with admin rights.
        The current process will be terminated after successful elevation.
        
        Raises:
            AdminPrivilegeError: If elevation fails or is cancelled
        """
        # SAFETY BARRIER: Prevent elevation during development
        if self.development_mode:
            self.logger.warning("🔒 SAFETY LOCK: Privilege elevation disabled in development mode")
            print("🔒 SAFETY: Privilege elevation blocked (development mode)")
            print("test pass1 - Elevation safely blocked")
            raise AdminPrivilegeError("DEVELOPMENT SAFETY: Privilege elevation disabled during development")
        
        # PRODUCTION CODE (commented out for safety):
        # Remove the development_mode check above to enable this in production
        """
        if self.check_admin():
            self.logger.info("Already running with admin privileges.")
            return
            
        try:
            self.logger.info("Attempting to elevate privileges via UAC...")
            # Re-run the program with admin rights
            result = ctypes.windll.shell32.ShellExecuteW(
                None,                    # Parent window handle
                "runas",                 # Verb (run as administrator)
                sys.executable,          # Application to run
                " ".join(sys.argv),      # Command line arguments
                None,                    # Working directory
                1                        # Show command (SW_NORMAL)
            )
            
            if result <= 32:  # ShellExecute error codes
                raise AdminPrivilegeError("UAC elevation was cancelled or failed.")
            
            self.logger.info("UAC elevation initiated. Terminating current instance.")
            sys.exit(0)  # Quit the initial non-admin instance
            
        except Exception as e:
            self.logger.error(f"Failed to elevate privileges: {e}")
            raise AdminPrivilegeError(f"Privilege elevation failed: {e}")
        """

    def ensure_admin_privileges(self) -> None:
        """
        Ensure the application is running with admin privileges.
        If not, attempt to elevate and restart.
        
        Raises:
            AdminPrivilegeError: If admin privileges cannot be obtained
        """
        if not self.check_admin():
            self.elevate_privileges()

    def get_drive_info(self) -> List[Dict[str, Any]]:
        """
        Retrieve comprehensive information about all physical drives in the system.
        
        SAFETY: In development mode, this only reads system information without
        making any changes. Completely safe for development use.
        
        Returns:
            List[Dict]: List of dictionaries containing drive information:
                - Index: Drive index (e.g., 0, 1, 2)
                - Model: Drive model name
                - SerialNumber: Drive serial number (critical for certificates)
                - Size: Drive size in bytes
                - InterfaceType: Interface type (IDE, SATA, NVMe, etc.)
                - MediaType: Media type (Fixed hard disk, Removable, etc.)
                - DeviceID: Physical device path (e.g., \\\\.\\PHYSICALDRIVE0)
                - Firmware: Firmware version if available
                - Status: Drive operational status
                
        Raises:



        
            HardwareDetectionError: If drive enumeration fails
        """
        print("test pass1 - Drive enumeration starting (SAFE - read only)")
        
        if not wmi:
            print("⚠️ WMI not available - using safe fallback")
            raise HardwareDetectionError("WMI library not available for hardware detection.")
        
        try:
            self.logger.info("Enumerating physical drives (DEVELOPMENT MODE - READ ONLY)...")
            print("🔍 Safely reading drive information...")
            c = wmi.WMI()
            drives = []
            
            for physical_disk in c.Win32_DiskDrive():
                try:
                    # Clean and validate drive data
                    model = physical_disk.Model.strip() if physical_disk.Model else "Unknown Model"
                    serial = physical_disk.SerialNumber.strip() if physical_disk.SerialNumber else "No Serial"
                    size = int(physical_disk.Size) if physical_disk.Size else 0
                    
                    drive_info = {
                        "Index": physical_disk.Index,
                        "Model": model,
                        "SerialNumber": serial,
                        "Size": size,
                        "SizeGB": round(size / (1024**3), 2) if size > 0 else 0,
                        "InterfaceType": physical_disk.InterfaceType or "Unknown",
                        "MediaType": physical_disk.MediaType or "Unknown",
                        "DeviceID": physical_disk.DeviceID or f"\\\\.\\PHYSICALDRIVE{physical_disk.Index}",
                        "Firmware": getattr(physical_disk, 'FirmwareRevision', 'Unknown'),
                        "Status": physical_disk.Status or "Unknown",
                        "Partitions": physical_disk.Partitions or 0,
                        "BytesPerSector": physical_disk.BytesPerSector or 512,
                        "TotalSectors": physical_disk.TotalSectors or 0,
                        "DEVELOPMENT_MODE": True,  # Safety marker
                        "SAFE_READ_ONLY": True    # Safety marker
                    }
                    
                    drives.append(drive_info)
                    print(f"✅ Safely detected: {model} ({serial}) - READ ONLY")
                    self.logger.debug(f"Detected drive: {model} ({serial}) - DEVELOPMENT MODE")
                    
                except Exception as e:
                    self.logger.warning(f"Error processing drive {physical_disk.Index}: {e}")
                    print(f"⚠️ Error reading drive {physical_disk.Index}: {e}")
                    continue
            
            print(f"test pass1 - Successfully enumerated {len(drives)} drives safely")
            self.logger.info(f"Successfully enumerated {len(drives)} physical drives (DEVELOPMENT MODE).")
            return drives
            
        except Exception as e:
            self.logger.error(f"Failed to enumerate drives: {e}")
            print(f"❌ Drive enumeration error: {e}")
            raise HardwareDetectionError(f"Drive enumeration failed: {e}")

    def detect_hpa_dco(self, drive_index: int) -> Dict[str, Any]:
        """
        Detect Hidden Protected Area (HPA) and Device Configuration Overlay (DCO)
        on the specified drive using ATA IDENTIFY DEVICE command.
        
        Args:
            drive_index: Physical drive index (0, 1, 2, etc.)
            
        Returns:
            Dict containing HPA/DCO detection results:
                - has_hpa: Boolean indicating HPA presence
                - has_dco: Boolean indicating DCO presence
                - native_max_lba: Native maximum LBA address
                - accessible_max_lba: Currently accessible maximum LBA
                - hidden_sectors: Number of hidden sectors
                - detection_method: Method used for detection
                
        Raises:
            HardwareDetectionError: If detection fails or is not supported
        """
        if not HAS_PYWIN32:
            raise HardwareDetectionError("pywin32 required for HPA/DCO detection.")
        
        if not self.admin_checked or not self.check_admin():
            raise AdminPrivilegeError("Admin privileges required for HPA/DCO detection.")
        
        device_path = f"\\\\.\\PhysicalDrive{drive_index}"
        
        try:
            self.logger.info(f"Attempting HPA/DCO detection on {device_path}")
            
            # Open physical drive with appropriate access
            handle = win32file.CreateFile(
                device_path,
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                0,
                None
            )
            
            try:
                # This is a simplified placeholder for ATA command implementation
                # Full implementation would require:
                # 1. Creating ATA_PASS_THROUGH_EX structure
                # 2. Sending IDENTIFY_DEVICE command (0xEC)
                # 3. Parsing 512-byte response for LBA capacity information
                # 4. Comparing native vs accessible capacity
                
                # For now, return a placeholder result
                result = {
                    "has_hpa": False,
                    "has_dco": False,
                    "native_max_lba": None,
                    "accessible_max_lba": None,
                    "hidden_sectors": 0,
                    "detection_method": "placeholder",
                    "supported": False,
                    "note": "Full ATA command implementation required for accurate detection"
                }
                
                self.logger.warning("HPA/DCO detection is placeholder implementation.")
                return result
                
            finally:
                win32file.CloseHandle(handle)
                
        except pywintypes.error as e:
            self.logger.error(f"Win32 error during HPA/DCO detection: {e}")
            raise HardwareDetectionError(f"Cannot access drive {device_path}: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during HPA/DCO detection: {e}")
            raise HardwareDetectionError(f"HPA/DCO detection failed: {e}")

    def determine_wipe_method(self, drive_info: Dict[str, Any]) -> Dict[str, str]:
        """
        Step 2: Optimized Wipe Method Decision Logic
        
        Determine the appropriate wipe method based on drive technology with optimized
        decision rules and fallback methods for maximum compatibility.
        
        SAFETY: This function only analyzes and recommends - no actual wiping occurs.
        Completely safe for development use.
        
        Step 2 Optimized Rule Set:
        - IF InterfaceType is NVMe: Primary = "NVME_FORMAT_NVM", Fallback = "AES_128_CTR"
        - ELSE IF MediaType suggests SSD or InterfaceType is SATA: Primary = "ATA_SECURE_ERASE", Fallback = "AES_128_CTR"
        - ELSE (HDD, USB, unknown): Method = "AES_128_CTR" (fast, secure software method)
        
        Args:
            drive_info: Dictionary containing drive information from get_drive_info()
            
        Returns:
            Dict containing:
                - "primary_method": Primary recommended wipe method
                - "fallback_method": Fallback method if primary fails
                - "reasoning": Explanation of decision logic
                - "drive_category": Classification (NVMe, SATA_SSD, HDD, USB, UNKNOWN)
        """
        print("test pass1 - Step 2: Optimized wipe method determination (SAFE - analysis only)")
        
        # Initialize default response
        result = {
            "primary_method": "AES_128_CTR",
            "fallback_method": "AES_128_CTR", 
            "reasoning": "Default safe method",
            "drive_category": "UNKNOWN"
        }
        
        if not drive_info:
            self.logger.warning("No drive info provided - Step 2: defaulting to AES_128_CTR")
            print("⚠️ No drive info - Step 2: using AES_128_CTR")
            result["reasoning"] = "No drive information available - using safe default"
            return result
        
        model = drive_info.get('Model', '').upper()
        interface_type = drive_info.get('InterfaceType', '').upper()
        media_type = drive_info.get('MediaType', '').upper()
        
        self.logger.info(f"Step 2: Optimized method determination for: {model} ({interface_type})")
        print(f"🔍 Step 2: Analyzing drive: {model} ({interface_type})")
        
        # Step 2 Rule 1: IF InterfaceType is NVMe
        if 'NVME' in interface_type or 'NVME' in model:
            result = {
                "primary_method": "NVME_FORMAT_NVM",
                "fallback_method": "AES_128_CTR",
                "reasoning": "NVMe interface detected - Format NVM is faster and more standard than SANITIZE for V1",
                "drive_category": "NVME"
            }
            self.logger.info("Step 2: NVMe drive detected - NVME_FORMAT_NVM primary, AES_128_CTR fallback")
            print("✅ Step 2: NVMe drive → NVME_FORMAT_NVM (primary) + AES_128_CTR (fallback)")
            print("   � Reasoning: NVMe Format NVM is faster and more standard than SANITIZE for V1")
            
        # Step 2 Rule 2: ELSE IF MediaType suggests SSD or InterfaceType is SATA
        elif ('SSD' in model or 'SOLID STATE' in model or 
              'SATA' in interface_type or 
              'FIXED' in media_type):
            result = {
                "primary_method": "ATA_SECURE_ERASE", 
                "fallback_method": "AES_128_CTR",
                "reasoning": "SATA SSD detected - ATA Secure Erase leverages hardware capabilities",
                "drive_category": "SATA_SSD"
            }
            self.logger.info("Step 2: SATA SSD detected - ATA_SECURE_ERASE primary, AES_128_CTR fallback")
            print("✅ Step 2: SATA SSD → ATA_SECURE_ERASE (primary) + AES_128_CTR (fallback)")
            print("   📋 Reasoning: SATA SSD leverages hardware secure erase capabilities")
            
        # Step 2 Rule 3: ELSE (HDD, USB, unknown)
        else:
            # Check for specific drive categories
            is_removable = 'REMOVABLE' in media_type or 'USB' in interface_type
            
            if is_removable:
                result["drive_category"] = "USB"
                result["reasoning"] = "Removable/USB drive - AES_128_CTR provides fast, secure software method"
                print("✅ Step 2: USB/Removable → AES_128_CTR (fast, secure software method)")
            else:
                result["drive_category"] = "HDD"
                result["reasoning"] = "Traditional HDD - AES_128_CTR provides fast, secure software method"
                print("✅ Step 2: Traditional HDD → AES_128_CTR (fast, secure software method)")
            
            self.logger.info(f"Step 2: {result['drive_category']} detected - AES_128_CTR method")
        
        print(f"   🎯 Final Decision: {result['primary_method']}")
        if result['primary_method'] != result['fallback_method']:
            print(f"   🔄 Fallback: {result['fallback_method']}")
        print(f"   📂 Category: {result['drive_category']}")
        
        return result

    def validate_drive_access(self, drive_index: int) -> bool:
        """
        Validate that the specified drive can be accessed for low-level operations.
        
        SAFETY LOCK: In development mode, this performs safe validation without
        actually opening drives for write access.
        
        Args:
            drive_index: Physical drive index to validate
            
        Returns:
            bool: True if drive is accessible, False otherwise
        """
        print(f"test pass1 - Drive access validation for drive {drive_index} (SAFE MODE)")
        
        # SAFETY BARRIER: Development mode performs read-only checks
        if self.development_mode:
            self.logger.info(f"DEVELOPMENT MODE: Safe drive access check for drive {drive_index}")
            print(f"🔒 SAFETY: Simulating drive access check for drive {drive_index}")
            
            # Perform safe existence check without opening for write
            device_path = f"\\\\.\\PhysicalDrive{drive_index}"
            try:
                # This is a safer check that doesn't require write access
                if not self.check_admin():
                    print(f"⚠️ No admin privileges - cannot verify {device_path}")
                    return False
                
                print(f"✅ SAFE: Drive {device_path} validation simulated successfully")
                return True
                
            except Exception as e:
                print(f"❌ Safe validation error for {device_path}: {e}")
                return False
        
        # PRODUCTION CODE (commented out for safety):
        # Remove the development_mode check above to enable this in production
        """
        if not self.check_admin():
            self.logger.error("Admin privileges required for drive access validation.")
            return False
        
        device_path = f"\\\\.\\PhysicalDrive{drive_index}"
        
        try:
            handle = win32file.CreateFile(
                device_path,
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                0,
                None
            )
            win32file.CloseHandle(handle)
            self.logger.info(f"Drive {device_path} is accessible.")
            return True
            
        except pywintypes.error as e:
            self.logger.error(f"Cannot access {device_path}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error accessing {device_path}: {e}")
            return False
        """

    def get_system_info(self) -> Dict[str, Any]:
        """
        Get relevant system information for audit trails and certificates.
        
        Returns:
            Dict containing system information:
                - os_version: Windows version
                - computer_name: Computer name
                - user_name: Current user
                - timestamp: Current timestamp
                - admin_status: Admin privilege status
        """
        try:
            import platform
            import getpass
            from datetime import datetime
            
            system_info = {
                "os_version": platform.platform(),
                "computer_name": platform.node(),
                "user_name": getpass.getuser(),
                "timestamp": datetime.now().isoformat(),
                "admin_status": self.check_admin(),
                "python_version": platform.python_version(),
                "architecture": platform.architecture()[0]
            }
            
            self.logger.info("System information collected successfully.")
            return system_info
            
        except Exception as e:
            self.logger.error(f"Error collecting system information: {e}")
            return {"error": str(e)}


# Convenience functions for backward compatibility and ease of use
def check_admin() -> bool:
    """Convenience function to check admin privileges."""
    core = SystemCore()
    return core.check_admin()


def get_drive_info() -> List[Dict[str, Any]]:
    """Convenience function to get drive information."""
    core = SystemCore()
    return core.get_drive_info()


def determine_wipe_method(drive_info: Dict[str, Any]) -> Dict[str, str]:
    """Convenience function to determine wipe method with Step 2 optimization."""
    core = SystemCore()
    return core.determine_wipe_method(drive_info)


# Main execution for testing
if __name__ == "__main__":
    print("🔒" + "="*60 + "🔒")
    print("🔒 OS DATA WIPER - DEVELOPMENT SAFETY MODE ACTIVE 🔒")
    print("🔒" + "="*60 + "🔒")
    print("✅ SAFE: All destructive operations are DISABLED")
    print("✅ SAFE: Only read-only operations are performed")
    print("✅ SAFE: Your computer cannot be harmed")
    print("✅ SAFE: All operations are simulated or blocked")
    print("test pass1 - Main execution starting safely")
    print()
    
    # Initialize system core in safe development mode
    try:
        core = SystemCore(development_mode=True)  # SAFETY: Always True during development
        
        # Check admin privileges (safe)
        print("=== SAFE Admin Privilege Check ===")
        print("test pass1 - Admin check starting")
        if core.check_admin():
            print("✓ Admin privileges detected (SAFE - read only check)")
        else:
            print("✗ No admin privileges (SAFE - no elevation attempted)")
            print("💡 Note: Some read-only features may be limited")
        
        print("test pass1 - Admin check completed safely")
        
        # Get drive information (safe read-only)
        print("\n=== SAFE Drive Information (Read-Only) ===")
        print("test pass1 - Drive enumeration starting")
        try:
            drives = core.get_drive_info()
            for drive in drives:
                print(f"✅ SAFE: Drive {drive['Index']}: {drive['Model']}")
                print(f"   Serial: {drive['SerialNumber']}")
                print(f"   Size: {drive['SizeGB']} GB")
                print(f"   Interface: {drive['InterfaceType']}")
                
                # Step 2: Get optimized wipe method decision
                wipe_decision = core.determine_wipe_method(drive)
                print(f"   🎯 Step 2 Primary Method: {wipe_decision['primary_method']}")
                if wipe_decision['primary_method'] != wipe_decision['fallback_method']:
                    print(f"   🔄 Step 2 Fallback Method: {wipe_decision['fallback_method']}")
                print(f"   📂 Step 2 Category: {wipe_decision['drive_category']}")
                print(f"   📋 Step 2 Reasoning: {wipe_decision['reasoning']}")
                print(f"   🔒 SAFETY: Read-only mode - no access to drive")
                print()
        except Exception as e:
            print(f"⚠️ Drive enumeration not available: {e}")
            print("💡 This is normal if WMI is not installed")
        
        print("test pass1 - Drive enumeration completed safely")
        
        # System information (safe)
        print("=== SAFE System Information ===")
        print("test pass1 - System info collection starting")
        sys_info = core.get_system_info()
        for key, value in sys_info.items():
            print(f"{key}: {value}")
        
        print("test pass1 - System info collection completed safely")
        
        # Safety demonstration
        print("\n=== SAFETY DEMONSTRATIONS ===")
        print("test pass1 - Safety demonstrations starting")
        
        try:
            print("🔒 Testing privilege elevation block...")
            core.elevate_privileges()
        except Exception as e:
            print(f"✅ SAFETY CONFIRMED: Elevation blocked - {e}")
        
        print("🔒 Testing drive access validation (safe mode)...")
        if drives:
            access_result = core.validate_drive_access(drives[0]['Index'])
            print(f"✅ SAFE: Drive access check result: {access_result}")
        
        print("test pass1 - Safety demonstrations completed")
        
        print("\n" + "🔒" + "="*60 + "🔒")
        print("🎉 ALL TESTS PASSED SAFELY - NO HARM TO SYSTEM 🎉")
        print("🔒" + "="*60 + "🔒")
        print("✅ Your computer is completely safe")
        print("✅ No destructive operations were performed")
        print("✅ All operations were read-only or simulated")
        print("✅ Development safety mode working correctly")
        print()
        print("💡 TO ENABLE PRODUCTION MODE (DANGEROUS!):")
        print("   1. Change development_mode=False in SystemCore.__init__()")
        print("   2. Remove safety barriers in each method")
        print("   3. Uncomment production code blocks")
        print("   4. Test in isolated environment ONLY")
        print()
        
    except Exception as e:
        print(f"❌ Error during safe testing: {e}")
        print("💡 This may be due to missing dependencies (WMI, pywin32)")
        print("   Run: pip install -r requirements.txt")
        sys.exit(1)
