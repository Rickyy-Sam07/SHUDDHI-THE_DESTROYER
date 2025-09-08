"""
Production System Core functions

PRODUCTION VERSION - ALL SAFETY FEATURES REMOVED
This script contains functions that interact with system hardware and require
administrative privileges.

Key Responsibilities:
- Hardware detection using Windows Management Instrumentation (WMI)
- Administrator privilege checking and elevation
- Drive enumeration and characterization
- Wipe method determination based on drive type
- Drive access validation for security

Security Notes:
- All operations require administrator privileges
- Uses ctypes for Windows API calls
- WMI queries for hardware information
- Input validation to prevent injection attacks
"""

import ctypes
import sys
import os
import logging
from typing import List, Dict, Any

try:
    import wmi
except ImportError:
    wmi = None

try:
    import win32file
    import win32api
    import win32con
    import pywintypes
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False


class AdminPrivilegeError(Exception):
    pass


class HardwareDetectionError(Exception):
    pass


class SystemCore:
    """Core system functions for hardware detection and privilege management
    
    This class handles all low-level system interactions including:
    - Windows administrator privilege checking and elevation
    - Hardware enumeration using WMI (Windows Management Instrumentation)
    - Drive type detection and wipe method determination
    - System security validation
    """
    
    def __init__(self, development_mode=False):
        """Initialize system core with logging and privilege tracking
        
        Args:
            development_mode (bool): If True, enables additional safety checks
        """
        self.logger = self._setup_logging()
        self.admin_checked = False      # Track if admin privileges have been verified
        self.development_mode = development_mode  # Controls safety features
        
    def _setup_logging(self) -> logging.Logger:
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
        """Check if current process has administrator privileges
        
        Uses Windows API through ctypes to check if the current process
        is running with administrator privileges. This is required for
        direct drive access operations.
        
        Returns:
            bool: True if running as administrator, False otherwise
        """
        try:
            # Use Windows Shell32 API to check admin status
            # IsUserAnAdmin() returns non-zero if current user is admin
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            self.admin_checked = True
            return is_admin
        except Exception as e:
            self.logger.error(f"Error checking admin privileges: {e}")
            return False

    def elevate_privileges(self) -> None:
        """Attempt to elevate current process to administrator privileges
        
        Uses Windows UAC (User Account Control) to request administrator
        privileges. If successful, restarts the application with admin rights.
        If the user cancels UAC or elevation fails, raises an exception.
        
        Raises:
            AdminPrivilegeError: If elevation fails or is cancelled
        """
        # Skip elevation if already admin
        if self.check_admin():
            return
            
        try:
            # Use ShellExecuteW with "runas" verb to trigger UAC elevation
            # This will show the UAC prompt to the user
            result = ctypes.windll.shell32.ShellExecuteW(
                None,                    # Parent window handle
                "runas",                # Verb - requests elevation
                sys.executable,         # Program to run (Python interpreter)
                " ".join(sys.argv),     # Command line arguments
                None,                   # Working directory
                1                       # Show window (SW_SHOWNORMAL)
            )
            
            # ShellExecuteW returns > 32 on success, <= 32 on failure
            if result <= 32:
                raise AdminPrivilegeError("UAC elevation was cancelled or failed.")
            
            # If elevation succeeded, the new process is starting
            # Exit this non-elevated process
            sys.exit(0)
            
        except (OSError, ctypes.WinError) as e:
            raise AdminPrivilegeError(f"Privilege elevation failed: {e}")
        except Exception as e:
            self.logger.critical(f"Unexpected error during privilege elevation: {e}")
            raise AdminPrivilegeError(f"Privilege elevation failed: {e}")

    def ensure_admin_privileges(self) -> None:
        if not self.check_admin():
            self.elevate_privileges()

    def get_drive_info(self) -> List[Dict[str, Any]]:
        """Enumerate all physical drives using Windows Management Instrumentation
        
        Queries WMI Win32_DiskDrive class to get comprehensive information
        about all physical storage devices in the system. This includes
        SSDs, HDDs, NVMe drives, and USB drives.
        
        Returns:
            List[Dict[str, Any]]: List of drive information dictionaries
            
        Raises:
            HardwareDetectionError: If WMI is unavailable or enumeration fails
        """
        if not wmi:
            raise HardwareDetectionError("WMI library not available for hardware detection.")
        
        try:
            # Initialize WMI connection to local machine
            c = wmi.WMI()
            drives = []
            
            # Query all physical disk drives
            for physical_disk in c.Win32_DiskDrive():
                try:
                    # Extract and sanitize drive information
                    # Handle cases where WMI returns None or empty values
                    model = physical_disk.Model.strip() if physical_disk.Model else "Unknown Model"
                    serial = physical_disk.SerialNumber.strip() if physical_disk.SerialNumber else "No Serial"
                    size = int(physical_disk.Size) if physical_disk.Size else 0
                    
                    # Build comprehensive drive information dictionary
                    drive_info = {
                        "Index": physical_disk.Index,                    # Physical drive number (0, 1, 2, etc.)
                        "Model": model,                                  # Drive model name
                        "SerialNumber": serial,                         # Unique serial number
                        "Size": size,                                   # Size in bytes
                        "SizeGB": round(size / (1024**3), 2) if size > 0 else 0,  # Size in GB
                        "InterfaceType": physical_disk.InterfaceType or "Unknown",  # SATA, NVMe, USB, etc.
                        "MediaType": physical_disk.MediaType or "Unknown",        # Fixed, Removable, etc.
                        "DeviceID": physical_disk.DeviceID or f"\\\\.\\PhysicalDrive{physical_disk.Index}",  # Windows device path
                        "Firmware": getattr(physical_disk, 'FirmwareRevision', 'Unknown'),  # Firmware version
                        "Status": physical_disk.Status or "Unknown",             # Drive health status
                        "Partitions": physical_disk.Partitions or 0,             # Number of partitions
                        "BytesPerSector": physical_disk.BytesPerSector or 512,   # Sector size
                        "TotalSectors": physical_disk.TotalSectors or 0          # Total sector count
                    }
                    
                    drives.append(drive_info)
                    
                except Exception as e:
                    # Log individual drive errors but continue enumeration
                    sanitized_error = str(e).replace('\n', ' ').replace('\r', '')
                    self.logger.warning(f"Error processing drive {physical_disk.Index}: {sanitized_error}")
                    continue
            
            return drives
            
        except Exception as e:
            raise HardwareDetectionError(f"Drive enumeration failed: {e}")

    def determine_wipe_method(self, drive_info: Dict[str, Any]) -> Dict[str, str]:
        """Determine the optimal wipe method based on drive characteristics
        
        Analyzes drive type, interface, and model to select the most appropriate
        data destruction method. Different drive types support different secure
        erase commands with varying levels of effectiveness.
        
        Drive Type Detection Logic:
        - NVMe drives: Use FORMAT_NVM command (fastest, hardware-level)
        - SATA SSDs: Use ATA SECURE ERASE command (hardware-level)
        - HDDs/Others: Use AES-128-CTR overwrite (software-level, universal)
        
        Args:
            drive_info (Dict[str, Any]): Drive information from get_drive_info()
            
        Returns:
            Dict[str, str]: Wipe method decision with primary/fallback methods
        """
        # Default safe method that works on all drive types
        result = {
            "primary_method": "AES_128_CTR",      # Software overwrite method
            "fallback_method": "AES_128_CTR",     # Same as primary for safety
            "reasoning": "Default safe method",
            "drive_category": "UNKNOWN"
        }
        
        if not drive_info:
            return result
        
        # Extract drive characteristics for analysis
        model_upper = drive_info.get('Model', '').upper()
        interface_type_upper = drive_info.get('InterfaceType', '').upper()
        media_type_upper = drive_info.get('MediaType', '').upper()
        
        # NVMe Drive Detection (highest priority)
        # NVMe drives support FORMAT_NVM command for instant secure erase
        if ('NVME' in interface_type_upper and interface_type_upper != 'SATA') or 'NVME' in model_upper:
            result = {
                "primary_method": "NVME_FORMAT_NVM",   # Hardware-level format command
                "fallback_method": "AES_128_CTR",      # Software fallback if hardware fails
                "reasoning": "Confirmed NVMe interface detected",
                "drive_category": "NVME"
            }
            
        # SATA SSD Detection (medium priority)
        # SATA SSDs support ATA SECURE ERASE for hardware-level wiping
        elif (('SSD' in model_upper or 'SOLID STATE' in model_upper) and 
              'HDD' not in model_upper and 'HARD DISK' not in model_upper and
              'SATA' in interface_type_upper and 'FIXED' in media_type_upper):
            result = {
                "primary_method": "ATA_SECURE_ERASE",  # Hardware secure erase command
                "fallback_method": "AES_128_CTR",      # Software fallback
                "reasoning": "Confirmed SATA SSD detected",
                "drive_category": "SATA_SSD"
            }
            
        # Traditional HDDs and Unknown Drives (lowest priority)
        # Use software overwrite method for maximum compatibility
        else:
            is_removable = 'REMOVABLE' in media_type_upper or 'USB' in interface_type_upper
            
            if is_removable:
                result["drive_category"] = "USB"
                result["reasoning"] = "Removable/USB drive - using safe AES method"
            else:
                result["drive_category"] = "HDD"
                result["reasoning"] = "Traditional HDD or uncertain type - using safe AES method"
        
        return result

    def validate_drive_access(self, drive_index: int) -> bool:
        """Validate that we can access the specified drive for read/write operations
        
        Attempts to open the physical drive with read/write access to ensure
        that wipe operations will succeed. This prevents starting a wipe operation
        only to fail partway through due to access restrictions.
        
        Args:
            drive_index (int): Physical drive index (0, 1, 2, etc.)
            
        Returns:
            bool: True if drive can be accessed, False otherwise
        """
        # Require administrator privileges for drive access
        if not self.check_admin():
            return False
        
        # Validate drive index is within reasonable bounds
        # Windows supports up to 99 physical drives in most configurations
        if not isinstance(drive_index, int) or drive_index < 0 or drive_index > 99:
            return False
            
        # Construct Windows device path for physical drive
        device_path = f"\\\\.\\PhysicalDrive{drive_index}"
        handle = None
        
        try:
            # Attempt to open drive with read/write access
            # This is the same access level required for wipe operations
            handle = win32file.CreateFile(
                device_path,                                    # Device path
                win32con.GENERIC_READ | win32con.GENERIC_WRITE, # Access rights
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,  # Share mode
                None,                                           # Security attributes
                win32con.OPEN_EXISTING,                        # Creation disposition
                0,                                              # Flags and attributes
                None                                            # Template file
            )
            return True
            
        except (OSError, pywintypes.error) as e:
            # Log specific Windows API errors
            sanitized_error = str(e).replace('\n', ' ').replace('\r', '')
            self.logger.error(f"Drive access validation failed for {device_path}: {sanitized_error}")
            return False
        except Exception as e:
            # Log unexpected errors
            sanitized_error = str(e).replace('\n', ' ').replace('\r', '')
            self.logger.error(f"Unexpected error validating drive access: {sanitized_error}")
            return False
        finally:
            # Always close the handle to prevent resource leaks
            if handle:
                try:
                    win32file.CloseHandle(handle)
                except Exception as e:
                    sanitized_error = str(e).replace('\n', ' ').replace('\r', '')
                    self.logger.error(f"Failed to close handle: {sanitized_error}")

    def get_system_info(self) -> Dict[str, Any]:
        """Collect comprehensive system information for audit logging
        
        Gathers system details that are included in wipe certificates
        for audit trail and compliance purposes. This information helps
        identify the system where the wipe operation was performed.
        
        Returns:
            Dict[str, Any]: System information dictionary
        """
        try:
            import platform
            import getpass
            from datetime import datetime
            
            return {
                "os_version": platform.platform(),        # Full OS version string
                "computer_name": platform.node(),        # Computer/hostname
                "user_name": getpass.getuser(),          # Current username
                "timestamp": datetime.now().isoformat(), # Current timestamp
                "admin_status": self.check_admin(),      # Administrator privilege status
                "python_version": platform.python_version(),  # Python interpreter version
                "architecture": platform.architecture()[0]    # System architecture (32/64-bit)
            }
            
        except Exception as e:
            # Return error information if system info collection fails
            return {"error": str(e)}