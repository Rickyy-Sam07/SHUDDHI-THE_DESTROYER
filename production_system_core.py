"""
Production System Core functions

PRODUCTION VERSION - ALL SAFETY FEATURES REMOVED
This scripts contains functions that interact with system hardware and require
administrative privileges
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
    def __init__(self, development_mode=False):
        self.logger = self._setup_logging()
        self.admin_checked = False
        self.development_mode = development_mode
        
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
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            self.admin_checked = True
            return is_admin
        except Exception as e:
            self.logger.error(f"Error checking admin privileges: {e}")
            return False

    def elevate_privileges(self) -> None:
        if self.check_admin():
            return
            
        try:
            result = ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                " ".join(sys.argv),
                None,
                1
            )
            
            if result <= 32:
                raise AdminPrivilegeError("UAC elevation was cancelled or failed.")
            
            sys.exit(0)
            
        except Exception as e:
            raise AdminPrivilegeError(f"Privilege elevation failed: {e}")

    def ensure_admin_privileges(self) -> None:
        if not self.check_admin():
            self.elevate_privileges()

    def get_drive_info(self) -> List[Dict[str, Any]]:
        if not wmi:
            raise HardwareDetectionError("WMI library not available for hardware detection.")
        
        try:
            c = wmi.WMI()
            drives = []
            
            for physical_disk in c.Win32_DiskDrive():
                try:
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
                        "DeviceID": physical_disk.DeviceID or f"\\\\.\\PhysicalDrive{physical_disk.Index}",
                        "Firmware": getattr(physical_disk, 'FirmwareRevision', 'Unknown'),
                        "Status": physical_disk.Status or "Unknown",
                        "Partitions": physical_disk.Partitions or 0,
                        "BytesPerSector": physical_disk.BytesPerSector or 512,
                        "TotalSectors": physical_disk.TotalSectors or 0
                    }
                    
                    drives.append(drive_info)
                    
                except Exception as e:
                    self.logger.warning(f"Error processing drive {physical_disk.Index}: {e}")
                    continue
            
            return drives
            
        except Exception as e:
            raise HardwareDetectionError(f"Drive enumeration failed: {e}")

    def determine_wipe_method(self, drive_info: Dict[str, Any]) -> Dict[str, str]:
        result = {
            "primary_method": "AES_128_CTR",
            "fallback_method": "AES_128_CTR", 
            "reasoning": "Default safe method",
            "drive_category": "UNKNOWN"
        }
        
        if not drive_info:
            return result
        
        model = drive_info.get('Model', '').upper()
        interface_type = drive_info.get('InterfaceType', '').upper()
        media_type = drive_info.get('MediaType', '').upper()
        
        # NVMe detection
        if 'NVME' in interface_type or 'NVME' in model:
            result = {
                "primary_method": "NVME_FORMAT_NVM",
                "fallback_method": "AES_128_CTR",
                "reasoning": "NVMe interface detected - Format NVM is faster",
                "drive_category": "NVME"
            }
            
        # SATA SSD detection
        elif ('SSD' in model or 'SOLID STATE' in model or 
              'SATA' in interface_type or 
              'FIXED' in media_type):
            result = {
                "primary_method": "ATA_SECURE_ERASE", 
                "fallback_method": "AES_128_CTR",
                "reasoning": "SATA SSD detected - ATA Secure Erase leverages hardware",
                "drive_category": "SATA_SSD"
            }
            
        # Other drives (HDD, USB, etc.)
        else:
            is_removable = 'REMOVABLE' in media_type or 'USB' in interface_type
            
            if is_removable:
                result["drive_category"] = "USB"
                result["reasoning"] = "Removable/USB drive - AES_128_CTR provides fast, secure method"
            else:
                result["drive_category"] = "HDD"
                result["reasoning"] = "Traditional HDD - AES_128_CTR provides fast, secure method"
        
        return result

    def validate_drive_access(self, drive_index: int) -> bool:
        if not self.check_admin():
            return False
        
        device_path = f"\\\\.\\PhysicalDrive{drive_index}"
        
        try:
            handle = win32file.CreateFile(
                device_path,
                win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                0,
                None
            )
            win32file.CloseHandle(handle)
            return True
            
        except Exception:
            return False

    def get_system_info(self) -> Dict[str, Any]:
        try:
            import platform
            import getpass
            from datetime import datetime
            
            return {
                "os_version": platform.platform(),
                "computer_name": platform.node(),
                "user_name": getpass.getuser(),
                "timestamp": datetime.now().isoformat(),
                "admin_status": self.check_admin(),
                "python_version": platform.python_version(),
                "architecture": platform.architecture()[0]
            }
            
        except Exception as e:
            return {"error": str(e)}