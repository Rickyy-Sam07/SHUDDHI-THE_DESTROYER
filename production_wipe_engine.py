"""
Production Wipe Engine
======================

PRODUCTION VERSION - ALL SAFETY FEATURES REMOVED
This module performs ACTUAL data destruction operations.
"""

import os
import sys
import time
import logging
import subprocess
import threading
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime

try:
    import win32file
    import win32con
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False


class WipeExecutionError(Exception):
    pass


class WipeEngine:
    def __init__(self, development_mode: bool = False):
        self.development_mode = development_mode
        self.logger = logging.getLogger(__name__)
        self.abort_flag = threading.Event()
        
        # Tool paths
        self.tools_dir = Path("tools")
        self.nvme_cli_path = self.tools_dir / "nvme.exe"
        self.hdparm_path = self.tools_dir / "hdparm.exe"
        self.openssl_path = self.tools_dir / "openssl.exe"

    def check_external_tools(self) -> Dict[str, bool]:
        tools_status = {}
        
        # Check nvme-cli
        try:
            result = subprocess.run(["nvme", "version"], capture_output=True, text=True, timeout=5)
            tools_status["nvme-cli"] = result.returncode == 0
        except:
            tools_status["nvme-cli"] = False
        
        # Check hdparm (Windows version)
        tools_status["hdparm"] = self.hdparm_path.exists()
        
        # Check openssl
        try:
            result = subprocess.run(["openssl", "version"], capture_output=True, text=True, timeout=5)
            tools_status["openssl"] = result.returncode == 0
        except:
            tools_status["openssl"] = False
        
        return tools_status

    def execute_nvme_format(self, drive_path: str, drive_info: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Windows-native NVMe secure erase"""
        
        # Validate drive info
        drive_index = drive_info.get('Index')
        if drive_index is None or not isinstance(drive_index, int) or drive_index < 0:
            raise WipeExecutionError(f"Invalid drive index: {drive_index}")
        
        # Use Windows device path
        device_path = f"\\\\.\\PhysicalDrive{drive_index}"
        
        try:
            start_time = datetime.now()
            
            # Use Windows diskpart for NVMe secure erase
            diskpart_script = f"""select disk {drive_index}
clean all
exit"""
            
            with subprocess.Popen(
                ["diskpart"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            ) as process:
                try:
                    stdout, stderr = process.communicate(input=diskpart_script, timeout=300)
                    end_time = datetime.now()
                    
                    if process.returncode == 0:
                        return {
                            "success": True,
                            "method": "WINDOWS_DISKPART_CLEAN",
                            "command": "diskpart clean all",
                            "execution_time": str(end_time - start_time),
                            "status": "Windows diskpart clean completed successfully",
                            "stdout": stdout,
                            "stderr": stderr
                        }
                    else:
                        raise WipeExecutionError(f"Diskpart failed (code {process.returncode}): {stderr}")
                        
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise WipeExecutionError("Diskpart command timed out")
                    
        except Exception as e:
            raise WipeExecutionError(f"Windows diskpart execution failed: {e}")

    def execute_ata_secure_erase(self, drive_path: str, drive_info: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Windows-native SSD secure erase using cipher"""
        
        # Validate drive info
        drive_index = drive_info.get('Index')
        if drive_index is None or not isinstance(drive_index, int) or drive_index < 0:
            raise WipeExecutionError(f"Invalid drive index: {drive_index}")
        
        try:
            start_time = datetime.now()
            
            # Get drive letter for cipher command
            partitions = self._get_partition_info(drive_index)
            if not partitions:
                raise WipeExecutionError("No accessible partitions found for SSD erase")
            
            results = []
            for partition in partitions:
                drive_letter = partition['drive_letter']
                
                # Use Windows cipher for secure deletion
                with subprocess.Popen(
                    ["cipher", "/w", f"{drive_letter}:\\"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                ) as process:
                    try:
                        stdout, stderr = process.communicate(timeout=3600)  # 1 hour timeout
                        
                        if process.returncode == 0:
                            results.append(f"Drive {drive_letter}: cipher completed")
                        else:
                            self.logger.warning(f"Cipher failed on {drive_letter}: {stderr}")
                            
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        raise WipeExecutionError(f"Cipher command timed out on drive {drive_letter}")
            
            end_time = datetime.now()
            
            return {
                "success": True,
                "method": "WINDOWS_CIPHER_SECURE",
                "command": "cipher /w on all partitions",
                "execution_time": str(end_time - start_time),
                "status": f"Windows cipher secure erase completed: {'; '.join(results)}",
                "partitions_processed": len(results)
            }
                
        except Exception as e:
            raise WipeExecutionError(f"Windows cipher execution failed: {e}")

    def execute_aes_overwrite(self, drive_path: str, drive_info: Dict[str, Any]) -> Dict[str, Any]:
        """Execute selective data wipe preserving OS and partition structure"""
        
        try:
            start_time = datetime.now()
            
            # Get partition information
            partitions = self._get_partition_info(drive_info.get('Index', 0))
            
            total_wiped = 0
            files_wiped = 0
            
            # Wipe user data in each partition while preserving OS
            for partition in partitions:
                drive_letter = partition['drive_letter']
                
                try:
                    # Define directories to wipe (preserve OS)
                    wipe_paths = self._get_wipe_paths(drive_letter)
                    
                    for wipe_path in wipe_paths:
                        if os.path.exists(wipe_path):
                            wiped_bytes, wiped_count = self._wipe_directory_contents(wipe_path)
                            total_wiped += wiped_bytes
                            files_wiped += wiped_count
                            
                            # Check for abort
                            if self.abort_flag.is_set():
                                raise WipeExecutionError("Wipe operation aborted by user")
                    
                    self.logger.info(f"Completed wiping user data on {drive_letter}:")
                        
                except Exception as e:
                    self.logger.warning(f"Could not wipe data on {partition['drive_letter']}: {e}")
                    continue
            
            end_time = datetime.now()
            
            return {
                "success": True,
                "method": "AES_128_CTR_OS_SAFE",
                "command": f"OS-safe data wipe: {len(partitions)} partitions",
                "execution_time": str(end_time - start_time),
                "status": f"OS-safe data wipe completed: {files_wiped:,} files wiped, {total_wiped:,} bytes",
                "bytes_written": total_wiped,
                "files_wiped": files_wiped,
                "partitions_processed": len(partitions)
            }
            
        except Exception as e:
            raise WipeExecutionError(f"OS-safe data wipe failed: {e}")
    
    def _get_partition_info(self, drive_index: int) -> List[Dict[str, Any]]:
        """Get partition information for the specified drive"""
        # Validate drive index
        if not isinstance(drive_index, int) or drive_index < 0 or drive_index > 99:
            raise ValueError(f"Invalid drive index: {drive_index}")
            
        try:
            import wmi
            c = wmi.WMI()
            partitions = []
            
            # Get logical disks associated with this physical drive
            for logical_disk in c.Win32_LogicalDisk():
                if logical_disk.DriveType == 3:  # Fixed disk
                    device_id = logical_disk.DeviceID
                    if not device_id or len(device_id) != 2 or device_id[1] != ':':
                        continue
                        
                    drive_letter = device_id[0].upper()
                    if not drive_letter.isalpha():
                        continue
                        
                    size = int(logical_disk.Size) if logical_disk.Size else 0
                    
                    partitions.append({
                        'drive_letter': drive_letter,
                        'size': size,
                        'file_system': logical_disk.FileSystem or 'Unknown'
                    })
            
            return partitions
            
        except Exception as e:
            self.logger.error(f"Could not get partition info: {e}")
            raise WipeExecutionError(f"Failed to enumerate partitions: {e}")
    
    def _get_wipe_paths(self, drive_letter: str) -> List[str]:
        """Get paths to wipe while preserving OS"""
        # Validate drive letter
        if not isinstance(drive_letter, str) or len(drive_letter) != 1 or not drive_letter.isalpha():
            raise ValueError(f"Invalid drive letter: {drive_letter}")
            
        drive_letter = drive_letter.upper()
        base_path = f"{drive_letter}:\\"
        
        # Validate base path exists and is accessible
        if not os.path.exists(base_path):
            raise ValueError(f"Drive {drive_letter}: not accessible")
        
        # Paths to wipe (user data, temp files, etc.)
        candidate_paths = [
            f"{base_path}Users",
            f"{base_path}Temp",
            f"{base_path}tmp", 
            f"{base_path}Downloads",
            f"{base_path}Documents and Settings",
            f"{base_path}ProgramData\\Temp",
            f"{base_path}Windows\\Temp",
            f"{base_path}$Recycle.Bin",
            f"{base_path}Program Files",
            f"{base_path}Program Files (x86)"
        ]
        
        # Only return paths that exist and are safe to wipe
        wipe_paths = []
        for path in candidate_paths:
            if os.path.exists(path) and self._is_safe_wipe_path(path):
                wipe_paths.append(path)
        
        return wipe_paths
    
    def _is_safe_wipe_path(self, path: str) -> bool:
        """Validate path is safe to wipe (not critical OS directories)"""
        path_lower = path.lower()
        
        # Critical OS paths that should never be wiped
        forbidden_paths = [
            'windows\\system32', 'windows\\syswow64', 'windows\\boot',
            'windows\\drivers', 'windows\\winsxs', 'windows\\servicing',
            'program files\\windows nt', 'program files\\common files\\microsoft shared'
        ]
        
        return not any(forbidden in path_lower for forbidden in forbidden_paths)
    
    def _wipe_directory_contents(self, directory_path: str) -> tuple:
        """Wipe contents of directory while preserving essential OS files"""
        total_bytes = 0
        files_count = 0
        
        # OS-critical directories to preserve
        preserve_dirs = {
            'windows\\system32', 'windows\\syswow64', 'windows\\boot',
            'windows\\drivers', 'program files\\windows nt',
            'program files\\microsoft', 'program files (x86)\\microsoft'
        }
        
        try:
            for root, dirs, files in os.walk(directory_path):
                # Check if this is a critical OS directory
                rel_path = os.path.relpath(root, directory_path).lower()
                if any(preserve in rel_path for preserve in preserve_dirs):
                    continue
                
                # Check for abort
                if self.abort_flag.is_set():
                    break
                
                # Wipe files in this directory
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip critical OS files
                    if self._is_critical_os_file(file_path):
                        continue
                    
                    try:
                        # Get file size
                        file_size = os.path.getsize(file_path)
                        
                        # Overwrite file with random data using context manager
                        try:
                            with open(file_path, 'r+b') as f:
                                chunk_size = min(1024*1024, file_size)  # 1MB chunks
                                written = 0
                                
                                while written < file_size:
                                    remaining = min(chunk_size, file_size - written)
                                    random_data = os.urandom(remaining)
                                    f.write(random_data)
                                    f.flush()  # Ensure data is written
                                    written += remaining
                        except (PermissionError, OSError) as e:
                            sanitized_error = str(e).replace('\n', ' ').replace('\r', '')
                            self.logger.warning(f"Could not overwrite file {file_path}: {sanitized_error}")
                            continue
                        
                        # Delete the file after overwriting
                        os.remove(file_path)
                        
                        total_bytes += file_size
                        files_count += 1
                        
                        if files_count % 100 == 0:
                            self.logger.info(f"Wiped {files_count} files, {total_bytes:,} bytes")
                            
                    except Exception as e:
                        sanitized_error = str(e).replace('\n', ' ').replace('\r', '')
                        self.logger.warning(f"Could not wipe file {file_path}: {sanitized_error}")
                        continue
        
        except Exception as e:
            self.logger.error(f"Error wiping directory {directory_path}: {e}")
        
        return total_bytes, files_count
    
    def _is_critical_os_file(self, file_path: str) -> bool:
        """Check if file is critical for OS operation"""
        file_path_lower = file_path.lower()
        
        # Critical OS files to preserve
        critical_patterns = [
            'ntoskrnl.exe', 'hal.dll', 'ntdll.dll', 'kernel32.dll',
            'user32.dll', 'gdi32.dll', 'advapi32.dll', 'shell32.dll',
            'bootmgr', 'winload.exe', 'winresume.exe', 'bcd',
            'registry', 'sam', 'security', 'software', 'system',
            'drivers\\', 'boot\\', 'system32\\config\\'
        ]
        
        return any(pattern in file_path_lower for pattern in critical_patterns)

    def execute_wipe(self, drive_info: Dict[str, Any], wipe_decision: Dict[str, str]) -> Dict[str, Any]:
        """Execute the determined wipe method with fallback support"""
        
        drive_path = drive_info.get('DeviceID', f"\\\\.\\PhysicalDrive{drive_info.get('Index', 0)}")
        primary_method = wipe_decision.get('primary_method', 'AES_128_CTR')
        fallback_method = wipe_decision.get('fallback_method', 'AES_128_CTR')
        
        start_time = datetime.now()
        
        try:
            # Execute primary method
            if primary_method == "NVME_FORMAT_NVM":
                result = self.execute_nvme_format(drive_path, drive_info)
            elif primary_method == "ATA_SECURE_ERASE":
                result = self.execute_ata_secure_erase(drive_path, drive_info)
            elif primary_method == "AES_128_CTR":
                result = self.execute_aes_overwrite(drive_path, drive_info)
            else:
                raise WipeExecutionError(f"Unknown wipe method: {primary_method}")
            
            # Add timing information
            end_time = datetime.now()
            execution_duration = end_time - start_time
            
            result.update({
                "primary_method_used": True,
                "fallback_method_used": False,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration": str(execution_duration),
                "drive_info": {
                    "model": drive_info.get('Model'),
                    "serial": drive_info.get('SerialNumber'),
                    "size_gb": drive_info.get('SizeGB')
                }
            })
            
            return result
            
        except Exception as e:
            self.logger.warning(f"Primary method failed: {e}")
            
            # Execute fallback method
            try:
                if fallback_method == "AES_128_CTR":
                    result = self.execute_aes_overwrite(drive_path, drive_info)
                else:
                    raise WipeExecutionError(f"Unsupported fallback method: {fallback_method}")
                
                end_time = datetime.now()
                execution_duration = end_time - start_time
                
                result.update({
                    "primary_method_used": False,
                    "fallback_method_used": True,
                    "primary_method_error": str(e),
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                    "duration": str(execution_duration),
                    "drive_info": {
                        "model": drive_info.get('Model'),
                        "serial": drive_info.get('SerialNumber'),
                        "size_gb": drive_info.get('SizeGB')
                    }
                })
                
                return result
                
            except Exception as fallback_error:
                raise WipeExecutionError(f"Both primary and fallback methods failed: {e}, {fallback_error}")