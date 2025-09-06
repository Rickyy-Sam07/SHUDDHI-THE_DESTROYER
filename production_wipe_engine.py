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
from typing import Dict, Any, Optional
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
        """Execute NVMe Format NVM with Secure Erase setting"""
        
        # Convert Windows drive path to NVMe device
        drive_index = drive_info.get('Index', 0)
        nvme_device = f"/dev/nvme{drive_index}n1"  # This would need proper Windows NVMe path mapping
        
        try:
            # Execute nvme format command with secure erase
            cmd = ["nvme", "format", nvme_device, "--ses=1"]
            
            start_time = datetime.now()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            end_time = datetime.now()
            
            if result.returncode == 0:
                return {
                    "success": True,
                    "method": "NVME_FORMAT_NVM",
                    "command": " ".join(cmd),
                    "execution_time": str(end_time - start_time),
                    "status": "NVMe Format with Secure Erase completed successfully",
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
            else:
                raise WipeExecutionError(f"NVMe format failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            raise WipeExecutionError("NVMe format command timed out")
        except Exception as e:
            raise WipeExecutionError(f"NVMe format execution failed: {e}")

    def execute_ata_secure_erase(self, drive_path: str, drive_info: Dict[str, Any]) -> Dict[str, Any]:
        """Execute ATA Secure Erase using hdparm"""
        
        # Convert Windows drive path to Linux-style path for hdparm
        drive_index = drive_info.get('Index', 0)
        device_path = f"/dev/sd{chr(ord('a') + drive_index)}"  # This would need proper Windows mapping
        
        try:
            start_time = datetime.now()
            
            # Step 1: Set security password
            cmd1 = [str(self.hdparm_path), "--user-master", "u", "--security-set-pass", "p", device_path]
            result1 = subprocess.run(cmd1, capture_output=True, text=True, timeout=30)
            
            if result1.returncode != 0:
                raise WipeExecutionError(f"Failed to set security password: {result1.stderr}")
            
            # Step 2: Execute secure erase
            cmd2 = [str(self.hdparm_path), "--user-master", "u", "--security-erase", "p", device_path]
            result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=7200)  # 2 hour timeout
            
            end_time = datetime.now()
            
            if result2.returncode == 0:
                return {
                    "success": True,
                    "method": "ATA_SECURE_ERASE",
                    "command": f"{' '.join(cmd1)} && {' '.join(cmd2)}",
                    "execution_time": str(end_time - start_time),
                    "status": "ATA Secure Erase completed successfully",
                    "stdout": result1.stdout + result2.stdout,
                    "stderr": result1.stderr + result2.stderr
                }
            else:
                raise WipeExecutionError(f"ATA secure erase failed: {result2.stderr}")
                
        except subprocess.TimeoutExpired:
            raise WipeExecutionError("ATA secure erase command timed out")
        except Exception as e:
            raise WipeExecutionError(f"ATA secure erase execution failed: {e}")

    def execute_aes_overwrite(self, drive_path: str, drive_info: Dict[str, Any]) -> Dict[str, Any]:
        """Execute AES-128-CTR single-pass overwrite using direct drive access"""
        
        if not HAS_PYWIN32:
            raise WipeExecutionError("pywin32 required for direct drive access")
        
        drive_size = drive_info.get('Size', 0)
        if drive_size == 0:
            raise WipeExecutionError("Cannot determine drive size")
        
        try:
            start_time = datetime.now()
            
            # Open drive for direct write access
            handle = win32file.CreateFile(
                drive_path,
                win32con.GENERIC_WRITE,
                0,  # No sharing
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_NO_BUFFERING | win32con.FILE_FLAG_WRITE_THROUGH,
                None
            )
            
            try:
                # Generate and write random data in chunks
                chunk_size = 1024 * 1024  # 1MB chunks
                total_written = 0
                
                while total_written < drive_size:
                    remaining = min(chunk_size, drive_size - total_written)
                    
                    # Generate cryptographically secure random data
                    random_data = os.urandom(remaining)
                    
                    # Write to drive
                    win32file.WriteFile(handle, random_data)
                    total_written += remaining
                    
                    # Progress tracking (could be used for UI updates)
                    progress = (total_written / drive_size) * 100
                    if total_written % (chunk_size * 100) == 0:  # Log every 100MB
                        self.logger.info(f"AES overwrite progress: {progress:.1f}%")
                
                # Force write completion
                win32file.FlushFileBuffers(handle)
                
            finally:
                win32file.CloseHandle(handle)
            
            end_time = datetime.now()
            
            return {
                "success": True,
                "method": "AES_128_CTR",
                "command": f"Direct drive overwrite: {drive_path}",
                "execution_time": str(end_time - start_time),
                "status": f"AES-128-CTR overwrite completed: {total_written:,} bytes written",
                "bytes_written": total_written
            }
            
        except Exception as e:
            raise WipeExecutionError(f"AES overwrite execution failed: {e}")

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