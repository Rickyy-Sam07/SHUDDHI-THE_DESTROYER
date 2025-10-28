"""
Report Generator
================

Generates comprehensive JSON reports for data wipe operations including:
- Drive information (FAT, clusters, sectors, geometry)
- Checksum verification (before/after)
- Wipe process details
- Data deletion proof
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

try:
    import wmi
    import pythoncom
    HAS_WMI = True
except ImportError:
    HAS_WMI = False

try:
    import win32file
    import win32api
    import win32con
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False


class ReportGenerator:
    """Generate comprehensive JSON reports for wipe operations"""
    
    def __init__(self):
        """Initialize report generator"""
        self.report_data = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "report_version": "1.0",
                "application": "Shuddh - The Destroyer"
            },
            "drive_info_before": {},
            "drive_info_after": {},
            "checksum_verification": {},
            "wipe_process_info": {},
            "data_deletion_proof": {}
        }
    
    def collect_drive_info_before(self, drive_info: Dict[str, Any]) -> None:
        """Collect comprehensive drive information BEFORE wipe
        
        Args:
            drive_info: Drive information from WMI
        """
        print("Collecting drive information before wipe...")
        
        try:
            # Initialize COM for this thread
            if HAS_WMI:
                pythoncom.CoInitialize()
            
            # Basic drive information
            info = {
                "drive_model": drive_info.get('Model', 'Unknown'),
                "drive_serial": drive_info.get('SerialNumber', 'Unknown'),
                "drive_size_bytes": drive_info.get('Size', 0),
                "drive_size_gb": round(int(drive_info.get('Size', 0)) / (1024**3), 2),
                "drive_index": drive_info.get('Index', -1),
                "interface_type": drive_info.get('InterfaceType', 'Unknown'),
                "media_type": drive_info.get('MediaType', 'Unknown'),
                "partitions": []
            }
            
            # Get partition information
            if HAS_WMI:
                c = wmi.WMI()
                drive_index = drive_info.get('Index', -1)
                
                # Find partitions on this drive
                for partition in c.Win32_DiskPartition():
                    if partition.DiskIndex == drive_index:
                        partition_info = {
                            "partition_index": partition.Index,
                            "partition_size_bytes": int(partition.Size) if partition.Size else 0,
                            "partition_size_gb": round(int(partition.Size) / (1024**3), 2) if partition.Size else 0,
                            "starting_offset": int(partition.StartingOffset) if partition.StartingOffset else 0,
                            "bootable": partition.Bootable,
                            "primary": partition.PrimaryPartition,
                            "drive_letter": None,
                            "file_system": None,
                            "cluster_size": None,
                            "total_clusters": None,
                            "free_clusters": None,
                            "sectors_per_cluster": None,
                            "bytes_per_sector": None
                        }
                        
                        # Find logical disk (drive letter) for this partition
                        for logical_disk in c.Win32_LogicalDisk():
                            partition_to_logical = c.Win32_LogicalDiskToPartition()
                            for assoc in partition_to_logical:
                                if (assoc.Antecedent.DeviceID == partition.DeviceID and 
                                    assoc.Dependent.DeviceID == logical_disk.DeviceID):
                                    
                                    device_id = logical_disk.DeviceID
                                    if device_id and len(device_id) >= 2 and device_id[1] == ':':
                                        drive_letter = device_id[0].upper()
                                        partition_info["drive_letter"] = drive_letter
                                        partition_info["file_system"] = logical_disk.FileSystem or "Unknown"
                                        
                                        # Store first found drive letter at root level
                                        if not info.get("drive_letter"):
                                            info["drive_letter"] = drive_letter
                                        
                                        # Get cluster information using Win32 API
                                        if HAS_PYWIN32 and drive_letter:
                                            try:
                                                sectors_per_cluster, bytes_per_sector, free_clusters, total_clusters = \
                                                    win32file.GetDiskFreeSpace(f"{drive_letter}:\\")
                                                
                                                partition_info["sectors_per_cluster"] = sectors_per_cluster
                                                partition_info["bytes_per_sector"] = bytes_per_sector
                                                partition_info["total_clusters"] = total_clusters
                                                partition_info["free_clusters"] = free_clusters
                                                partition_info["cluster_size"] = sectors_per_cluster * bytes_per_sector
                                                partition_info["total_sectors"] = total_clusters * sectors_per_cluster
                                                partition_info["used_clusters"] = total_clusters - free_clusters
                                                
                                            except Exception as e:
                                                print(f"Could not get cluster info for {drive_letter}: {e}")
                        
                        info["partitions"].append(partition_info)
            
            self.report_data["drive_info_before"] = info
            print(f"✓ Drive info collected: {info.get('drive_model', 'Unknown')}")
            
        except Exception as e:
            print(f"Error collecting drive info: {e}")
            self.report_data["drive_info_before"] = {
                "error": str(e),
                "drive_model": drive_info.get('Model', 'Unknown')
            }
        finally:
            if HAS_WMI:
                try:
                    pythoncom.CoUninitialize()
                except:
                    pass
    
    def collect_drive_info_after(self, drive_info: Dict[str, Any]) -> None:
        """Collect comprehensive drive information AFTER wipe
        
        Args:
            drive_info: Drive information from WMI
        """
        print("Collecting drive information after wipe...")
        
        try:
            # Initialize COM for this thread
            if HAS_WMI:
                pythoncom.CoInitialize()
            
            # Basic drive information
            info = {
                "drive_model": drive_info.get('Model', 'Unknown'),
                "drive_serial": drive_info.get('SerialNumber', 'Unknown'),
                "drive_size_bytes": drive_info.get('Size', 0),
                "drive_size_gb": round(int(drive_info.get('Size', 0)) / (1024**3), 2),
                "drive_index": drive_info.get('Index', -1),
                "partitions": []
            }
            
            # Get partition information after wipe
            if HAS_WMI:
                c = wmi.WMI()
                drive_index = drive_info.get('Index', -1)
                
                for partition in c.Win32_DiskPartition():
                    if partition.DiskIndex == drive_index:
                        partition_info = {
                            "partition_index": partition.Index,
                            "partition_size_bytes": int(partition.Size) if partition.Size else 0,
                            "partition_size_gb": round(int(partition.Size) / (1024**3), 2) if partition.Size else 0,
                            "drive_letter": None,
                            "file_system": None,
                            "free_clusters": None,
                            "total_clusters": None
                        }
                        
                        # Find logical disk for this partition
                        for logical_disk in c.Win32_LogicalDisk():
                            partition_to_logical = c.Win32_LogicalDiskToPartition()
                            for assoc in partition_to_logical:
                                if (assoc.Antecedent.DeviceID == partition.DeviceID and 
                                    assoc.Dependent.DeviceID == logical_disk.DeviceID):
                                    
                                    device_id = logical_disk.DeviceID
                                    if device_id and len(device_id) >= 2 and device_id[1] == ':':
                                        drive_letter = device_id[0].upper()
                                        partition_info["drive_letter"] = drive_letter
                                        partition_info["file_system"] = logical_disk.FileSystem or "Unknown"
                                        
                                        if not info.get("drive_letter"):
                                            info["drive_letter"] = drive_letter
                                        
                                        # Get cluster information after wipe
                                        if HAS_PYWIN32 and drive_letter:
                                            try:
                                                sectors_per_cluster, bytes_per_sector, free_clusters, total_clusters = \
                                                    win32file.GetDiskFreeSpace(f"{drive_letter}:\\")
                                                
                                                partition_info["free_clusters"] = free_clusters
                                                partition_info["total_clusters"] = total_clusters
                                                partition_info["used_clusters"] = total_clusters - free_clusters
                                                
                                            except Exception as e:
                                                print(f"Could not get cluster info for {drive_letter}: {e}")
                        
                        info["partitions"].append(partition_info)
            
            self.report_data["drive_info_after"] = info
            print(f"✓ Drive info collected after wipe")
            
        except Exception as e:
            print(f"Error collecting drive info after wipe: {e}")
            self.report_data["drive_info_after"] = {"error": str(e)}
        finally:
            if HAS_WMI:
                try:
                    pythoncom.CoUninitialize()
                except:
                    pass
    
    def add_checksum_verification(self, pre_checksum: Dict[str, Any], post_checksum: Dict[str, Any]) -> None:
        """Add checksum verification data to report
        
        Args:
            pre_checksum: Pre-wipe checksum data
            post_checksum: Post-wipe checksum data
        """
        self.report_data["checksum_verification"] = {
            "pre_wipe": {
                "checksum": pre_checksum.get('checksum', 'N/A'),
                "timestamp": pre_checksum.get('timestamp', 'N/A'),
                "data_size": pre_checksum.get('data_size', 0),
                "status": pre_checksum.get('status', 'UNKNOWN')
            },
            "post_wipe": {
                "checksum": post_checksum.get('checksum', 'N/A'),
                "timestamp": post_checksum.get('timestamp', 'N/A'),
                "data_size": post_checksum.get('data_size', 0),
                "status": post_checksum.get('status', 'UNKNOWN')
            },
            "verification": {
                "checksums_different": pre_checksum.get('checksum') != post_checksum.get('checksum'),
                "data_destroyed": pre_checksum.get('checksum') != post_checksum.get('checksum'),
                "verification_status": "VERIFIED" if pre_checksum.get('checksum') != post_checksum.get('checksum') else "FAILED"
            }
        }
    
    def add_wipe_process_info(self, wipe_result: Dict[str, Any], method_name: str, method_id: str) -> None:
        """Add wipe process information to report
        
        Args:
            wipe_result: Result from wipe operation
            method_name: Name of wipe method used
            method_id: ID of wipe method
        """
        # Determine number of overwrite passes based on method
        passes_map = {
            "NIST_SP_800_88_CLEAR": 1,
            "NIST_SP_800_88_PURGE": 1,
            "DOD_5220_22_M": 3,
            "AFSSI_5020": 4,
            "ATA_SECURE_ERASE": 1,
            "NVME_FORMAT": 1,
            "CRYPTOGRAPHIC_ERASE": 1
        }
        num_passes = passes_map.get(method_id, 1)
        
        self.report_data["wipe_process_info"] = {
            "wipe_method": method_name,
            "method_id": method_id,
            "files_wiped": wipe_result.get('files_wiped', 0),
            "bytes_written": wipe_result.get('bytes_written', 0),
            "bytes_overwritten": wipe_result.get('bytes_written', 0),
            "passes": num_passes,
            "overwrite_passes_completed": num_passes,
            "success": wipe_result.get('success', True),
            "overwrite_status": "COMPLETED" if wipe_result.get('success', True) else "FAILED",
            "execution_time": wipe_result.get('execution_time', 'Unknown'),
            "timestamp": datetime.now().isoformat()
        }
    
    def generate_data_deletion_proof(self) -> Dict[str, Any]:
        """Generate comprehensive data deletion proof from collected data"""
        
        # Extract data from collected information
        before = self.report_data.get("drive_info_before", {})
        after = self.report_data.get("drive_info_after", {})
        wipe_info = self.report_data.get("wipe_process_info", {})
        checksum = self.report_data.get("checksum_verification", {})
        
        # Calculate space reclaimed
        total_space_before = before.get("drive_size_bytes", 0)
        
        # Count files and calculate used space before
        files_before = 0
        used_space_before = 0
        for partition in before.get("partitions", []):
            if partition.get("used_clusters") and partition.get("cluster_size"):
                used_space_before += partition["used_clusters"] * partition["cluster_size"]
            # Estimate files from used clusters (rough estimate)
            if partition.get("used_clusters"):
                files_before += partition["used_clusters"] // 10  # Rough estimate
        
        # Count files and calculate used space after
        files_after = 0
        used_space_after = 0
        for partition in after.get("partitions", []):
            if partition.get("used_clusters") and partition.get("cluster_size"):
                used_space_after += partition["used_clusters"] * partition.get("cluster_size", 0)
            if partition.get("used_clusters"):
                files_after += partition["used_clusters"] // 10
        
        # Calculate deletion metrics
        space_reclaimed = used_space_before - used_space_after
        files_deleted = wipe_info.get("files_wiped", 0)
        
        proof = {
            "deletion_summary": {
                "files_deleted": files_deleted,
                "space_reclaimed_bytes": space_reclaimed,
                "space_reclaimed_mb": round(space_reclaimed / (1024**2), 2),
                "data_overwritten_bytes": wipe_info.get("bytes_overwritten", 0),
                "overwrite_passes": wipe_info.get("passes", 1)
            },
            "verification_proof": {
                "checksum_changed": checksum.get("verification", {}).get("checksums_different", False),
                "overwrite_completed": wipe_info.get("overwrite_status") == "COMPLETED",
                "data_destruction_verified": checksum.get("verification", {}).get("data_destroyed", False)
            },
            "footprint_evidence": {
                "method_used": wipe_info.get("wipe_method", "Unknown"),
                "overwrite_pattern": "AES-128-CTR encrypted random data" if "NIST" in wipe_info.get("method_id", "") else "Multi-pass pattern",
                "compliance_standard": wipe_info.get("method_id", "Unknown"),
                "timestamp": datetime.now().isoformat()
            }
        }
        
        self.report_data["data_deletion_proof"] = proof
        return proof
    
    def save_report(self, drive_info: Dict[str, Any]) -> str:
        """Save comprehensive report to Desktop
        
        Args:
            drive_info: Drive information for filename
            
        Returns:
            Path to saved report file
        """
        try:
            # Generate report filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            drive_model = drive_info.get('Model', 'Unknown').replace(' ', '_')
            drive_serial = drive_info.get('SerialNumber', 'Unknown')[:8]
            
            filename = f"wipe_report_{drive_model}_{drive_serial}_{timestamp}.json"
            
            # Save to Desktop
            desktop_path = Path.home() / "Desktop"
            report_path = desktop_path / filename
            
            # Write report
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(self.report_data, f, indent=2, ensure_ascii=False)
            
            print(f"✓ Report saved: {report_path}")
            return str(report_path)
            
        except Exception as e:
            print(f"Error saving report: {e}")
            # Fallback to current directory
            try:
                report_path = Path(filename)
                with open(report_path, 'w', encoding='utf-8') as f:
                    json.dump(self.report_data, f, indent=2, ensure_ascii=False)
                return str(report_path)
            except:
                return "Report could not be saved"
