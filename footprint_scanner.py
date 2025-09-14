"""
Digital Footprint Scanner
========================

Scans for digital footprints and traces left after USB/storage device removal.
Checks registry, recent files, logs, and system artifacts for device traces.
"""

import os
import sys
import json
import winreg
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

try:
    import wmi
    HAS_WMI = True
except ImportError:
    HAS_WMI = False


class FootprintScanner:
    """Scan for digital footprints after storage device removal"""
    
    def __init__(self):
        self.findings = []
        self.scan_timestamp = datetime.now().isoformat()
        self.target_drive = None
    
    def scan_all_footprints(self) -> Dict[str, Any]:
        """Perform comprehensive footprint scan"""
        print("Digital Footprint Scanner")
        print("=" * 50)
        print(f"Scan started: {self.scan_timestamp}\n")
        
        # Registry footprints
        print("1. Scanning registry for USB traces...")
        self._scan_registry_usb()
        
        # Recent files
        print("2. Scanning recent files...")
        self._scan_recent_files()
        
        # Event logs
        print("3. Scanning event logs...")
        self._scan_event_logs()
        
        # Prefetch files
        print("4. Scanning prefetch files...")
        self._scan_prefetch()
        
        # Jump lists
        print("5. Scanning jump lists...")
        self._scan_jump_lists()
        
        # Shortcuts
        print("6. Scanning shortcuts...")
        self._scan_shortcuts()
        
        # System artifacts
        print("7. Scanning system artifacts...")
        self._scan_system_artifacts()
        
        # Generate report
        return self._generate_report()
    
    def _scan_registry_usb(self):
        """Scan registry for USB device traces"""
        usb_keys = [
            r"SYSTEM\CurrentControlSet\Enum\USB",
            r"SYSTEM\CurrentControlSet\Enum\USBSTOR",
            r"SOFTWARE\Microsoft\Windows Portable Devices\Devices",
            r"SYSTEM\MountedDevices"
        ]
        
        for key_path in usb_keys:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
                self._enumerate_registry_key(key, key_path, "USB Registry")
                winreg.CloseKey(key)
            except PermissionError:
                print(f"  Access denied to {key_path} (requires admin)")
                continue
            except Exception:
                continue
    
    def _scan_recent_files(self):
        """Scan for recent file references to removed drives"""
        recent_paths = [
            Path.home() / "AppData/Roaming/Microsoft/Windows/Recent",
            Path.home() / "AppData/Roaming/Microsoft/Office/Recent"
        ]
        
        for path in recent_paths:
            if path.exists():
                for file in path.glob("*"):
                    try:
                        if file.is_file():
                            content = file.read_text(errors='ignore')
                            if self.target_drive and f"{self.target_drive}:" in content:
                                self.findings.append({
                                    "type": "Recent File Reference",
                                    "location": str(file),
                                    "details": f"Contains reference to drive {self.target_drive}:",
                                    "risk": "Medium"
                                })
                    except Exception:
                        continue
    
    def _scan_event_logs(self):
        """Scan Windows event logs for USB activity"""
        try:
            cmd = 'wevtutil qe System /c:50 /f:text /q:"*[System[Provider[@Name=\'Microsoft-Windows-Kernel-PnP\']]]"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.stdout and "USB" in result.stdout:
                self.findings.append({
                    "type": "Event Log Entry",
                    "location": "Windows System Log",
                    "details": "USB device activity found in event logs",
                    "risk": "High"
                })
        except Exception:
            pass
    
    def _scan_prefetch(self):
        """Scan prefetch files for application traces"""
        prefetch_path = Path("C:/Windows/Prefetch")
        
        if prefetch_path.exists():
            for file in prefetch_path.glob("*.pf"):
                try:
                    if self.target_drive and self.target_drive in file.name.upper():
                        self.findings.append({
                            "type": "Prefetch File",
                            "location": str(file),
                            "details": f"Application execution trace for drive {self.target_drive}: {file.name}",
                            "risk": "Medium"
                        })
                except Exception:
                    continue
    
    def _scan_jump_lists(self):
        """Scan jump lists for file access traces"""
        jumplist_paths = [
            Path.home() / "AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations",
            Path.home() / "AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations"
        ]
        
        for path in jumplist_paths:
            if path.exists():
                for file in path.iterdir():
                    if file.is_file():
                        self.findings.append({
                            "type": "Jump List",
                            "location": str(file),
                            "details": "File access history",
                            "risk": "Medium"
                        })
    
    def _scan_shortcuts(self):
        """Scan for shortcuts pointing to removed drives"""
        shortcut_paths = [
            Path.home() / "Desktop",
            Path.home() / "AppData/Roaming/Microsoft/Windows/Start Menu"
        ]
        
        for path in shortcut_paths:
            if path.exists():
                for file in path.rglob("*.lnk"):
                    try:
                        # Check if shortcut points to removable drive
                        self.findings.append({
                            "type": "Shortcut File",
                            "location": str(file),
                            "details": "Potential drive reference",
                            "risk": "Low"
                        })
                    except Exception:
                        continue
    
    def _scan_system_artifacts(self):
        """Scan for system artifacts and traces"""
        artifacts = [
            "C:/Windows/inf/setupapi.dev.log"
        ]
        
        for artifact in artifacts:
            try:
                if Path(artifact).exists():
                    # Try to read a small portion to check accessibility
                    with open(artifact, 'r', errors='ignore') as f:
                        content = f.read(1024)
                        if self.target_drive and f"{self.target_drive}:" in content:
                            self.findings.append({
                                "type": "System Artifact",
                                "location": artifact,
                                "details": f"Contains references to drive {self.target_drive}:",
                                "risk": "High"
                            })
            except PermissionError:
                print(f"  Access denied to {artifact} (requires admin)")
                continue
            except Exception:
                continue
    
    def _enumerate_registry_key(self, key, key_path, category):
        """Enumerate registry key for USB traces"""
        try:
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    if any(usb_id in subkey_name.upper() for usb_id in ["VID_", "PID_", "USB"]):
                        self.findings.append({
                            "type": category,
                            "location": f"{key_path}\\{subkey_name}",
                            "details": f"USB device registry entry: {subkey_name}",
                            "risk": "High"
                        })
                    i += 1
                except OSError:
                    break
        except Exception:
            pass
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive footprint report"""
        report = {
            "scan_info": {
                "timestamp": self.scan_timestamp,
                "total_findings": len(self.findings),
                "scanner_version": "1.0"
            },
            "risk_summary": {
                "high": len([f for f in self.findings if f.get("risk") == "High"]),
                "medium": len([f for f in self.findings if f.get("risk") == "Medium"]),
                "low": len([f for f in self.findings if f.get("risk") == "Low"])
            },
            "findings": self.findings,
            "recommendations": self._get_recommendations()
        }
        
        # Save report to Desktop
        desktop = Path.home() / "Desktop"
        report_file = desktop / f"footprint_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n" + "=" * 50)
        print(f"SCAN COMPLETE")
        print(f"=" * 50)
        print(f"Total findings: {len(self.findings)}")
        print(f"High risk: {report['risk_summary']['high']}")
        print(f"Medium risk: {report['risk_summary']['medium']}")
        print(f"Low risk: {report['risk_summary']['low']}")
        print(f"\nReport saved: {report_file}")
        
        return report
    
    def _get_recommendations(self) -> List[str]:
        """Get cleanup recommendations"""
        recommendations = []
        
        if any(f.get("risk") == "High" for f in self.findings):
            recommendations.extend([
                "Clear Windows Event Logs",
                "Clean registry USB entries",
                "Delete system artifact files"
            ])
        
        if any(f.get("type") == "Recent File Reference" for f in self.findings):
            recommendations.append("Clear recent files and jump lists")
        
        if any(f.get("type") == "Prefetch File" for f in self.findings):
            recommendations.append("Clear prefetch directory")
        
        recommendations.extend([
            "Run disk cleanup utility",
            "Clear browser history and cache",
            "Empty recycle bin",
            "Use CCleaner or similar tool"
        ])
        
        return recommendations
    
def _clean_temp_files(self):
    """Clean temporary files"""
    temp_paths = [
        Path.home() / "AppData/Local/Temp",
        Path("C:/Windows/Temp")
    ]
    
    for temp_path in temp_paths:
        if temp_path.exists():
            for file in temp_path.glob("*"):
                try:
                    if file.is_file():
                        file.unlink()
                except Exception:
                    continue


def get_available_drives():
    """Get list of available drives"""
    drives = []
    for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        drive = f"{letter}:\\"
        if os.path.exists(drive):
            drives.append(letter)
    return drives

def check_admin_privileges():
    """Check if running with admin privileges"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    """Main entry point"""
    if not os.name == 'nt':
        print("This scanner is designed for Windows systems only.")
        return
    
    print("Digital Footprint Scanner")
    print("=" * 50)
    
    # Check admin privileges
    if not check_admin_privileges():
        print("WARNING: Not running as administrator.")
        print("Some registry and system files may be inaccessible.")
        print("For complete scan, run as administrator.\n")
    
    # Get available drives
    drives = get_available_drives()
    if not drives:
        print("No drives found!")
        return
    
    # Display available drives
    print("Available drives:")
    for i, drive in enumerate(drives, 1):
        print(f"{i}. {drive}:\\")
    
    # Get user selection
    try:
        choice = input("\nSelect drive to scan (number or letter): ").strip().upper()
        
        # Handle numeric choice
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(drives):
                selected_drive = drives[idx]
            else:
                print("Invalid selection!")
                return
        # Handle letter choice
        elif len(choice) == 1 and choice in drives:
            selected_drive = choice
        else:
            print("Invalid selection!")
            return
        
        print(f"\nScanning drive {selected_drive}:\\ for digital footprints...\n")
        
        scanner = FootprintScanner()
        scanner.target_drive = selected_drive
        report = scanner.scan_all_footprints()
        
        # Display summary
        if report['findings']:
            print(f"\n⚠️  DIGITAL FOOTPRINTS DETECTED!")
            print(f"Found {len(report['findings'])} potential traces.")
            print(f"\nRecommendations:")
            for rec in report['recommendations']:
                print(f"  • {rec}")
            print(f"\nNote: Use Shuddh GUI 'Clean Footprints' button for automatic cleanup.")
        else:
            print(f"\n✅ NO SIGNIFICANT FOOTPRINTS DETECTED")
            print(f"System appears clean of storage device traces.")
        
    except KeyboardInterrupt:
        print("\nScan cancelled by user.")
    except Exception as e:
        print(f"Scanner error: {e}")


if __name__ == "__main__":
    main()