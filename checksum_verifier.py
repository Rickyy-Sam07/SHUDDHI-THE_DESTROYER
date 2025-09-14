"""
Drive Checksum Verifier
=======================

Calculates checksums of first 5MB of drive before and after cleaning
to verify data destruction effectiveness.
"""

import os
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

try:
    import win32file
    import win32con
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False


class ChecksumVerifier:
    """Calculate drive checksums before and after wipe operations"""
    
    def __init__(self, drive_letter: str):
        """Initialize verifier for specific drive
        
        Args:
            drive_letter (str): Drive letter (e.g., 'E')
        """
        self.drive_letter = drive_letter.upper()
        self.drive_path = f"\\\\.\\{self.drive_letter}:"
        self.chunk_size = 5 * 1024 * 1024  # 5MB
        
    def calculate_pre_wipe_checksum(self) -> Dict[str, Any]:
        """Calculate checksum before wipe operation"""
        print(f"Calculating pre-wipe checksum for drive {self.drive_letter}...")
        
        try:
            data = self._read_drive_data()
            checksum = hashlib.sha256(data).hexdigest()
            
            result = {
                'drive_letter': self.drive_letter,
                'timestamp': datetime.now().isoformat(),
                'data_size': len(data),
                'checksum': checksum,
                'status': 'SUCCESS'
            }
            
            # Save pre-wipe checksum
            self._save_checksum(result, 'pre_wipe')
            print(f"Pre-wipe checksum: {checksum[:16]}...")
            return result
            
        except Exception as e:
            result = {
                'drive_letter': self.drive_letter,
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'status': 'FAILED'
            }
            print(f"Pre-wipe checksum failed: {e}")
            return result
    
    def calculate_post_wipe_checksum(self) -> Dict[str, Any]:
        """Calculate checksum after wipe operation"""
        print(f"Calculating post-wipe checksum for drive {self.drive_letter}...")
        
        try:
            data = self._read_drive_data()
            checksum = hashlib.sha256(data).hexdigest()
            
            result = {
                'drive_letter': self.drive_letter,
                'timestamp': datetime.now().isoformat(),
                'data_size': len(data),
                'checksum': checksum,
                'status': 'SUCCESS'
            }
            
            # Save post-wipe checksum
            self._save_checksum(result, 'post_wipe')
            print(f"Post-wipe checksum: {checksum[:16]}...")
            return result
            
        except Exception as e:
            result = {
                'drive_letter': self.drive_letter,
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'status': 'FAILED'
            }
            print(f"Post-wipe checksum failed: {e}")
            return result
    
    def compare_checksums(self) -> Dict[str, Any]:
        """Compare pre and post wipe checksums"""
        print(f"Comparing checksums for drive {self.drive_letter}...")
        
        try:
            # Load saved checksums
            pre_wipe = self._load_checksum('pre_wipe')
            post_wipe = self._load_checksum('post_wipe')
            
            if not pre_wipe or not post_wipe:
                return {
                    'status': 'FAILED',
                    'error': 'Missing checksum data'
                }
            
            checksums_different = pre_wipe['checksum'] != post_wipe['checksum']
            
            result = {
                'drive_letter': self.drive_letter,
                'comparison_timestamp': datetime.now().isoformat(),
                'pre_wipe_checksum': pre_wipe['checksum'],
                'post_wipe_checksum': post_wipe['checksum'],
                'checksums_different': checksums_different,
                'data_destroyed': checksums_different,
                'verification_status': 'VERIFIED' if checksums_different else 'FAILED',
                'status': 'SUCCESS'
            }
            
            # Save comparison result
            self._save_checksum(result, 'comparison')
            
            if checksums_different:
                print(f"✓ Data destruction VERIFIED - checksums are different")
            else:
                print(f"✗ Data destruction FAILED - checksums are identical")
                
            return result
            
        except Exception as e:
            result = {
                'drive_letter': self.drive_letter,
                'comparison_timestamp': datetime.now().isoformat(),
                'error': str(e),
                'status': 'FAILED'
            }
            print(f"Checksum comparison failed: {e}")
            return result
    
    def _read_drive_data(self) -> bytes:
        """Read first 5MB of drive data"""
        if not HAS_PYWIN32:
            raise Exception("pywin32 required for drive access")
        
        handle = win32file.CreateFile(
            self.drive_path,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
            None,
            win32con.OPEN_EXISTING,
            0,
            None
        )
        
        try:
            # Read first 5MB
            _, data = win32file.ReadFile(handle, self.chunk_size)
            return data
        finally:
            win32file.CloseHandle(handle)
    
    def _save_checksum(self, data: Dict[str, Any], suffix: str):
        """Save checksum data to file"""
        desktop = Path.home() / "Desktop"
        filename = f"checksum_{self.drive_letter}_{suffix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = desktop / filename
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"Checksum saved: {filepath}")
    
    def _load_checksum(self, suffix: str) -> Dict[str, Any]:
        """Load most recent checksum file"""
        desktop = Path.home() / "Desktop"
        pattern = f"checksum_{self.drive_letter}_{suffix}_*.json"
        
        files = list(desktop.glob(pattern))
        if not files:
            return None
        
        # Get most recent file
        latest_file = max(files, key=lambda f: f.stat().st_mtime)
        
        with open(latest_file, 'r') as f:
            return json.load(f)


def main():
    """Interactive checksum verification"""
    print("Drive Checksum Verifier")
    print("======================\n")
    
    drive_letter = input("Enter drive letter (e.g., E): ").strip().upper()
    
    if not drive_letter or len(drive_letter) != 1:
        print("Invalid drive letter!")
        return
    
    verifier = ChecksumVerifier(drive_letter)
    
    while True:
        print(f"\nOptions for drive {drive_letter}:")
        print("1. Calculate pre-wipe checksum")
        print("2. Calculate post-wipe checksum")
        print("3. Compare checksums")
        print("4. Full verification cycle")
        print("5. Exit")
        
        choice = input("\nSelect option (1-5): ").strip()
        
        if choice == '1':
            verifier.calculate_pre_wipe_checksum()
            
        elif choice == '2':
            verifier.calculate_post_wipe_checksum()
            
        elif choice == '3':
            verifier.compare_checksums()
            
        elif choice == '4':
            print("\nFull verification cycle:")
            print("1. Calculating pre-wipe checksum...")
            verifier.calculate_pre_wipe_checksum()
            
            input("\n*** NOW RUN SHUDDH TO WIPE THE DRIVE ***\nPress Enter when wipe is complete...")
            
            print("2. Calculating post-wipe checksum...")
            verifier.calculate_post_wipe_checksum()
            
            print("3. Comparing checksums...")
            result = verifier.compare_checksums()
            
            print(f"\nVerification complete!")
            print(f"Data destruction: {result.get('verification_status', 'UNKNOWN')}")
            
        elif choice == '5':
            print("Exiting...")
            break
            
        else:
            print("Invalid option!")


if __name__ == "__main__":
    main()