"""
Build Script for Shuddh Production Executable
Creates standalone executable using PyInstaller
"""

import subprocess
import sys
import os
from pathlib import Path

def build_executable():
    """Build production executable using PyInstaller"""
    
    # PyInstaller command with minimal configuration
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",                    # Single executable file
        "--windowed",                   # No console window
        "--name=Shuddh",               # Executable name
        "--distpath=dist",             # Output directory
        "--workpath=build",            # Build directory
        "--specpath=.",                # Spec file location
        "production_shuddh.py"         # Main script
    ]
    
    # Add icon if it exists
    icon_path = Path("shuddh_icon.ico")
    if icon_path.exists():
        cmd.extend(["--icon", str(icon_path)])
    
    print("Building executable with PyInstaller...")
    print(f"Command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("Build successful!")
        print(f"Executable created: dist\\Shuddh.exe")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Build failed: {e}")
        print(f"Error output: {e.stderr}")
        return False
    except FileNotFoundError:
        print("PyInstaller not found. Installing...")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller>=6.0.0"], check=True)
            print("PyInstaller installed successfully. Retrying build...")
            return build_executable()  # Retry after installation
        except subprocess.CalledProcessError as install_error:
            print(f"Failed to install PyInstaller: {install_error}")
            return False

if __name__ == "__main__":
    success = build_executable()
    if not success:
        sys.exit(1)