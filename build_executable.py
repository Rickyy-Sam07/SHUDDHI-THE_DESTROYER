"""

This script creates the .exe file for the production version of the Shuddh application.but be carefull and dont run the .exe file on your main system as it will destroy data permanently.
"""

import subprocess
import sys
import os
from pathlib import Path

def install_requirements():
    
    print("Installing production requirements...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements_production.txt"])

def build_executable():
    """.exe bana rahe hai  using PyInstaller"""
    print("Building Shuddh.exe...")
    
    # PyInstaller command
    cmd = [
        "pyinstaller",
        "--onefile",                   
        "--windowed",                  
        "--name=Shuddh",               
        "--icon=shuddh_icon.ico",      
        "--add-data=tools;tools",      
        "--hidden-import=win32timezone",
        "--hidden-import=pywintypes",
        "--hidden-import=win32api",
        "--hidden-import=win32con",
        "--hidden-import=win32file",
        "--hidden-import=wmi",
        "--uac-admin",                 # Request admin privileges
        "production_shuddh.py"
    ]
    
    try:
        subprocess.check_call(cmd)
        print("1. Executable built successfully!")
        print("2. Location: dist/Shuddh.exe")
    except subprocess.CalledProcessError as e:
        print(f"!!! Build failed: {e}")
        # without icon 
        cmd_no_icon = [c for c in cmd if not c.startswith("--icon")]
        try:
            subprocess.check_call(cmd_no_icon)
            print("1. Executable built successfully (without icon)!")
            print("2. Location: dist/Shuddh.exe")
        except subprocess.CalledProcessError as e2:
            print(f"!!! Build failed again: {e2}")
            return False
    
    return True

def create_tools_directory():

    tools_dir = Path("tools")
    tools_dir.mkdir(exist_ok=True)
    
    placeholder_content = "# External tool placeholder - replace with actual binary in production"
    
    (tools_dir / "nvme.exe").write_text(placeholder_content)
    (tools_dir / "hdparm.exe").write_text(placeholder_content)
    (tools_dir / "openssl.exe").write_text(placeholder_content)
    
    print("3. Tools directory created with placeholders")

def main():
    """Main build process"""
    print("> Building Shuddh Production Executable")
    
    
    # Check if we're in the right directory
    if not Path("production_shuddh.py").exists():
        print("!!! Error: production_shuddh.py not found in current directory")
        return
    
    try:
        # Install requirements
        install_requirements()
        
        # Create tools directory
        create_tools_directory()
        
        # Build executable
        if build_executable():
            print("\n BUILD COMPLETED SUCCESSFULLY!")
        
            print("@@ Executable location: dist/Shuddh.exe")
            print("!!!  IMPORTANT: This executable will perform ACTUAL data destruction!")
            print("!!!  Test only on systems where data loss is acceptable!")
            print("!!!  Ensure you have proper authorization before use!")
        else:
            print("\n!!! BUILD FAILED!")

    except Exception as e:
        print(f"!!! Build process failed: {e}")

if __name__ == "__main__":
    main()