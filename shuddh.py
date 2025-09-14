"""
Shuddh - OS-Safe Data Wiper
===========================

Main launcher script for Shuddh data wiper.
Automatically handles privilege elevation and error display.
"""

import sys
import os
import traceback
from pathlib import Path

def check_dependencies():
    """Check if all required dependencies are available"""
    missing = []
    
    try:
        import tkinter
    except ImportError:
        missing.append("tkinter")
    
    try:
        import wmi
    except ImportError:
        missing.append("wmi")
    
    try:
        import win32file
    except ImportError:
        missing.append("pywin32")
    
    try:
        import reportlab
    except ImportError:
        missing.append("reportlab")
    
    if missing:
        print("Missing required dependencies:")
        for dep in missing:
            print(f"  - {dep}")
        print("\nInstall with: pip install -r requirements_production.txt")
        return False
    
    return True

def main():
    """Main entry point with error handling"""
    print("Shuddh - OS-Safe Data Wiper")
    print("=" * 30)
    
    # Check dependencies
    if not check_dependencies():
        input("Press Enter to exit...")
        return
    
    # Check admin privileges and elevate if needed
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Administrator privileges required. Requesting elevation...")
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            return
    except Exception as e:
        print(f"Could not check admin privileges: {e}")
    
    try:
        # Import and run GUI
        from shuddh_gui import ShuddGUI
        
        app = ShuddGUI()
        app.run()
        
    except ImportError as e:
        print(f"Import Error: {e}")
        print("Make sure all production files are in the same directory.")
        traceback.print_exc()
        input("Press Enter to exit...")
    except Exception as e:
        print(f"Fatal Error: {e}")
        traceback.print_exc()
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()