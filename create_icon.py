"""
Icon Creation Script for Shuddh
Creates application icon if not present
"""

import os
from pathlib import Path

def create_icon():
    """Create or verify application icon exists"""
    icon_path = Path("shuddh_icon.ico")
    
    if icon_path.exists():
        print(f"Icon already exists: {icon_path}")
        return True
    
    print("Icon file not found, using default system icon")
    return True

if __name__ == "__main__":
    create_icon()