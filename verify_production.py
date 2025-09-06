"""
Production Verification Script
=============================

Verifies that all production files are ready and safety features are removed.
"""

import os
import sys
from pathlib import Path
import importlib.util

def check_file_exists(filepath, description):
    """Check if a file exists"""
    if Path(filepath).exists():
        print(f"✅ {description}: {filepath}")
        return True
    else:
        print(f"❌ {description}: {filepath} - NOT FOUND")
        return False

def check_safety_removed(filepath):
    """Check if safety features are removed from a Python file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for development mode flags
        safety_indicators = [
            'development_mode=True',
            'DEVELOPMENT SAFETY',
            'test pass1',
            'SIMULATED',
            'SAFE:',
            'safety_barrier'
        ]
        
        found_safety = []
        for indicator in safety_indicators:
            if indicator in content:
                found_safety.append(indicator)
        
        if found_safety:
            print(f"⚠️  {filepath}: Safety features still present: {found_safety}")
            return False
        else:
            print(f"✅ {filepath}: Safety features removed")
            return True
            
    except Exception as e:
        print(f"❌ {filepath}: Error checking file: {e}")
        return False

def check_imports():
    """Check if required modules can be imported"""
    required_modules = [
        ('tkinter', 'GUI framework'),
        ('win32file', 'Windows API access'),
        ('wmi', 'Hardware detection'),
        ('cryptography', 'Certificate signing'),
    ]
    
    all_good = True
    for module, description in required_modules:
        try:
            __import__(module)
            print(f"✅ {description}: {module} available")
        except ImportError:
            print(f"⚠️  {description}: {module} not available (install with pip)")
            all_good = False
    
    return all_good

def main():
    """Main verification process"""
    print("🔍 SHUDDH PRODUCTION VERIFICATION")
    print("=" * 50)
    
    all_checks_passed = True
    
    # Check core production files
    print("\n📁 CHECKING PRODUCTION FILES:")
    files_to_check = [
        ('production_shuddh.py', 'Main application'),
        ('production_system_core.py', 'System core module'),
        ('production_wipe_engine.py', 'Wipe engine module'),
        ('production_verification_engine.py', 'Verification engine module'),
        ('requirements_production.txt', 'Production requirements'),
        ('build_executable.py', 'Build script'),
        ('deploy_production.bat', 'Deployment script'),
        ('PRODUCTION_README.md', 'Production documentation')
    ]
    
    for filepath, description in files_to_check:
        if not check_file_exists(filepath, description):
            all_checks_passed = False
    
    # Check safety features removed
    print("\n🔒 CHECKING SAFETY FEATURE REMOVAL:")
    python_files = [
        'production_shuddh.py',
        'production_system_core.py', 
        'production_wipe_engine.py',
        'production_verification_engine.py'
    ]
    
    for filepath in python_files:
        if Path(filepath).exists():
            if not check_safety_removed(filepath):
                all_checks_passed = False
    
    # Check imports
    print("\n📦 CHECKING DEPENDENCIES:")
    if not check_imports():
        all_checks_passed = False
    
    # Check admin privileges
    print("\n🔐 CHECKING ADMIN PRIVILEGES:")
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if is_admin:
            print("✅ Running with administrator privileges")
        else:
            print("⚠️  Not running as administrator (required for production use)")
    except Exception as e:
        print(f"❌ Error checking admin privileges: {e}")
        all_checks_passed = False
    
    # Final assessment
    print("\n" + "=" * 50)
    if all_checks_passed:
        print("🎉 ALL CHECKS PASSED - READY FOR PRODUCTION BUILD")
        print("\nNext steps:")
        print("1. Run: deploy_production.bat")
        print("2. Test executable on non-critical system")
        print("3. Deploy to target environment")
        print("\n⚠️  REMEMBER: This will perform ACTUAL data destruction!")
    else:
        print("❌ SOME CHECKS FAILED - NOT READY FOR PRODUCTION")
        print("\nPlease fix the issues above before building.")
    
    print("=" * 50)

if __name__ == "__main__":
    main()