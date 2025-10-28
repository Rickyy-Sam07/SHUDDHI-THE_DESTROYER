# -*- mode: python ; coding: utf-8 -*-

"""
PyInstaller spec file for Shuddh - The Destroyer (Production Version)

This spec file ensures all necessary modules are included in the EXE:
- shuddh_gui.py (main GUI with report generation)
- production_system_core.py (hardware detection)
- production_wipe_engine.py (data destruction)
- production_verification_engine.py (verification & certificates)
- checksum_verifier.py (checksum calculations)
- report_generator.py (comprehensive report generation)
- emergency_handler.py (emergency abort)
- footprint_scanner.py (footprint scanning)

Build command:
    pyinstaller production_shuddh.spec
"""

a = Analysis(
    ['shuddh_gui.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'production_system_core',
        'production_wipe_engine',
        'production_verification_engine',
        'emergency_handler',
        'checksum_verifier',
        'report_generator',
        'footprint_scanner',
        'wmi',
        'pythoncom',
        'win32file',
        'win32api',
        'win32con',
        'pywintypes',
        'cryptography',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.asymmetric',
        'cryptography.hazmat.primitives.hashes',
        'cryptography.hazmat.primitives.serialization',
        'Crypto.Cipher',
        'Crypto.Random',
        'Crypto.Util',
        'reportlab',
        'reportlab.pdfgen',
        'reportlab.lib',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Shuddh',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # Set to True to see console output during execution
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='shuddh_icon.ico' if __import__('os').path.exists('shuddh_icon.ico') else None,
)
