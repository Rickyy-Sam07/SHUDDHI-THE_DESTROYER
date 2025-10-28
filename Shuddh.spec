# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['shuddh.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'report_generator',
        'checksum_verifier',
        'wmi',
        'pythoncom',
        'win32file',
        'win32api',
        'win32con',
        'Crypto.Cipher.AES',
        'Crypto.Random',
        'Crypto.Util.Counter'
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
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['shuddh_icon.ico'],
)
