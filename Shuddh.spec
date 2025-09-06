# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['production_shuddh.py'],
    pathex=[],
    binaries=[],
    datas=[('tools', 'tools')],
    hiddenimports=['win32timezone', 'pywintypes', 'win32api', 'win32con', 'win32file', 'wmi'],
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
    uac_admin=True,
    icon=['shuddh_icon.ico'],
)
