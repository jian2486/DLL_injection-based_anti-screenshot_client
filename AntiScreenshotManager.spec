# -*- mode: python ; coding: utf-8 -*-

import sys
import os

block_cipher = None

# 获取当前目录
current_dir = os.path.dirname(os.path.abspath(sys.argv[0]))

# 定义需要包含的DLL文件
dll_files = []
dll_dir = os.path.join(current_dir, 'dll')

# 添加x86 DLLs
x86_dir = os.path.join(dll_dir, 'x86')
if os.path.exists(x86_dir):
    for file in os.listdir(x86_dir):
        if file.endswith('.dll'):
            src = os.path.join(x86_dir, file)
            dst = os.path.join('dll', 'x86', file)
            dll_files.append((src, dst))

# 添加x64 DLLs
x64_dir = os.path.join(dll_dir, 'x64')
if os.path.exists(x64_dir):
    for file in os.listdir(x64_dir):
        if file.endswith('.dll'):
            src = os.path.join(x64_dir, file)
            dst = os.path.join('dll', 'x64', file)
            dll_files.append((src, dst))

# 添加injector.py
injector_file = os.path.join(current_dir, 'injector.py')
injector_data = (injector_file, '.')

a = Analysis(
    ['AntiScreenshotManager.py'],
    pathex=[current_dir],
    binaries=[],
    datas=[injector_data] + dll_files,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='AntiScreenshotManager',
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
    icon='favicon.ico'
)