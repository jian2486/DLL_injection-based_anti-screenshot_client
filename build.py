import os
import sys
import subprocess
import shutil

def build_executable():
    """
    将程序打包为单个exe文件，无命令窗口，并包含图标
    """
    # 检查PyInstaller是否已安装
    try:
        import PyInstaller
    except ImportError:
        print("PyInstaller未安装，正在安装...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
    
    # 获取当前目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 定义文件路径
    main_script = os.path.join(current_dir, "AntiScreenshotManager.py")
    icon_file = os.path.join(current_dir, "favicon.ico")
    dll_dir = os.path.join(current_dir, "dll")
    
    # 检查必要文件是否存在
    if not os.path.exists(main_script):
        print(f"错误: 找不到主脚本 {main_script}")
        return False
        
    if not os.path.exists(icon_file):
        print(f"错误: 找不到图标文件 {icon_file}")
        return False
        
    if not os.path.exists(dll_dir):
        print(f"错误: 找不到DLL目录 {dll_dir}")
        return False
    
    # 构建PyInstaller命令
    cmd = [
        "pyinstaller",
        "--onefile",                    # 打包为单个exe文件
        "--noconsole",                  # 无命令窗口
        "--icon", icon_file,           # 包含图标
        "--add-data", f"dll;dll",      # 包含dll目录（会自动包含子目录）
        "--name", "反截屏管理程序",      # 设置exe文件名
        main_script
    ]
    
    print("正在执行打包命令:")
    print(" ".join(cmd))
    
    try:
        # 执行打包命令
        subprocess.run(cmd, check=True)
        print("\n打包完成!")
        print("可执行文件位于 dist/反截屏管理程序.exe")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n打包失败: {e}")
        return False
    except Exception as e:
        print(f"\n发生错误: {e}")
        return False

if __name__ == "__main__":
    build_executable()