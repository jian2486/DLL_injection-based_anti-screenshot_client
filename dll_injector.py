import ctypes
import ctypes.wintypes
import logging
import os
import sys
from ctypes import wintypes

# 引入进程管理器
from process_manager import ProcessManager

# 设置日志
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Windows API常量
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

# 定义缺失的类型
LPSECURITY_ATTRIBUTES = ctypes.c_void_p

# Windows API函数
kernel32 = ctypes.windll.kernel32
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = wintypes.BOOL

GetModuleHandle = kernel32.GetModuleHandleW
GetModuleHandle.argtypes = [wintypes.LPCWSTR]
GetModuleHandle.restype = wintypes.HANDLE

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = [wintypes.HANDLE, wintypes.LPCSTR]
GetProcAddress.restype = wintypes.LPVOID

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = [wintypes.HANDLE, LPSECURITY_ATTRIBUTES, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD]
CreateRemoteThread.restype = wintypes.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

GetLastError = kernel32.GetLastError
GetLastError.argtypes = []
GetLastError.restype = wintypes.DWORD


class DLLInjector:
    """DLL注入器类，用于向目标进程注入DLL"""
    
    _instance = None
    _initialized = False
    _injection_locks = set()  # 用于防止对同一进程的重复注入
    _process_manager = None  # 进程管理器实例
    
    def __new__(cls):
        """单例模式，确保只创建一个实例"""
        if cls._instance is None:
            cls._instance = super(DLLInjector, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        """初始化DLL注入器"""
        # 确保只初始化一次
        if not DLLInjector._initialized:
            logger.debug("初始化DLL注入器")
            DLLInjector._initialized = True
            # 初始化进程管理器
            DLLInjector._process_manager = ProcessManager()
        
    def inject_dll(self, process_id, dll_path):
        """
        向指定进程注入DLL
        
        Args:
            process_id (int): 目标进程ID
            dll_path (str): DLL文件的完整路径
            
        Returns:
            bool: 注入是否成功
        """
        # 检查是否正在对同一进程进行注入
        if process_id in DLLInjector._injection_locks:
            logger.debug(f"进程 {process_id} 正在注入中，跳过重复注入")
            return False
            
        # 设置注入锁
        DLLInjector._injection_locks.add(process_id)
        
        try:
            # 检查DLL文件是否存在
            if not os.path.exists(dll_path):
                logger.error(f"DLL文件不存在: {dll_path}")
                return False
                
            # 使用进程管理器执行注入
            success = DLLInjector._process_manager.inject_dll(process_id, dll_path)

            return success
            
        except Exception as e:
            logger.error(f"注入DLL时发生异常: {e}")
            return False
        finally:
            # 清除注入锁
            if process_id in DLLInjector._injection_locks:
                DLLInjector._injection_locks.remove(process_id)

    def inject_affinity_hide_dll(self, process_id):
        """
        向指定进程注入AffinityHide.dll (模式二)
        
        Args:
            process_id (int): 目标进程ID
            
        Returns:
            bool: 注入是否成功
        """
        return self.inject_dll_by_name(process_id, "AffinityHide.dll")

    def inject_affinity_trans_dll(self, process_id):
        """
        向指定进程注入AffinityTrans.dll (模式一)
        
        Args:
            process_id (int): 目标进程ID
            
        Returns:
            bool: 注入是否成功
        """
        return self.inject_dll_by_name(process_id, "AffinityTrans.dll")

    def inject_affinity_unhide_dll(self, process_id):
        """
        向指定进程注入AffinityUnhide.dll (取消反截屏)
        
        Args:
            process_id (int): 目标进程ID
            
        Returns:
            bool: 注入是否成功
        """
        return self.inject_dll_by_name(process_id, "AffinityUnhide.dll")

    def inject_affinity_status_dll(self, process_id):
        """
        向指定进程注入AffinityStatus.dll (检查状态)
        
        Args:
            process_id (int): 目标进程ID
            
        Returns:
            bool: 注入是否成功
        """
        return self.inject_dll_by_name(process_id, "AffinityStatus.dll")

    def inject_dll_by_name(self, process_id, dll_name):
        """
        根据DLL名称注入DLL
        
        Args:
            process_id (int): 目标进程ID
            dll_name (str): DLL文件名
            
        Returns:
            bool: 注入是否成功
        """
        # 获取DLL文件路径
        # 首先检查当前目录下的dll文件夹
        dll_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dll", dll_name)
        
        # 如果在当前目录的dll文件夹中找不到，则检查程序运行目录下的dll文件夹
        if not os.path.exists(dll_path):
            if getattr(sys, 'frozen', False):
                # 如果是打包后的exe文件
                dll_path = os.path.join(os.path.dirname(sys.executable), "dll", dll_name)
            else:
                # 如果是Python脚本
                dll_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dll", dll_name)
        
        return self.inject_dll(process_id, dll_path)
        
    def get_dll_name_from_path(self, dll_path):
        """
        根据DLL路径获取DLL名称
        
        Args:
            dll_path (str): DLL文件的完整路径
            
        Returns:
            str: DLL文件名
        """
        return os.path.basename(dll_path)
        
    def __del__(self):
        """析构函数，清理资源"""
        if DLLInjector._process_manager:
            DLLInjector._process_manager.shutdown()