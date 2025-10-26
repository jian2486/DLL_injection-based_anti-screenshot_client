import ctypes
import threading
import time
from ctypes import wintypes

class DisplayAffinityManager:
    """窗口显示亲和力管理器，专门用于控制程序自身的防截屏设置"""
    
    def __init__(self):
        """初始化显示亲和力管理器，专门用于程序自身"""
        self.WDA_NONE = 0x00000000
        self.WDA_MONITOR = 0x00000001
        self.WDA_EXCLUDEFROMCAPTURE = 0x00000011
        
        # 初始化user32.dll中的函数
        self.user32 = ctypes.windll.user32
        self.kernel32 = ctypes.windll.kernel32
        
        # 设置函数参数和返回类型
        self._setup_function_signatures()
        
        # 线程控制变量
        self.affinity_thread = None
        self.affinity_thread_running = False
        
        # 防截屏功能开关状态
        self.anti_screenshot_enabled = False
        
        # 获取当前进程ID
        self.current_process_id = ctypes.windll.kernel32.GetCurrentProcessId()
        
        # 程序自身的窗口句柄列表
        self.own_windows = []
        
    def _setup_function_signatures(self):
        """设置Windows API函数的参数和返回类型"""
        # SetWindowDisplayAffinity
        self.user32.SetWindowDisplayAffinity.argtypes = [wintypes.HWND, wintypes.DWORD]
        self.user32.SetWindowDisplayAffinity.restype = wintypes.BOOL
        
        # GetWindowDisplayAffinity
        self.user32.GetWindowDisplayAffinity.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        self.user32.GetWindowDisplayAffinity.restype = wintypes.BOOL
        
        # GetCurrentProcessId
        self.kernel32.GetCurrentProcessId.argtypes = []
        self.kernel32.GetCurrentProcessId.restype = wintypes.DWORD
        
        # GetWindowThreadProcessId
        self.user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        self.user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        
        # FindWindowEx
        self.user32.FindWindowExW.argtypes = [wintypes.HWND, wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR]
        self.user32.FindWindowExW.restype = wintypes.HWND
        
        # IsWindowVisible
        self.user32.IsWindowVisible.argtypes = [wintypes.HWND]
        self.user32.IsWindowVisible.restype = wintypes.BOOL
        
        # GetWindowTextW
        self.user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        self.user32.GetWindowTextW.restype = ctypes.c_int
            
    def set_window_affinity(self, hwnd, affinity):
        """
        设置窗口的显示亲和力
        
        Args:
            hwnd: 窗口句柄
            affinity: 亲和力值 (WDA_NONE, WDA_MONITOR, WDA_EXCLUDEFROMCAPTURE)
            
        Returns:
            bool: 设置是否成功
        """
        try:
            result = self.user32.SetWindowDisplayAffinity(hwnd, affinity)
            if result:
                return True
            else:
                return False
        except Exception as e:
            return False
            
    def get_window_affinity(self, hwnd):
        """
        获取窗口的显示亲和力
        
        Args:
            hwnd: 窗口句柄
            
        Returns:
            int: 当前的亲和力值，失败时返回-1
        """
        try:
            affinity = wintypes.DWORD()
            result = self.user32.GetWindowDisplayAffinity(hwnd, ctypes.byref(affinity))
            if result:
                return affinity.value
            else:
                return -1
        except Exception as e:
            return -1
            
    def _find_own_windows(self):
        """
        查找程序自身的所有窗口句柄
        
        Returns:
            list: 程序自身的窗口句柄列表
        """
        own_windows = []
        try:
            hwnd = self.user32.FindWindowExW(None, None, None, None)
            
            while hwnd:
                # 获取窗口所属的进程ID
                window_pid = wintypes.DWORD()
                self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
                
                # 检查是否是当前进程且窗口可见
                if window_pid.value == self.current_process_id and self.user32.IsWindowVisible(hwnd):
                    own_windows.append(hwnd)
                        
                # 查找下一个窗口
                hwnd = self.user32.FindWindowExW(None, hwnd, None, None)
                
        except Exception as e:
            pass
            
        self.own_windows = own_windows
        return own_windows
            
    def apply_affinity_to_own_windows(self, affinity):
        """
        为程序自身的所有窗口应用显示亲和力
        
        Args:
            affinity: 要应用的亲和力值
            
        Returns:
            int: 成功设置的窗口数量
        """
        # 如果防截屏功能未启用且要设置的不是WDA_NONE，则不执行操作
        if not self.anti_screenshot_enabled and affinity != self.WDA_NONE:
            return 0
            
        try:
            # 查找程序自身的所有窗口
            own_windows = self._find_own_windows()
            modified_count = 0
            
            for hwnd in own_windows:
                # 应用显示亲和力
                if self.set_window_affinity(hwnd, affinity):
                    modified_count += 1
                        
            return modified_count
            
        except Exception as e:
            return 0
            
    def _affinity_worker(self):
        """反截屏管理线程的工作函数"""
        while self.affinity_thread_running:
            try:
                # 只有在防截屏功能启用时才执行操作
                if self.anti_screenshot_enabled:
                    # 为程序自身的所有窗口设置亲和力
                    self.apply_affinity_to_own_windows(self.WDA_EXCLUDEFROMCAPTURE)
                        
                # 线程休眠一段时间以避免过度占用CPU
                time.sleep(2.0)
                
            except Exception as e:
                time.sleep(1)  # 出错时等待更长时间
                
    def start_affinity_thread(self):
        """启动显示亲和力管理线程"""
        if not self.affinity_thread or not self.affinity_thread.is_alive():
            self.affinity_thread_running = True
            self.affinity_thread = threading.Thread(target=self._affinity_worker, daemon=True)
            self.affinity_thread.start()

    def stop_affinity_thread(self):
        """停止反截屏管理线程"""
        self.affinity_thread_running = False
        if self.affinity_thread and self.affinity_thread.is_alive():
            self.affinity_thread.join(timeout=2.0)
            
    def set_anti_screenshot_enabled(self, enabled):
        """
        设置程序自身防截屏功能开关状态
        
        Args:
            enabled: 是否启用防截屏功能
        """
        # 只有在状态真正改变时才进行操作
        if self.anti_screenshot_enabled != enabled:
            self.anti_screenshot_enabled = enabled
            # 确定要应用的亲和力值
            affinity = self.WDA_EXCLUDEFROMCAPTURE if enabled else self.WDA_NONE
            # 立即应用一次
            self.apply_affinity_to_own_windows(affinity)