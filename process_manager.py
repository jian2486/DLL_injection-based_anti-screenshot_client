import ctypes
import ctypes.wintypes
import logging
import os
import sys
import json
import time
from ctypes import wintypes

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


def inject_dll_task(task_data):
    """
    在独立进程中执行DLL注入任务
    
    Args:
        task_data (dict): 包含注入任务信息的字典
            {
                "process_id": int,           # 目标进程ID
                "dll_path": str,             # DLL文件路径
                "result_path": str           # 结果文件路径
            }
    """
    try:
        process_id = task_data["process_id"]
        dll_path = task_data["dll_path"]
        result_path = task_data["result_path"]
        
        # 初始化日志记录器（在子进程中）
        logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
        logger = logging.getLogger(__name__)

        # 检查DLL文件是否存在
        if not os.path.exists(dll_path):
            logger.error(f"DLL文件不存在: {dll_path}")
            result = {
                "process_id": process_id,
                "success": False,
                "error": f"DLL文件不存在: {dll_path}"
            }
            with open(result_path, 'w') as f:
                json.dump(result, f)
            return
            
        # 打开目标进程
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if not process_handle:
            error_code = GetLastError()
            logger.error(f"无法打开进程 {process_id}，错误码: {error_code}")
            result = {
                "process_id": process_id,
                "success": False,
                "error": f"无法打开进程，错误码: {error_code}"
            }
            with open(result_path, 'w') as f:
                json.dump(result, f)
            return
            
        # 在目标进程中分配内存用于存储DLL路径
        dll_path_bytes = dll_path.encode('utf-16le') + b'\x00\x00'  # UTF-16 LE with null terminator
        path_size = len(dll_path_bytes)
        
        allocated_memory = VirtualAllocEx(
            process_handle,
            None,
            path_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
        
        if not allocated_memory:
            error_code = GetLastError()
            logger.error(f"无法在目标进程中分配内存，错误码: {error_code}")
            CloseHandle(process_handle)
            result = {
                "process_id": process_id,
                "success": False,
                "error": f"无法在目标进程中分配内存，错误码: {error_code}"
            }
            with open(result_path, 'w') as f:
                json.dump(result, f)
            return
            
        # 将DLL路径写入目标进程内存
        written_bytes = ctypes.c_size_t(0)
        if not WriteProcessMemory(
            process_handle,
            allocated_memory,
            dll_path_bytes,
            path_size,
            ctypes.byref(written_bytes)
        ):
            error_code = GetLastError()
            logger.error(f"无法向目标进程写入DLL路径，错误码: {error_code}")
            CloseHandle(process_handle)
            result = {
                "process_id": process_id,
                "success": False,
                "error": f"无法向目标进程写入DLL路径，错误码: {error_code}"
            }
            with open(result_path, 'w') as f:
                json.dump(result, f)
            return
            
        # 获取LoadLibraryW函数地址
        kernel32_handle = GetModuleHandle("kernel32.dll")
        if not kernel32_handle:
            error_code = GetLastError()
            logger.error(f"无法获取kernel32.dll句柄，错误码: {error_code}")
            CloseHandle(process_handle)
            result = {
                "process_id": process_id,
                "success": False,
                "error": f"无法获取kernel32.dll句柄，错误码: {error_code}"
            }
            with open(result_path, 'w') as f:
                json.dump(result, f)
            return
            
        load_library_addr = GetProcAddress(kernel32_handle, b"LoadLibraryW")
        if not load_library_addr:
            error_code = GetLastError()
            logger.error(f"无法获取LoadLibraryW地址，错误码: {error_code}")
            CloseHandle(process_handle)
            result = {
                "process_id": process_id,
                "success": False,
                "error": f"无法获取LoadLibraryW地址，错误码: {error_code}"
            }
            with open(result_path, 'w') as f:
                json.dump(result, f)
            return
            
        # 创建远程线程执行LoadLibraryW加载DLL
        thread_handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            load_library_addr,
            allocated_memory,
            0,
            None
        )
        
        if not thread_handle:
            error_code = GetLastError()
            logger.error(f"无法创建远程线程，错误码: {error_code}")
            CloseHandle(process_handle)
            result = {
                "process_id": process_id,
                "success": False,
                "error": f"无法创建远程线程，错误码: {error_code}"
            }
            with open(result_path, 'w') as f:
                json.dump(result, f)
            return
            
        # 等待线程执行完成（最多等待5秒）
        result = kernel32.WaitForSingleObject(thread_handle, 5000)
        if result == 0xFFFFFFFF:  # WAIT_FAILED
            logger.warning(f"等待线程完成时出错，进程 {process_id}")
        
        # 清理资源
        CloseHandle(thread_handle)
        CloseHandle(process_handle)

        result = {
            "process_id": process_id,
            "success": True,
            "error": None
        }
        with open(result_path, 'w') as f:
            json.dump(result, f)
        
    except Exception as e:
        logger.error(f"注入DLL时发生异常: {e}")
        result = {
            "process_id": task_data.get("process_id", 0),
            "success": False,
            "error": str(e)
        }
        try:
            with open(result_path, 'w') as f:
                json.dump(result, f)
        except:
            pass


class ProcessManager:
    """进程管理器，用于创建独立进程执行DLL注入任务"""
    
    def __init__(self):
        """初始化进程管理器"""
        self.process_pool = []
        self._active_injections = set()  # 用于防止对同一进程的重复注入
        logger.info("进程管理器初始化完成")
        
    def inject_dll(self, process_id, dll_path):
        """
        向指定进程注入DLL（使用独立进程执行）
        
        Args:
            process_id (int): 目标进程ID
            dll_path (str): DLL文件的完整路径
            
        Returns:
            bool: 注入是否成功
        """
        # 检查是否正在对同一进程进行注入
        if process_id in self._active_injections:
            logger.debug(f"进程 {process_id} 正在注入中，跳过重复注入")
            return False
            
        # 设置注入锁
        self._active_injections.add(process_id)
        
        try:
            # 创建临时结果文件
            import tempfile
            result_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
            result_path = result_file.name
            result_file.close()
            
            # 创建任务数据
            task_data = {
                "process_id": process_id,
                "dll_path": dll_path,
                "result_path": result_path
            }
            
            # 创建独立进程执行注入任务
            import subprocess
            import sys
            process = subprocess.Popen([
                sys.executable, 
                __file__, 
                json.dumps(task_data)
            ])
            
            # 记录进程信息
            self.process_pool.append({
                "process": process,
                "process_id": process_id,
                "start_time": time.time(),
                "result_path": result_path
            })
            
            # 等待结果（最多等待10秒）
            try:
                # 等待进程结束
                process.wait(timeout=10)
                
                # 读取结果
                if os.path.exists(result_path):
                    with open(result_path, 'r') as f:
                        result = json.load(f)
                    os.unlink(result_path)  # 删除临时文件
                    
                    # 获取DLL文件名用于日志输出
                    dll_name = os.path.basename(dll_path)
                    
                    if result["process_id"] == process_id:
                        if result["success"]:
                            logger.info(f"为进程 {process_id} 注入{dll_name} 注入成功")
                            return True
                        else:
                            logger.error(f"进程 {process_id} 注入{dll_name} 失败: {result['error']}")
                            return False
                    else:
                        logger.error("返回结果与请求不匹配")
                        return False
                else:
                    logger.error("结果文件不存在")
                    return False
                    
            except Exception as e:
                logger.error(f"等待注入结果时发生异常: {e}")
                # 强制终止进程
                process.terminate()
                process.wait(timeout=1)
                # 清理临时文件
                if os.path.exists(result_path):
                    os.unlink(result_path)
                return False
                
        except Exception as e:
            logger.error(f"创建注入进程时发生异常: {e}")
            return False
        finally:
            # 清除注入锁
            if process_id in self._active_injections:
                self._active_injections.remove(process_id)
            
    def _cleanup_processes(self):
        """清理已完成的进程"""
        # 过滤掉已完成的进程
        active_processes = []
        for proc_info in self.process_pool:
            process = proc_info["process"]
            if process.poll() is None:  # 进程仍在运行
                # 检查是否超时（超过30秒）
                if time.time() - proc_info["start_time"] > 30:
                    logger.warning(f"进程 {proc_info['process_id']} 超时，强制终止")
                    process.terminate()
                else:
                    active_processes.append(proc_info)
            else:
                logger.info(f"进程 {proc_info['process_id']} 已完成")
                # 清理临时文件
                if "result_path" in proc_info and os.path.exists(proc_info["result_path"]):
                    os.unlink(proc_info["result_path"])
                
        self.process_pool = active_processes
        
    def shutdown(self):
        """关闭进程管理器，清理所有进程"""
        logger.info("关闭进程管理器")
        for proc_info in self.process_pool:
            process = proc_info["process"]
            if process.poll() is None:  # 进程仍在运行
                logger.info(f"终止进程 {proc_info['process_id']}")
                process.terminate()
                process.wait(timeout=1)
            # 清理临时文件
            if "result_path" in proc_info and os.path.exists(proc_info["result_path"]):
                os.unlink(proc_info["result_path"])
                
        self.process_pool.clear()
        # 清理注入锁
        self._active_injections.clear()


# 如果作为子进程运行，则执行任务
if __name__ == "__main__" and len(sys.argv) > 1:
    try:
        task_data = json.loads(sys.argv[1])
        inject_dll_task(task_data)
    except Exception as e:
        logger.error(f"子进程执行任务时出错: {e}")
    sys.exit(0)