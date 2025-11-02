import subprocess
from ctypes import (WinError, byref, c_int, c_long, c_ulong, c_void_p,
                    create_string_buffer, windll)


class Injector:
    PROC_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)
    MEM_CREATE = 0x00001000 | 0x00002000
    MEM_RELEASE = 0x8000
    PAGE_EXECUTE_READWRITE = 0x40

    def __init__(self):
        self.kernel32 = windll.kernel32
        self.user32 = windll.user32
        self.pid = c_ulong()
        self.handle = None

    def create_process(self, path):
        return subprocess.Popen([path]).pid

    def load_from_pid(self, pid):
        self.unload()
        self.pid = c_ulong(pid)
        self.handle = self.kernel32.OpenProcess(self.PROC_ALL_ACCESS, 0, pid)
        if not self.handle:
            raise WinError()

    def unload(self):
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
            if not self.handle:
                raise WinError()
        self.handle = None

    def alloc_remote(self, buffer, size):
        from ctypes import c_size_t
        alloc = self.kernel32.VirtualAllocEx(self.handle, None, c_size_t(size),
                                             self.MEM_CREATE, self.PAGE_EXECUTE_READWRITE)
        if not alloc:
            raise WinError()
        self.write_memory(alloc, buffer)
        return alloc

    def free_remote(self, addr, size):
        from ctypes import c_size_t, c_void_p
        if not self.kernel32.VirtualFreeEx(self.handle, c_void_p(addr), c_size_t(0), self.MEM_RELEASE):
            raise WinError()

    def get_address_from_module(self, module, function):
        module_addr = self.kernel32.GetModuleHandleA(module.encode("ascii"))
        if not module_addr:
            raise WinError()
        function_addr = self.kernel32.GetProcAddress(module_addr, function.encode("ascii"))
        if not function_addr:
            raise WinError()
        return function_addr

    def create_remote_thread(self, function_addr, args):
        dll_addr = c_long(0)
        args_addr = self.alloc_remote(args, len(args))
        thread = self.kernel32.CreateRemoteThread(self.handle, None, 0, c_void_p(function_addr),
                                                  c_void_p(args_addr), 0, None)
        if not thread:
            raise WinError()
        if self.kernel32.WaitForSingleObject(thread, 0xFFFFFFFF) == 0xFFFFFFFF:
            raise WinError()
        if not self.kernel32.GetExitCodeThread(thread, byref(dll_addr)):
            raise WinError()
        self.free_remote(args_addr, len(args))
        return dll_addr.value

    def read_memory(self, addr, size):
        buffer = create_string_buffer(size)
        if not self.kernel32.ReadProcessMemory(self.handle, addr, buffer, size, None):
            raise WinError()
        return buffer

    def write_memory(self, addr, string):
        size = len(string)
        from ctypes import c_size_t
        if not self.kernel32.WriteProcessMemory(self.handle, addr, string, c_size_t(size), None):
            raise WinError()

    def load_library(self, buffer):
        function_addr = self.get_address_from_module("kernel32.dll", "LoadLibraryA")
        dll_addr = self.create_remote_thread(function_addr, buffer)
        # 验证DLL是否成功加载
        if dll_addr == 0:
            print("警告: LoadLibraryA可能未成功加载DLL")
        return dll_addr

    def inject_dll(self, path):
        # 确保路径是bytes类型
        if isinstance(path, str):
            path_bytes = path.encode("ascii") + b'\x00'
        else:
            path_bytes = path + b'\x00'
        result = self.load_library(path_bytes)
        return result

    def call_from_injected(self, path, dll_addr, function, args):
        function_offset = self.get_offset_of_exported_function(path.encode("ascii"), function)
        self.create_remote_thread(dll_addr + function_offset, args)

    def get_offset_of_exported_function(self, module, function):
        base_addr = self.kernel32.LoadLibraryA(module)
        if not base_addr:
            raise WinError()
        function_addr = self.kernel32.GetProcAddress(base_addr, function.encode("ascii"))
        if not function_addr:
            raise WinError()
        if not self.kernel32.FreeLibrary(base_addr):
            raise WinError()
        return function_addr - base_addr
