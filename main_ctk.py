import sys
import os
import json
try:
    import psutil
    import win32gui
    import win32process
except ImportError as e:
    print(f"导入模块失败: {e}")
    print("请安装所需的依赖包:")
    print("pip install psutil pywin32")
    sys.exit(1)

import customtkinter as ctk
from tkinter import messagebox, simpledialog
import tkinter as tk
from tkinter import ttk
import threading
import time
import queue

# 引入 DisplayAffinityManager
from display_affinity_manager import DisplayAffinityManager
# 引入 DLLInjector
from dll_injector import DLLInjector
# 引入 UIComponents
from ui_components import UIComponents

# 设置customtkinter的外观模式和主题
ctk.set_appearance_mode("Light")  # 默认设置为浅色模式以符合用户偏好
ctk.set_default_color_theme("blue")  # 可选: "blue", "green", "dark-blue"


class ProcessLoader:
    """进程列表加载线程"""
    def __init__(self, callback):
        self.callback = callback
        self.process_dict = {}
        
    def run(self):
        try:
            # 收集所有进程信息
            for proc in psutil.process_iter():
                try:
                    pid = proc.pid
                    name = proc.name()
                    
                    try:
                        ppid = proc.ppid()
                    except:
                        ppid = 0
                    
                    if name not in self.process_dict:
                        self.process_dict[name] = {
                            'pids': [pid],
                            'ppids': [ppid],
                            'count': 1
                        }
                    else:
                        self.process_dict[name]['pids'].append(pid)
                        self.process_dict[name]['ppids'].append(ppid)
                        self.process_dict[name]['count'] += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # 格式化输出
            processes = []
            for name, info in self.process_dict.items():
                if info['count'] == 1:
                    process_info = f"{name} (PID: {info['pids'][0]})"
                else:
                    process_info = f"{name} ({info['count']} 个实例)"
                processes.append((process_info, name))
                
            # 调用回调函数传递结果
            self.callback(sorted(processes, key=lambda x: x[0]))
        except Exception as e:
            self.callback([])


class WindowLoader:
    """窗口列表加载线程"""
    def __init__(self, callback):
        self.callback = callback
        
    def run(self):
        windows = []
        
        def enum_windows_callback(hwnd, windows_list):
            if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
                try:
                    window_text = win32gui.GetWindowText(hwnd)
                    _, pid = win32process.GetWindowThreadProcessId(hwnd)
                    process_name = "unknown"
                    try:
                        process = psutil.Process(pid)
                        process_name = process.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    # 使用标准格式: "窗口标题 [进程名]"
                    window_info = f"{window_text} [{process_name}]"
                    windows_list.append((window_info, process_name))
                except Exception:
                    pass
            return True
            
        try:
            win32gui.EnumWindows(enum_windows_callback, windows)
            self.callback(sorted(windows, key=lambda x: x[0]))
        except Exception as e:
            self.callback([])


class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # 配置窗口
        self.title("反截屏管理程序")
        self.geometry("900x700")  # 保持原窗口尺寸
        
        # 初始化 DisplayAffinityManager (保留用于兼容性)
        self.display_affinity_manager = DisplayAffinityManager()
        # 使用DLL注入方式替代原有的反截屏功能
        # self.display_affinity_manager.set_anti_screenshot_enabled(True)
        # self.display_affinity_manager.get_current_process_id()  # 确保进程ID是最新的
        # self.display_affinity_manager.start_affinity_thread()
        
        # 添加全屏反截屏状态跟踪
        self.fullscreen_anti_screenshot_enabled = False
        
        # 防止反截屏保护重复应用的标志
        self._anti_screenshot_applying = False
        
        # 创建UI组件管理器
        self.ui_components = UIComponents(self)
        
        # 创建主布局
        self.ui_components.create_main_layout()
        
        # 初始化组件
        self.init_components()
        
        # 初始化加载器
        self.process_loader = None
        self.window_loader = None
        self.process_loading = False
        self.window_loading = False
        
        # 初始化定时器
        self.after(10000, self.auto_refresh)  # 每10秒自动刷新一次
        
        # 窗口完全初始化后刷新列表
        self.show_lists_refresh = True
        self.after(100, self.initial_refresh)

        
    def init_components(self):
        """初始化所有组件"""
        # 创建左侧模式一列表
        self.ui_components.create_mode1_section()
        
        # 创建左侧模式二列表
        self.ui_components.create_mode2_section()
        
        # 创建控制标签页
        self.ui_components.create_control_tab()
        
        # 创建设置标签页
        self.ui_components.create_settings_tab()
        
        # 创建关于标签页
        self.ui_components.create_about_tab()
        
    def _delayed_init_anti_screenshot_protection(self):
        """延迟初始化程序自身的反截屏保护"""
        # 检查设置中反截屏功能是否启用
        if hasattr(self, 'anti_screenshot_switch_var') and self.anti_screenshot_switch_var.get():
            try:
                # 使用DisplayAffinityManager为程序自身启用反截屏保护
                self.display_affinity_manager.set_anti_screenshot_enabled(True)
                self.display_affinity_manager.start_affinity_thread()
                self.status_label.configure(text="程序启动成功，已启用自身反截屏保护")
            except Exception as e:
                self.status_label.configure(text=f"启用反截屏保护时出错: {str(e)}")
        else:
            # 如果反截屏功能关闭，则不执行任何操作
            self.status_label.configure(text="程序启动成功，自身反截屏保护已禁用")
        
    def create_mode1_section(self):
        """创建模式一列表区域"""
        self.mode1_frame = ctk.CTkFrame(self.left_frame)
        self.mode1_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # 模式一标题
        mode1_label = ctk.CTkLabel(self.mode1_frame, text="模式一", font=ctk.CTkFont(size=14, weight="bold"))
        mode1_label.pack(pady=(5, 0))
        
        # 模式一列表框
        self.mode1_listbox_frame = ctk.CTkFrame(self.mode1_frame)
        self.mode1_listbox_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.mode1_listbox = tk.Listbox(
            self.mode1_listbox_frame, 
            bg="white", 
            fg="black",
            selectbackground="#3B8ED0",
            selectforeground="white"
        )
        self.mode1_listbox.pack(side="left", fill="both", expand=True)
        
        # 添加滚动条
        mode1_scrollbar = ctk.CTkScrollbar(self.mode1_listbox_frame, command=self.mode1_listbox.yview)
        mode1_scrollbar.pack(side="right", fill="y")
        self.mode1_listbox.configure(yscrollcommand=mode1_scrollbar.set)
        
        # 绑定右键菜单
        self.mode1_listbox.bind("<Button-3>", lambda e: self.show_mode_list_context_menu(e, self.mode1_listbox, "模式一"))
        
        # 模式一按钮框架
        mode1_buttons_frame = ctk.CTkFrame(self.mode1_frame)
        mode1_buttons_frame.pack(fill="x", padx=5, pady=(0, 5))
        
        self.mode1_add_btn = ctk.CTkButton(mode1_buttons_frame, text="添加", width=50, height=25, 
                                          font=ctk.CTkFont(size=14), command=lambda: self.add_custom_item(self.mode1_listbox, "模式一"))
        self.mode1_add_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)
        
        self.mode1_remove_btn = ctk.CTkButton(mode1_buttons_frame, text="移除", width=50, height=25,
                                             font=ctk.CTkFont(size=14), command=lambda: self.remove_selected_item(self.mode1_listbox, "模式一"))
        self.mode1_remove_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)
        
        self.mode1_clear_btn = ctk.CTkButton(mode1_buttons_frame, text="清空", width=50, height=25,
                                            font=ctk.CTkFont(size=14), command=lambda: self.clear_list(self.mode1_listbox, "模式一"))
        self.mode1_clear_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)
        
    def create_mode2_section(self):
        """创建模式二列表区域"""
        self.mode2_frame = ctk.CTkFrame(self.left_frame)
        self.mode2_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # 模式二标题
        mode2_label = ctk.CTkLabel(self.mode2_frame, text="模式二", font=ctk.CTkFont(size=14, weight="bold"))
        mode2_label.pack(pady=(5, 0))
        
        # 模式二列表框
        self.mode2_listbox_frame = ctk.CTkFrame(self.mode2_frame)
        self.mode2_listbox_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.mode2_listbox = tk.Listbox(
            self.mode2_listbox_frame, 
            bg="white", 
            fg="black",
            selectbackground="#3B8ED0",
            selectforeground="white"
        )
        self.mode2_listbox.pack(side="left", fill="both", expand=True)
        
        # 添加滚动条
        mode2_scrollbar = ctk.CTkScrollbar(self.mode2_listbox_frame, command=self.mode2_listbox.yview)
        mode2_scrollbar.pack(side="right", fill="y")
        self.mode2_listbox.configure(yscrollcommand=mode2_scrollbar.set)
        
        # 绑定右键菜单
        self.mode2_listbox.bind("<Button-3>", lambda e: self.show_mode_list_context_menu(e, self.mode2_listbox, "模式二"))
        
        # 模式二按钮框架
        mode2_buttons_frame = ctk.CTkFrame(self.mode2_frame)
        mode2_buttons_frame.pack(fill="x", padx=5, pady=(0, 5))
        
        self.mode2_add_btn = ctk.CTkButton(mode2_buttons_frame, text="添加", width=50, height=25,
                                          font=ctk.CTkFont(size=14), command=lambda: self.add_custom_item(self.mode2_listbox, "模式二"))
        self.mode2_add_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)
        
        self.mode2_remove_btn = ctk.CTkButton(mode2_buttons_frame, text="移除", width=50, height=25,
                                             font=ctk.CTkFont(size=14), command=lambda: self.remove_selected_item(self.mode2_listbox, "模式二"))
        self.mode2_remove_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)
        
        self.mode2_clear_btn = ctk.CTkButton(mode2_buttons_frame, text="清空", width=50, height=25,
                                            font=ctk.CTkFont(size=14), command=lambda: self.clear_list(self.mode2_listbox, "模式二"))
        self.mode2_clear_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)

    def create_control_tab(self):
        """创建控制标签页"""
        # 创建按钮框架，将模式切换按钮和刷新按钮放在同一行
        button_frame = ctk.CTkFrame(self.control_tab)
        button_frame.pack(pady=10, padx=10, fill="x")
        
        # 创建切换按钮
        self.current_mode = 1  # 1表示模式一，2表示模式二
        self.toggle_button = ctk.CTkButton(button_frame, text="当前模式: 模式一", 
                                          command=self.toggle_mode, 
                                          font=ctk.CTkFont(size=12, weight="bold"),
                                          width=150, height=30)
        self.toggle_button.pack(side="left", padx=(0, 10))
        
        # 添加刷新按钮
        self.refresh_windows_btn = ctk.CTkButton(button_frame, text="刷新窗口列表", width=120, command=self.refresh_windows_list)
        self.refresh_windows_btn.pack(side="left", padx=(0, 5))
        
        self.refresh_processes_btn = ctk.CTkButton(button_frame, text="刷新进程列表", width=120, command=self.refresh_processes_list)
        self.refresh_processes_btn.pack(side="left", padx=(0, 5))
        
        # 创建窗口列表区域
        window_frame = ctk.CTkFrame(self.control_tab)
        window_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        window_label = ctk.CTkLabel(window_frame, text="窗口列表 (双击添加)", font=ctk.CTkFont(size=12, weight="bold"))
        window_label.pack(pady=(5, 0))
        
        # 窗口列表框
        self.window_listbox_frame = ctk.CTkFrame(window_frame)
        self.window_listbox_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.window_listbox = tk.Listbox(
            self.window_listbox_frame,
            bg="white",
            fg="black",
            selectmode=tk.EXTENDED,
            selectbackground="#3B8ED0",
            selectforeground="white"
        )
        self.window_listbox.pack(side="left", fill="both", expand=True)
        self.window_listbox.bind("<Double-Button-1>", lambda e: self.add_to_current_mode_from_list(self.window_listbox))
        
        # 添加滚动条
        window_scrollbar = ctk.CTkScrollbar(self.window_listbox_frame, command=self.window_listbox.yview)
        window_scrollbar.pack(side="right", fill="y")
        self.window_listbox.configure(yscrollcommand=window_scrollbar.set)
        
        # 创建进程列表区域
        process_frame = ctk.CTkFrame(self.control_tab)
        process_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        process_label = ctk.CTkLabel(process_frame, text="进程列表 (双击添加)", font=ctk.CTkFont(size=12, weight="bold"))
        process_label.pack(pady=(5, 0))
        
        # 进程列表框
        self.process_listbox_frame = ctk.CTkFrame(process_frame)
        self.process_listbox_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.process_listbox = tk.Listbox(
            self.process_listbox_frame,
            bg="white",
            fg="black",
            selectmode=tk.EXTENDED,
            selectbackground="#3B8ED0",
            selectforeground="white"
        )
        self.process_listbox.pack(side="left", fill="both", expand=True)
        self.process_listbox.bind("<Double-Button-1>", lambda e: self.add_to_current_mode_from_list(self.process_listbox))
        
        # 添加滚动条
        process_scrollbar = ctk.CTkScrollbar(self.process_listbox_frame, command=self.process_listbox.yview)
        process_scrollbar.pack(side="right", fill="y")
        self.process_listbox.configure(yscrollcommand=process_scrollbar.set)
        
        # 添加说明标签
        instruction_label = ctk.CTkLabel(self.control_tab, text="说明：双击列表项可添加到当前模式", 
                                        text_color="blue", font=ctk.CTkFont(size=12))
        instruction_label.pack(pady=5)
        
    def create_settings_tab(self):
        """创建设置标签页"""
        settings_label = ctk.CTkLabel(self.settings_tab, text="程序设置", font=ctk.CTkFont(size=16, weight="bold"))
        settings_label.pack(pady=10)
        
        # 主题设置
        theme_label = ctk.CTkLabel(self.settings_tab, text="主题设置", font=ctk.CTkFont(size=14, weight="bold"))
        theme_label.pack(pady=(10, 5), anchor="w", padx=10)
        
        # 主题切换框架
        theme_frame = ctk.CTkFrame(self.settings_tab)
        theme_frame.pack(fill="x", padx=10, pady=2)
        
        theme_label = ctk.CTkLabel(theme_frame, text="选择主题:")
        theme_label.pack(side="left", padx=10, pady=2)
        
        # 主题选项
        self.theme_var = ctk.StringVar(value="Light")  # 默认主题
        light_radio = ctk.CTkRadioButton(theme_frame, text="浅色主题", variable=self.theme_var, value="Light", command=self.change_theme)
        light_radio.pack(side="left", padx=10, pady=2)
        
        dark_radio = ctk.CTkRadioButton(theme_frame, text="深色主题", variable=self.theme_var, value="Dark", command=self.change_theme)
        dark_radio.pack(side="left", padx=10, pady=2)
        
        # 反截屏设置
        anti_screenshot_label = ctk.CTkLabel(self.settings_tab, text="反截屏设置", font=ctk.CTkFont(size=14, weight="bold"))
        anti_screenshot_label.pack(pady=(20, 2), anchor="w", padx=10)
        
        # 程序自身反截屏保护说明
        program_anti_screenshot_desc = ctk.CTkLabel(
            self.settings_tab, 
            text="程序自身反截屏保护（防止本程序界面被截屏）", 
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        program_anti_screenshot_desc.pack(pady=(0, 2), anchor="w", padx=15)
        
        # 程序自身反截屏功能开关
        anti_screenshot_frame = ctk.CTkFrame(self.settings_tab)
        anti_screenshot_frame.pack(fill="x", padx=10, pady=2)
        
        anti_screenshot_label = ctk.CTkLabel(anti_screenshot_frame, text="启用程序自身反截屏保护:")
        anti_screenshot_label.pack(side="left", padx=10, pady=2)
        
        # 反截屏开关
        self.anti_screenshot_switch_var = ctk.BooleanVar(value=True)  # 默认启用
        self.anti_screenshot_switch = ctk.CTkSwitch(
            anti_screenshot_frame, 
            text="", 
            variable=self.anti_screenshot_switch_var, 
            command=self.toggle_anti_screenshot
        )
        self.anti_screenshot_switch.pack(side="left", padx=10, pady=10)
        
        # 子进程注入设置
        child_process_injection_desc = ctk.CTkLabel(
            self.settings_tab,
            text="子进程注入设置",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        child_process_injection_desc.pack(pady=(20, 5), anchor="w", padx=10)
        
        child_process_injection_note = ctk.CTkLabel(
            self.settings_tab,
            text="向指定程序的所有子进程注入反截屏保护",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        child_process_injection_note.pack(pady=(0, 5), anchor="w", padx=15)
        
        # 子进程注入开关
        child_process_injection_frame = ctk.CTkFrame(self.settings_tab)
        child_process_injection_frame.pack(fill="x", padx=10, pady=5)
        
        child_process_injection_label = ctk.CTkLabel(child_process_injection_frame, text="启用子进程注入:")
        child_process_injection_label.pack(side="left", padx=10, pady=10)
        
        # 子进程注入开关，默认关闭
        self.child_process_injection_var = ctk.BooleanVar(value=False)
        self.child_process_injection_switch = ctk.CTkSwitch(
            child_process_injection_frame,
            text="",
            variable=self.child_process_injection_var
        )
        self.child_process_injection_switch.pack(side="left", padx=10, pady=10)
        
        # 模式列表反截屏保护说明
        mode_anti_screenshot_desc = ctk.CTkLabel(
            self.settings_tab, 
            text="模式列表反截屏保护（通过DLL注入保护列表中的进程）", 
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        mode_anti_screenshot_desc.pack(pady=(10, 5), anchor="w", padx=15)
        
        mode_anti_screenshot_note = ctk.CTkLabel(
            self.settings_tab,
            text="在模式一和模式二列表中添加进程后，将自动向这些进程注入AffinityHide.dll",
            font=ctk.CTkFont(size=10),
            text_color="gray"
        )
        mode_anti_screenshot_note.pack(pady=(0, 5), anchor="w", padx=20)
        
        # 功能按钮区域
        functions_label = ctk.CTkLabel(self.settings_tab, text="功能操作", font=ctk.CTkFont(size=14, weight="bold"))
        functions_label.pack(pady=(20, 5), anchor="w", padx=10)
        
        # 功能按钮框架
        functions_frame = ctk.CTkFrame(self.settings_tab)
        functions_frame.pack(fill="x", padx=10, pady=5)
        
        # 将按钮放在一行里
        buttons_frame = ctk.CTkFrame(functions_frame, fg_color="transparent")
        buttons_frame.pack(fill="x", padx=10, pady=10)
        
        # 保存和加载按钮放在同一行
        save_btn = ctk.CTkButton(buttons_frame, text="保存", width=80, height=25, 
                                font=ctk.CTkFont(size=11), command=lambda: self.save_data(show_status=True))
        save_btn.pack(side="left", padx=5)
        
        load_btn = ctk.CTkButton(buttons_frame, text="加载", width=80, height=25,
                                font=ctk.CTkFont(size=11), command=self.load_data)
        load_btn.pack(side="left", padx=5)
        
    def create_about_tab(self):
        """创建关于标签页"""
        about_label = ctk.CTkLabel(self.about_tab, text="反截屏管理程序", font=ctk.CTkFont(size=16, weight="bold"))
        about_label.pack(pady=(10, 5))
        
        version_label = ctk.CTkLabel(self.about_tab, text="版本 1.0")
        version_label.pack()
        
        description_label = ctk.CTkLabel(self.about_tab, text="基于Windows Display Affinity技术和DLL注入的进程窗口反截屏保护工具")
        description_label.pack(pady=5)
        
        features_label = ctk.CTkLabel(self.about_tab, text="\n核心技术特性：", font=ctk.CTkFont(weight="bold"))
        features_label.pack(anchor="w", padx=10)
        
        feature_list = ctk.CTkLabel(self.about_tab, text=
            "- 基于DLL注入技术实现反截屏保护\n"
            "- 使用多种Affinity DLL防止屏幕录制\n"
            "- 支持进程级和窗口级精细控制\n"
            "- 多线程实时监控和更新窗口亲和性\n"
            "- 支持配置持久化和主题切换\n"
            "- 使用psutil库进行系统进程管理",
            justify="left", anchor="w")
        feature_list.pack(padx=10, pady=5, anchor="w")
        
        # 添加DLL说明
        dll_label = ctk.CTkLabel(self.about_tab, text="\nDLL功能说明：", font=ctk.CTkFont(weight="bold"))
        dll_label.pack(anchor="w", padx=10)
        
        dll_list = ctk.CTkLabel(self.about_tab, text=
            "- AffinityHide.dll: 模式二反截屏保护\n"
            "- AffinityTrans.dll: 模式一反截屏保护\n"
            "- AffinityUnhide.dll: 取消反截屏保护\n"
            "- AffinityStatus.dll: 检查进程保护状态",
            justify="left", anchor="w")
        dll_list.pack(padx=10, pady=5, anchor="w")
        
        # 添加技术说明
        tech_label = ctk.CTkLabel(self.about_tab, text="\n技术说明", font=ctk.CTkFont(size=14, weight="bold"))
        tech_label.pack(pady=(15, 5), anchor="w", padx=10)
        
        tech_text = ctk.CTkLabel(self.about_tab, text=
            "1. 利用Windows API实现DLL远程注入\n"
            "2. 通过DLL中的SetWindowDisplayAffinity API设置窗口属性\n"
            "3. 使用FindWindowEx遍历系统窗口句柄\n"
            "4. 多线程异步处理避免界面卡顿\n"
            "5. JSON格式配置文件存储用户设置\n"
            "6. 基于CustomTkinter现代UI框架构建",
            justify="left", anchor="w")
        tech_text.pack(padx=10, pady=5, anchor="w")
        
    def save_data(self, show_status=True):
        """保存数据到配置文件"""
        try:
            # 收集所有需要保存的数据
            config_data = {
                "theme": self.theme_var.get(),
                "mode1_items": [],
                "mode2_items": [],
                "current_mode": self.current_mode,
                "anti_screenshot_enabled": self.anti_screenshot_switch_var.get(),  # 保存反截屏开关状态
                "child_process_injection_enabled": self.child_process_injection_var.get()  # 保存子进程注入开关状态
            }
            
            # 保存模式一列表项
            for i in range(self.mode1_listbox.size()):
                item_text = self.mode1_listbox.get(i)
                # 检查是否有状态指示器（红点表示禁用，绿点表示启用）
                is_enabled = True
                if item_text.startswith("● "):
                    # 获取项目状态
                    is_enabled = getattr(self.mode1_listbox, f"item_{i}_status", "enabled") != "disabled"
                    # 保存时不带状态指示器的文本
                    clean_text = item_text[2:]
                else:
                    clean_text = item_text
                    
                config_data["mode1_items"].append({
                    "text": clean_text,
                    "enabled": is_enabled
                })
            
            # 保存模式二列表项
            for i in range(self.mode2_listbox.size()):
                item_text = self.mode2_listbox.get(i)
                # 检查是否有状态指示器（红点表示禁用，绿点表示启用）
                is_enabled = True
                if item_text.startswith("● "):
                    # 获取项目状态
                    is_enabled = getattr(self.mode2_listbox, f"item_{i}_status", "enabled") != "disabled"
                    # 保存时不带状态指示器的文本
                    clean_text = item_text[2:]
                else:
                    clean_text = item_text
                    
                config_data["mode2_items"].append({
                    "text": clean_text,
                    "enabled": is_enabled
                })
            
            # 保存到配置文件
            config_file = "config.json"
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump(config_data, f, ensure_ascii=False, indent=4)
            
            # 只在手动保存时显示状态信息
            if show_status:
                self.status_label.configure(text=f"配置已保存到 {config_file}")
        except Exception as e:
            if show_status:
                self.status_label.configure(text=f"保存配置失败: {str(e)}")
    
    def load_data(self):
        """从配置文件加载数据"""
        try:
            config_file = "config.json"
            if not os.path.exists(config_file):
                self.status_label.configure(text="配置文件不存在")
                # 即使没有配置文件，也要刷新列表
                self.after(100, self._delayed_list_refresh)
                return
                
            # 从配置文件加载数据
            with open(config_file, "r", encoding="utf-8") as f:
                config_data = json.load(f)
            
            # 恢复主题设置
            theme = config_data.get("theme", "Light")
            self.theme_var.set(theme)
            self.change_theme()
            
            # 恢复反截屏开关状态
            anti_screenshot_enabled = config_data.get("anti_screenshot_enabled", True)
            self.anti_screenshot_switch_var.set(anti_screenshot_enabled)
            # 根据配置设置反截屏功能，但仅在开关启用时才执行
            if anti_screenshot_enabled:
                self.toggle_anti_screenshot()
            
            # 恢复子进程注入开关状态
            child_process_injection_enabled = config_data.get("child_process_injection_enabled", False)
            self.child_process_injection_var.set(child_process_injection_enabled)
            
            # 清空现有列表
            self.mode1_listbox.delete(0, tk.END)
            self.mode2_listbox.delete(0, tk.END)
            
            # 恢复模式一列表项
            for item in config_data.get("mode1_items", []):
                item_text = item["text"]
                is_enabled = item.get("enabled", True)
                
                # 根据状态添加适当的指示器
                if not is_enabled:
                    display_text = "● " + item_text
                    # 为禁用项设置状态属性
                    index = self.mode1_listbox.size()
                    setattr(self.mode1_listbox, f"item_{index}_status", "disabled")
                else:
                    display_text = item_text
                    index = self.mode1_listbox.size()
                    setattr(self.mode1_listbox, f"item_{index}_status", "enabled")
                    
                self.mode1_listbox.insert(tk.END, display_text)
            
            # 恢复模式二列表项
            for item in config_data.get("mode2_items", []):
                item_text = item["text"]
                is_enabled = item.get("enabled", True)
                
                # 根据状态添加适当的指示器
                if not is_enabled:
                    display_text = "● " + item_text
                    # 为禁用项设置状态属性
                    index = self.mode2_listbox.size()
                    setattr(self.mode2_listbox, f"item_{index}_status", "disabled")
                else:
                    display_text = item_text
                    index = self.mode2_listbox.size()
                    setattr(self.mode2_listbox, f"item_{index}_status", "enabled")
                    
                self.mode2_listbox.insert(tk.END, display_text)
            
            # 恢复当前模式
            self.current_mode = config_data.get("current_mode", 1)
            if self.current_mode == 1:
                self.toggle_button.configure(text="当前模式: 模式一")
            else:
                self.toggle_button.configure(text="当前模式: 模式二")
            
            # 应用反截屏保护（两个列表都需要应用）
            # 使用延迟确保UI已完全初始化
            self.after(100, lambda: self.apply_anti_screenshot_protection(self.mode1_listbox))
            self.after(150, lambda: self.apply_anti_screenshot_protection(self.mode2_listbox))
            
            self.status_label.configure(text="配置加载成功")
            
            # 延迟刷新列表，确保在应用反截屏保护之后
            self.after(200, self._delayed_list_refresh)
        except Exception as e:
            self.status_label.configure(text=f"加载配置失败: {str(e)}")
            import traceback
            traceback.print_exc()
            # 即使加载配置失败，也要刷新列表
            self.after(100, self._delayed_list_refresh)
            
    def _delayed_list_refresh(self):
        """延迟刷新列表"""
        self.refresh_processes_list()
        self.refresh_windows_list()
        self.show_lists_refresh = False
        
    def apply_anti_screenshot_protection(self, listbox):
        """应用反截屏保护"""
        try:
            # 检查是否正在执行，防止重复执行
            if self._anti_screenshot_applying:
                return  # 如果正在执行，则直接返回
            
            # 设置执行状态
            self._anti_screenshot_applying = True
            
            # 在后台线程中执行耗时操作
            threading.Thread(target=self._apply_anti_screenshot_protection_thread, args=(listbox,), daemon=True).start()
        except Exception as e:
            self.status_label.configure(text=f"应用反截屏保护时发生错误，请查看日志")
            import traceback
            traceback.print_exc()
            # 重置执行状态
            self._anti_screenshot_applying = False

    def _apply_anti_screenshot_protection_thread(self, listbox):
        """在后台线程中应用反截屏保护"""
        try:
            # 初始化DLL注入器
            dll_injector = DLLInjector()
            
            # 确定当前是哪个列表（模式一还是模式二）
            is_mode1 = (listbox == self.mode1_listbox)
            
            # 从列表项中提取进程信息
            process_items = []
            for i in range(listbox.size()):
                text = listbox.get(i)
                # 获取项目状态
                item_status = getattr(listbox, f'item_{i}_status', 'enabled')
                
                # 如果项目被禁用，跳过
                if item_status == 'disabled':
                    continue
                    
                # 处理状态指示器
                if text.startswith("● "):
                    text = text[2:]
                    
                # 处理两种格式:
                # 1. "进程名 (PID: 1234)" 格式
                # 2. "窗口标题 [进程名]" 格式
                # 3. 自定义添加的项目格式
                if " [" in text and text.endswith("]"):
                    # 窗口列表格式: "窗口标题 [进程名]" - 提取进程名
                    process_name = text.split(" [")[-1][:-1]
                    process_items.append({"name": process_name, "type": "window", "text": text})
                elif " (" in text and text.endswith(")"):
                    # 进程列表格式: "进程名 (PID: 1234)"
                    process_name = text.split(" (")[0]
                    # 提取PID
                    try:
                        pid_str = text.split("(PID: ")[1].split(")")[0]
                        pid = int(pid_str)
                        process_items.append({"name": process_name, "type": "process", "text": text, "pid": pid})
                    except (IndexError, ValueError):
                        # 如果无法提取PID，只使用进程名
                        process_items.append({"name": process_name, "type": "process", "text": text})
                else:
                    # 自定义添加的项目格式，尝试直接作为进程名处理
                    process_items.append({"name": text, "type": "custom", "text": text})
            
            # 如果启用了子进程注入，则收集所有子进程（仅对进程类型项目）
            all_process_items = process_items.copy()
            if hasattr(self, 'child_process_injection_var') and self.child_process_injection_var.get():
                for item in process_items:
                    if item["type"] == "process" and "pid" in item:  # 只对有PID的进程列表中的项目查找子进程
                        child_processes = self._get_child_processes_by_pid(item["pid"])
                        for child_process in child_processes:
                            all_process_items.append({"name": child_process["name"], "type": "child", "text": item["text"], "pid": child_process["pid"]})
            
            # 获取所有正在运行的进程
            import psutil
            injected_count = 0
            
            # 用于跟踪已处理的进程PID，避免重复注入
            processed_pids = set()
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_name = proc.info['name']
                    proc_pid = proc.info['pid']
                    
                    # 检查进程是否在需要保护的列表中
                    for item in all_process_items:
                        should_inject = False
                        
                        if item["type"] == "window":
                            # 窗口类型项目，检查进程名匹配
                            should_inject = (proc_name == item["name"])
                        elif item["type"] in ["process", "child"]:
                            # 进程或子进程类型项目
                            # 如果有PID信息，优先使用PID匹配
                            if "pid" in item:
                                should_inject = (proc_pid == item["pid"])
                            else:
                                should_inject = (proc_name == item["name"])
                        elif item["type"] == "custom":
                            # 自定义类型项目
                            should_inject = (proc_name == item["name"])
                        
                        if should_inject and proc_pid not in processed_pids:
                            # 根据模式选择不同的DLL进行注入
                            if is_mode1:
                                # 模式一使用AffinityTrans.dll
                                success = dll_injector.inject_affinity_trans_dll(proc_pid)
                            else:
                                # 模式二使用AffinityHide.dll
                                success = dll_injector.inject_affinity_hide_dll(proc_pid)
                                
                            if success:
                                injected_count += 1
                                processed_pids.add(proc_pid)
                            break  # 找到匹配项后跳出循环
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # 忽略无法访问的进程
                    pass
            
            # 更新状态（在主线程中执行）
            self.after(0, lambda: self.status_label.configure(
                text=f"已尝试向 {injected_count} 个进程注入{'AffinityTrans' if is_mode1 else 'AffinityHide'}.dll"))
        except Exception as e:
            # 在出现错误时显示更明显的提示（在主线程中执行）
            self.after(0, lambda: self.status_label.configure(text=f"应用反截屏保护时发生错误，请查看日志"))
            import traceback
            traceback.print_exc()
        finally:
            # 重置执行状态
            self._anti_screenshot_applying = False
        
        # 确保防截屏功能处于启用状态
        if not self.display_affinity_manager.anti_screenshot_enabled:
            self.display_affinity_manager.set_anti_screenshot_enabled(True)
        
    def _get_child_processes_by_pid(self, parent_pid):
        """
        获取指定进程的所有子进程信息
        
        Args:
            parent_pid (int): 父进程PID
            
        Returns:
            list: 子进程信息列表 [{"name": str, "pid": int}, ...]
        """
        child_processes = []
        try:
            import psutil
            
            # 查找所有子进程
            for child_proc in psutil.process_iter(['pid', 'name', 'ppid']):
                try:
                    if child_proc.info['ppid'] == parent_pid:
                        child_processes.append({
                            "name": child_proc.info['name'],
                            "pid": child_proc.info['pid']
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                    
        except Exception as e:
            # 避免在获取子进程时出现错误影响主流程
            pass
            
        return child_processes

    def _clear_list_thread(self, process_names, mode_name):
        """在后台线程中为进程取消反截屏保护"""
        try:
            # 如果启用了子进程注入，则也包括子进程（仅对进程项目）
            all_process_names = process_names.copy()
            if hasattr(self, 'child_process_injection_var') and self.child_process_injection_var.get():
                # 只处理进程项目，不处理窗口项目
                for process_name in process_names:
                    # 检查是否为进程项目格式（窗口项目格式：包含 [ 和 ] 但不包含 PID 信息）
                    if not (" [" in process_name and process_name.endswith("]")):
                        # 是进程项目，查找子进程
                        child_processes = self._get_child_processes(process_name)
                        all_process_names.extend(child_processes)
            
            # 去重
            all_process_names = list(set(all_process_names))
            
            # 初始化DLL注入器
            dll_injector = DLLInjector()
            
            # 获取所有正在运行的进程
            import psutil
            uninjected_count = 0
            processed_pids = set()  # 防止重复注入
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_name = proc.info['name']
                    proc_pid = proc.info['pid']
                    
                    # 检查进程是否在需要取消保护的列表中
                    if proc_name in all_process_names and proc_pid not in processed_pids:
                        # 注入AffinityUnhide.dll取消反截屏保护
                        success = dll_injector.inject_affinity_unhide_dll(proc_pid)
                        if success:
                            uninjected_count += 1
                            processed_pids.add(proc_pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # 忽略无法访问的进程
                    pass
                    
            # 更新状态（在主线程中执行）
            self.after(0, lambda: self.status_label.configure(text=f"已尝试向 {uninjected_count} 个进程注入AffinityUnhide.dll取消反截屏保护"))
        except Exception as e:
            # 更新状态（在主线程中执行）
            self.after(0, lambda: self.status_label.configure(text=f"为进程取消反截屏保护时出错，请查看日志"))
            print(f"DEBUG: 为进程取消反截屏保护时出错: {e}")
        
    def _remove_selected_item_thread(self, removed_process_names, mode_name):
        """在后台线程中为移除的进程取消反截屏保护"""
        try:
            # 如果启用了子进程注入，则也包括子进程（仅对进程项目）
            all_process_names = removed_process_names.copy()
            if hasattr(self, 'child_process_injection_var') and self.child_process_injection_var.get():
                # 只处理进程项目，不处理窗口项目
                for process_name in removed_process_names:
                    # 检查是否为进程项目格式（窗口项目格式：包含 [ 和 ] 但不包含 PID 信息）
                    if not (" [" in process_name and process_name.endswith("]")):
                        # 是进程项目，查找子进程
                        child_processes = self._get_child_processes(process_name)
                        all_process_names.extend(child_processes)
            
            # 去重
            all_process_names = list(set(all_process_names))
            
            # 初始化DLL注入器
            dll_injector = DLLInjector()
            
            # 获取所有正在运行的进程
            import psutil
            uninjected_count = 0
            processed_pids = set()  # 防止重复注入
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_name = proc.info['name']
                    proc_pid = proc.info['pid']
                    
                    # 检查进程是否在需要取消保护的列表中
                    if proc_name in all_process_names and proc_pid not in processed_pids:
                        # 注入AffinityUnhide.dll取消反截屏保护
                        success = dll_injector.inject_affinity_unhide_dll(proc_pid)
                        if success:
                            uninjected_count += 1
                            processed_pids.add(proc_pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # 忽略无法访问的进程
                    pass
                    
            # 更新状态（在主线程中执行）
            self.after(0, lambda: self.status_label.configure(text=f"已从 {mode_name} 中移除选中的项目，并尝试向 {uninjected_count} 个进程注入AffinityUnhide.dll"))
        except Exception as e:
            # 更新状态（在主线程中执行）
            self.after(0, lambda: self.status_label.configure(text=f"为进程取消反截屏保护时出错，请查看日志"))
            print(f"DEBUG: 为进程取消反截屏保护时出错: {e}")
        
    def add_custom_item(self, listbox, mode_name):
        """添加自定义项目"""
        item_text = simpledialog.askstring("添加项目", "请输入项目名称:")
        if item_text:
            # 检查是否已存在相同项目（去除状态指示器前缀后比较）
            exists = False
            for i in range(listbox.size()):
                existing_item = listbox.get(i)
                # 去除状态指示器前缀进行比较
                clean_existing = existing_item[2:] if existing_item.startswith("● ") else existing_item

                if clean_existing == item_text:
                    exists = True
                    break
            
            if exists:
                self.status_label.configure(text=f"项目 '{item_text}' 已存在于 {mode_name} 中")
            else:
                # 检查该项目是否已经存在于另一个列表中
                other_listbox = self.mode2_listbox if listbox == self.mode1_listbox else self.mode1_listbox
                other_mode_name = "模式二" if mode_name == "模式一" else "模式一"
                already_exists_in_other = False
                
                for i in range(other_listbox.size()):
                    existing_item = other_listbox.get(i)
                    clean_existing = existing_item[2:] if existing_item.startswith("● ") else existing_item
                    if clean_existing == item_text:
                        already_exists_in_other = True
                        break
                
                if already_exists_in_other:
                    self.status_label.configure(text=f"项目 '{item_text}' 已存在于 {other_mode_name} 中，无法同时添加到两个列表")
                else:
                    listbox.insert(tk.END, item_text)
                    # 为新项目设置默认状态
                    index = listbox.size() - 1
                    setattr(listbox, f'item_{index}_status', 'enabled')
                    self.status_label.configure(text=f"已向 {mode_name} 添加项目: {item_text}")
                    # 添加项目后应用反截屏保护（在后台线程中执行）
                    threading.Thread(target=self._apply_anti_screenshot_protection_thread, args=(listbox,), daemon=True).start()
                    # 自动保存配置
                    self.save_data(show_status=False)
            
    def clear_list(self, listbox, mode_name):
        """清空列表"""
        # 在清空列表前，先为列表中的所有进程取消反截屏保护
        process_names = []
        for i in range(listbox.size()):
            text = listbox.get(i)
            # 获取项目状态
            item_status = getattr(listbox, f'item_{i}_status', 'enabled')
            
            # 只处理启用状态的项目
            if item_status != 'disabled':
                # 处理状态指示器
                if text.startswith("● "):
                    text = text[2:]
                    
                # 处理多种格式:
                if " [" in text and text.endswith("]"):
                    # 窗口列表格式: "窗口标题 [进程名]"
                    process_name = text.split(" [")[-1][:-1]
                    process_names.append(process_name)
                elif " (" in text and text.endswith(")"):
                    # 进程列表格式: "进程名 (PID: 1234)"
                    process_name = text.split(" (")[0]
                    process_names.append(process_name)
                else:
                    # 自定义添加的项目格式，直接作为进程名处理
                    process_names.append(text)
                
        # 为这些进程移除反截屏保护（注入AffinityUnhide.dll）
        if process_names:
            # 在后台线程中执行耗时操作
            threading.Thread(target=self._clear_list_thread, args=(process_names, mode_name), daemon=True).start()
        else:
            self.status_label.configure(text=f"已清空 {mode_name}")
            
        # 清空列表
        listbox.delete(0, tk.END)
        # 自动保存配置
        self.save_data(show_status=False)
        
    def remove_selected_item(self, listbox, mode_name):
        """从列表中移除选中的项目"""
        selected_indices = listbox.curselection()
        if not selected_indices:
            return
            
        # 收集将要移除的进程名称
        removed_process_names = []
        for index in reversed(selected_indices):  # 反向遍历以避免索引问题
            text = listbox.get(index)
            # 获取项目状态
            item_status = getattr(listbox, f'item_{index}_status', 'enabled')
            
            # 只处理启用状态的项目
            if item_status != 'disabled':
                # 处理状态指示器
                if text.startswith("● "):
                    text = text[2:]
                    
                # 处理两种格式:
                if " [" in text and text.endswith("]"):
                    # 窗口列表格式: "窗口标题 [进程名]"
                    process_name = text.split(" [")[-1][:-1]
                    removed_process_names.append(process_name)
                elif " (" in text and text.endswith(")"):
                    # 进程列表格式: "进程名 (PID: 1234)"
                    process_name = text.split(" (")[0]
                    removed_process_names.append(process_name)
                
        # 从列表中移除项目（反向删除以避免索引问题）
        for index in reversed(selected_indices):
            listbox.delete(index)
            
        # 为这些进程移除反截屏保护（注入AffinityUnhide.dll）
        if removed_process_names:
            # 在后台线程中执行耗时操作
            threading.Thread(target=self._remove_selected_item_thread, args=(removed_process_names, mode_name), daemon=True).start()
        else:
            self.status_label.configure(text=f"已从 {mode_name} 中移除选中的项目")
        # 自动保存配置
        self.save_data(show_status=False)
        
    def _remove_selected_item_thread(self, removed_process_names, mode_name):
        """在后台线程中为移除的进程取消反截屏保护"""
        try:
            # 如果启用了子进程注入，则也包括子进程（仅对进程项目）
            all_process_names = removed_process_names.copy()
            if hasattr(self, 'child_process_injection_var') and self.child_process_injection_var.get():
                # 只处理进程项目，不处理窗口项目
                for process_name in removed_process_names:
                    # 检查是否为进程项目格式（窗口项目格式：包含 [ 和 ] 但不包含 PID 信息）
                    if not (" [" in process_name and process_name.endswith("]")):
                        # 是进程项目，查找子进程
                        child_processes = self._get_child_processes(process_name)
                        all_process_names.extend(child_processes)
            
            # 去重
            all_process_names = list(set(all_process_names))
            
            # 初始化DLL注入器
            dll_injector = DLLInjector()
            
            # 获取所有正在运行的进程
            import psutil
            uninjected_count = 0
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_name = proc.info['name']
                    proc_pid = proc.info['pid']
                    
                    # 检查进程是否在需要取消保护的列表中
                    if proc_name in all_process_names:
                        # 注入AffinityUnhide.dll取消反截屏保护
                        success = dll_injector.inject_affinity_unhide_dll(proc_pid)
                        if success:
                            uninjected_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # 忽略无法访问的进程
                    pass
                    
            # 更新状态（在主线程中执行）
            self.after(0, lambda: self.status_label.configure(text=f"已从 {mode_name} 中移除选中的项目，并尝试向 {uninjected_count} 个进程注入AffinityUnhide.dll"))
        except Exception as e:
            # 更新状态（在主线程中执行）
            self.after(0, lambda: self.status_label.configure(text=f"为进程取消反截屏保护时出错，请查看日志"))
            print(f"DEBUG: 为进程取消反截屏保护时出错: {e}")
    def show_mode_list_context_menu(self, event, listbox, mode_name):
        """显示模式列表右键菜单"""
        # 获取选中项
        selection = listbox.curselection()
        if not selection:
            return
            
        index = selection[0]
        
        # 创建右键菜单
        context_menu = tk.Menu(self, tearoff=0)
        
        # 添加开关选项
        context_menu.add_command(
            label="开关", 
            command=lambda: self.toggle_item_status(listbox, index, mode_name)
        )
        
        # 添加转移到另一模式选项
        context_menu.add_command(
            label="转移到另一模式",
            command=lambda: self.switch_item_mode(listbox, index)
        )
        
        # 添加检查状态选项
        context_menu.add_command(
            label="检查状态",
            command=lambda: self.check_item_status(listbox, index)
        )
        
        # 显示菜单
        context_menu.post(event.x_root, event.y_root)
        
    def check_item_status(self, listbox, index):
        """检查项目状态"""
        # 获取项目文本
        item_text = listbox.get(index)
        
        # 处理状态指示器
        if item_text.startswith("● "):
            clean_text = item_text[2:]
        else:
            clean_text = item_text
            
        # 从项目文本中提取进程名
        process_name = None
        if " [" in clean_text and clean_text.endswith("]"):
            # 窗口列表格式: "窗口标题 [进程名]"
            process_name = clean_text.split(" [")[-1][:-1]
        elif " (" in clean_text and clean_text.endswith(")"):
            # 进程列表格式: "进程名 (PID: 1234)"
            process_name = clean_text.split(" (")[0]
        else:
            # 自定义添加的项目格式，直接作为进程名处理
            process_name = clean_text
            
        if not process_name:
            self.status_label.configure(text="无法提取进程名")
            return
            
        # 查找进程ID
        import psutil
        target_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] == process_name:
                    target_pid = proc.info['pid']
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        if not target_pid:
            self.status_label.configure(text=f"未找到进程: {process_name}")
            return
            
        # 注入状态检查DLL
        dll_injector = DLLInjector()
        success = dll_injector.inject_affinity_status_dll(target_pid)
        if success:
            self.status_label.configure(text=f"已向进程 {process_name} 注入状态检查DLL")
            # TODO: 实现状态返回值的读取和解析
            # 这里应该读取DLL返回的状态信息并更新UI
        else:
            self.status_label.configure(text=f"向进程 {process_name} 注入状态检查DLL失败")
            
    def switch_item_mode(self, source_listbox, index):
        """将项目转移到另一模式"""
        # 获取项目文本
        item_text = source_listbox.get(index)
        # 获取项目状态
        item_status = getattr(source_listbox, f'item_{index}_status', 'enabled')
        
        # 确定源列表和目标列表
        if source_listbox == self.mode1_listbox:
            target_listbox = self.mode2_listbox
            source_name = "模式一"
            target_name = "模式二"
            # 源模式是模式一，目标模式是模式二
            from_mode = "mode1"
            to_mode = "mode2"
        else:
            target_listbox = self.mode1_listbox
            source_name = "模式二"
            target_name = "模式一"
            # 源模式是模式二，目标模式是模式一
            from_mode = "mode2"
            to_mode = "mode1"
            
        # 检查目标列表中是否已存在相同项目
        exists = False
        for i in range(target_listbox.size()):
            existing_item = target_listbox.get(i)
            # 去除状态指示器前缀进行比较
            clean_existing = existing_item[2:] if existing_item.startswith("● ") else existing_item
            clean_item_text = item_text[2:] if item_text.startswith("● ") else item_text
            if clean_existing == clean_item_text:
                exists = True
                break
                
        if exists:
            clean_item_text = item_text[2:] if item_text.startswith("● ") else item_text
            self.status_label.configure(text=f"项目 '{clean_item_text}' 已存在于 {target_name} 中")
            return
            
        # 从源列表移除项目
        source_listbox.delete(index)
        
        # 添加到目标列表
        target_index = target_listbox.size()
        target_listbox.insert(target_index, item_text)
        # 保持项目状态
        setattr(target_listbox, f'item_{target_index}_status', item_status)
        
        # 更新状态栏
        clean_text = item_text[2:] if item_text.startswith("● ") else item_text
        self.status_label.configure(text=f"已将 '{clean_text}' 从 {source_name} 转移到 {target_name}")
        
        # 如果项目是启用状态，则需要先取消反截屏保护，然后重新应用新模式的反截屏保护
        if item_status != 'disabled':
            # 在后台线程中执行耗时操作
            threading.Thread(target=self._switch_item_mode_thread, args=(clean_text, from_mode, to_mode), daemon=True).start()
        
        # 自动保存配置
        self.save_data(show_status=False)
        
    def _switch_item_mode_thread(self, clean_text, from_mode, to_mode):
        """在后台线程中执行模式切换的DLL操作"""
        # 提取进程信息
        process_name = None
        is_window_item = False
        pid = None
        if " [" in clean_text and clean_text.endswith("]"):
            # 窗口列表格式: "窗口标题 [进程名]"
            process_name = clean_text.split(" [")[-1][:-1]
            is_window_item = True
        elif " (" in clean_text and clean_text.endswith(")"):
            # 进程列表格式: "进程名 (PID: 1234)"
            process_name = clean_text.split(" (")[0]
            # 提取PID
            try:
                pid_str = clean_text.split("(PID: ")[1].split(")")[0]
                pid = int(pid_str)
            except (IndexError, ValueError):
                pass
        else:
            # 自定义添加的项目格式，直接作为进程名处理
            process_name = clean_text
            
        if process_name:
            # 查找进程ID
            import psutil
            target_pids = []
            if pid is not None:
                # 如果有明确的PID，只针对该PID
                target_pids = [pid]
            elif is_window_item:
                # 对于窗口项目，我们需要更精确地匹配
                # 这里简化处理，仍然查找所有同名进程
                # 在实际应用中，可能需要通过其他方式获取特定窗口的PID
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if proc.info['name'] == process_name:
                            target_pids.append(proc.info['pid'])
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
            else:
                # 对于进程项目，查找所有同名进程
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if proc.info['name'] == process_name:
                            target_pids.append(proc.info['pid'])
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                    
            if target_pids:
                # 先注入AffinityUnhide.dll取消反截屏保护
                dll_injector = DLLInjector()
                unhide_success_count = 0
                processed_pids = set()  # 防止重复注入
                
                for target_pid in target_pids:
                    if target_pid not in processed_pids:
                        unhide_success = dll_injector.inject_affinity_unhide_dll(target_pid)
                        if unhide_success:
                            unhide_success_count += 1
                            processed_pids.add(target_pid)
                
                if unhide_success_count > 0:
                    # 更新状态（在主线程中执行）
                    self.after(0, lambda: self.status_label.configure(text=f"已向 {unhide_success_count} 个进程注入AffinityUnhide.dll取消反截屏保护"))
                
                # 然后注入新模式对应的DLL
                success_count = 0
                processed_pids = set()  # 重新初始化防止重复注入
                
                if to_mode == "mode1":
                    # 转移到模式一，使用AffinityTrans.dll
                    for target_pid in target_pids:
                        if target_pid not in processed_pids:
                            success = dll_injector.inject_affinity_trans_dll(target_pid)
                            if success:
                                success_count += 1
                                processed_pids.add(target_pid)
                    if success_count > 0:
                        # 更新状态（在主线程中执行）
                        self.after(0, lambda: self.status_label.configure(text=f"已将 '{clean_text}' 转移并注入AffinityTrans.dll到 {success_count} 个进程"))
                else:
                    # 转移到模式二，使用AffinityHide.dll
                    for target_pid in target_pids:
                        if target_pid not in processed_pids:
                            success = dll_injector.inject_affinity_hide_dll(target_pid)
                            if success:
                                success_count += 1
                                processed_pids.add(target_pid)
                    if success_count > 0:
                        # 更新状态（在主线程中执行）
                        self.after(0, lambda: self.status_label.configure(text=f"已将 '{clean_text}' 转移并注入AffinityHide.dll到 {success_count} 个进程"))
                
                # 如果启用了子进程注入，则也对子进程执行相同操作（仅对进程项目）
                if not is_window_item and hasattr(self, 'child_process_injection_var') and self.child_process_injection_var.get():
                    child_processes = self._get_child_processes(process_name)
                    processed_pids = set()  # 防止重复注入
                    
                    for child_process_name in child_processes:
                        for child_proc in psutil.process_iter(['pid', 'name']):
                            try:
                                if child_proc.info['name'] == child_process_name and child_proc.info['pid'] not in processed_pids:
                                    child_pid = child_proc.info['pid']
                                    
                                    # 先取消子进程的反截屏保护
                                    dll_injector.inject_affinity_unhide_dll(child_pid)
                                    
                                    # 然后根据新模式注入对应的DLL
                                    if to_mode == "mode1":
                                        dll_injector.inject_affinity_trans_dll(child_pid)
                                    else:
                                        dll_injector.inject_affinity_hide_dll(child_pid)
                                        
                                    processed_pids.add(child_pid)
                            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                                pass

    def _rehide_process_thread(self, process_text, listbox):
        """在后台线程中重新应用进程的反截屏保护"""
        # 提取进程信息
        process_name = None
        is_window_item = False
        pid = None
        if " [" in process_text and process_text.endswith("]"):
            # 窗口列表格式: "窗口标题 [进程名]"
            process_name = process_text.split(" [")[-1][:-1]
            is_window_item = True
        elif " (" in process_text and process_text.endswith(")"):
            # 进程列表格式: "进程名 (PID: 1234)"
            process_name = process_text.split(" (")[0]
            # 提取PID
            try:
                pid_str = process_text.split("(PID: ")[1].split(")")[0]
                pid = int(pid_str)
            except (IndexError, ValueError):
                pass
        else:
            # 自定义添加的项目格式，直接作为进程名处理
            process_name = process_text
            
        if not process_name:
            return
            
        # 查找进程ID
        import psutil
        target_pids = []
        if pid is not None:
            # 如果有明确的PID，只针对该PID
            target_pids = [pid]
        else:
            # 对于窗口项目，仍然查找所有同名进程（在实际应用中可以优化）
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'] == process_name:
                        target_pids.append(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                
        if not target_pids:
            return
            
        # 确定当前是哪个列表（模式一还是模式二）
        is_mode1 = (listbox == self.mode1_listbox)
            
        # 注入对应的DLL重新应用反截屏保护
        dll_injector = DLLInjector()
        success_count = 0
        processed_pids = set()  # 防止重复注入
        
        if is_mode1:
            # 模式一使用AffinityTrans.dll
            for target_pid in target_pids:
                if target_pid not in processed_pids:
                    success = dll_injector.inject_affinity_trans_dll(target_pid)
                    if success:
                        success_count += 1
                        processed_pids.add(target_pid)
            if success_count > 0:
                # 更新状态（在主线程中执行）
                self.after(0, lambda: self.status_label.configure(text=f"已向 {success_count} 个进程注入AffinityTrans.dll重新应用反截屏保护"))
        else:
            # 模式二使用AffinityHide.dll
            for target_pid in target_pids:
                if target_pid not in processed_pids:
                    success = dll_injector.inject_affinity_hide_dll(target_pid)
                    if success:
                        success_count += 1
                        processed_pids.add(target_pid)
            if success_count > 0:
                # 更新状态（在主线程中执行）
                self.after(0, lambda: self.status_label.configure(text=f"已向 {success_count} 个进程注入AffinityHide.dll重新应用反截屏保护"))
                
        # 如果启用了子进程注入，且不是窗口项目，则也对子进程执行相同操作
        if not is_window_item and hasattr(self, 'child_process_injection_var') and self.child_process_injection_var.get():
            child_processes = self._get_child_processes(process_name)
            processed_pids = set()  # 防止重复注入
            
            for child_process_name in child_processes:
                for child_proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if child_proc.info['name'] == child_process_name and child_proc.info['pid'] not in processed_pids:
                            child_pid = child_proc.info['pid']
                            
                            # 根据模式注入对应的DLL
                            if is_mode1:
                                dll_injector.inject_affinity_trans_dll(child_pid)
                            else:
                                dll_injector.inject_affinity_hide_dll(child_pid)
                                
                            processed_pids.add(child_pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass

    def _unhide_process_thread(self, process_text):
        """在后台线程中取消进程的反截屏保护"""
        # 提取进程信息
        process_name = None
        is_window_item = False
        pid = None
        if " [" in process_text and process_text.endswith("]"):
            # 窗口列表格式: "窗口标题 [进程名]"
            process_name = process_text.split(" [")[-1][:-1]
            is_window_item = True
        elif " (" in process_text and process_text.endswith(")"):
            # 进程列表格式: "进程名 (PID: 1234)"
            process_name = process_text.split(" (")[0]
            # 提取PID
            try:
                pid_str = process_text.split("(PID: ")[1].split(")")[0]
                pid = int(pid_str)
            except (IndexError, ValueError):
                pass
        else:
            # 自定义添加的项目格式，直接作为进程名处理
            process_name = process_text
            
        if not process_name:
            return
            
        # 查找进程ID
        import psutil
        target_pids = []
        if pid is not None:
            # 如果有明确的PID，只针对该PID
            target_pids = [pid]
        else:
            # 对于窗口项目，仍然查找所有同名进程（在实际应用中可以优化）
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'] == process_name:
                        target_pids.append(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                
        if not target_pids:
            return
            
        # 注入AffinityUnhide.dll取消反截屏保护
        dll_injector = DLLInjector()
        success_count = 0
        processed_pids = set()  # 防止重复注入
        
        for target_pid in target_pids:
            if target_pid not in processed_pids:
                success = dll_injector.inject_affinity_unhide_dll(target_pid)
                if success:
                    success_count += 1
                    processed_pids.add(target_pid)
        
        if success_count > 0:
            # 更新状态（在主线程中执行）
            self.after(0, lambda: self.status_label.configure(text=f"已向 {success_count} 个进程注入AffinityUnhide.dll取消反截屏保护"))
            
        # 如果启用了子进程注入，且不是窗口项目，则也对子进程执行相同操作
        if not is_window_item and hasattr(self, 'child_process_injection_var') and self.child_process_injection_var.get():
            child_processes = self._get_child_processes(process_name)
            processed_pids = set()  # 防止重复注入
            
            for child_process_name in child_processes:
                for child_proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if child_proc.info['name'] == child_process_name and child_proc.info['pid'] not in processed_pids:
                            child_pid = child_proc.info['pid']
                            dll_injector.inject_affinity_unhide_dll(child_pid)
                            processed_pids.add(child_pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass

                
        if not target_pids:
            return
            
        # 注入AffinityUnhide.dll取消反截屏保护
        dll_injector = DLLInjector()
        success_count = 0
        for target_pid in target_pids:
            success = dll_injector.inject_affinity_unhide_dll(target_pid)
            if success:
                success_count += 1
        
        if success_count > 0:
            # 更新状态（在主线程中执行）
            self.after(0, lambda: self.status_label.configure(text=f"已向 {success_count} 个进程注入AffinityUnhide.dll取消反截屏保护"))
            
        # 如果启用了子进程注入，且不是窗口项目，则也对子进程执行相同操作
        if not is_window_item and hasattr(self, 'child_process_injection_var') and self.child_process_injection_var.get():
            child_processes = self._get_child_processes(process_name)
            for child_process_name in child_processes:
                for child_proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if child_proc.info['name'] == child_process_name:
                            child_pid = child_proc.info['pid']
                            dll_injector.inject_affinity_unhide_dll(child_pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass

        # 注入AffinityUnhide.dll取消反截屏保护
        dll_injector = DLLInjector()
        success_count = 0
        for target_pid in target_pids:
            success = dll_injector.inject_affinity_unhide_dll(target_pid)
            if success:
                success_count += 1
        
        if success_count > 0:
            # 更新状态（在主线程中执行）
            self.after(0, lambda: self.status_label.configure(text=f"已向 {success_count} 个进程注入AffinityUnhide.dll取消反截屏保护"))
            
        # 如果启用了子进程注入，且不是窗口项目，则也对子进程执行相同操作
        if not is_window_item and hasattr(self, 'child_process_injection_var') and self.child_process_injection_var.get():
            child_processes = self._get_child_processes(process_name)
            for child_process_name in child_processes:
                for child_proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if child_proc.info['name'] == child_process_name:
                            child_pid = child_proc.info['pid']
                            dll_injector.inject_affinity_unhide_dll(child_pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass

    def toggle_item_status(self, listbox, index, mode_name):
        """切换项目状态（开启/关闭）"""
        # 获取项目文本
        item_text = listbox.get(index)
        
        # 检查项目当前是否为开启状态（是否有状态指示器）
        is_enabled = not item_text.startswith("● ") or (item_text.startswith("● ") and getattr(listbox, f'item_{index}_status', 'enabled') == 'enabled')
        
        if item_text.startswith("● "):
            # 移除现有的状态指示器
            clean_text = item_text[2:]
        else:
            clean_text = item_text
            
        listbox.delete(index)
            
        if is_enabled:
            # 切换到关闭状态（红点）
            new_text = "● " + clean_text
            listbox.insert(index, new_text)
            setattr(listbox, f'item_{index}_status', 'disabled')
            self.status_label.configure(text=f"'{clean_text}' 在 {mode_name} 中已关闭")
            
            # 在后台线程中取消进程的反截屏保护
            threading.Thread(target=self._unhide_process_thread, args=(clean_text,), daemon=True).start()
        else:
            # 切换到开启状态（绿点）
            new_text = "● " + clean_text
            listbox.insert(index, new_text)
            setattr(listbox, f'item_{index}_status', 'enabled')
            self.status_label.configure(text=f"'{clean_text}' 在 {mode_name} 中已开启")
            
            # 在后台线程中重新应用反截屏保护
            threading.Thread(target=self._rehide_process_thread, args=(clean_text, listbox), daemon=True).start()
            
        # 重新应用反截屏保护
        if listbox == self.mode1_listbox:
            self.apply_anti_screenshot_protection(self.mode1_listbox)
        elif listbox == self.mode2_listbox:
            self.apply_anti_screenshot_protection(self.mode2_listbox)
        # 自动保存配置
        self.save_data(show_status=False)
        
    def _unhide_process(self, process_text):
        """取消进程的反截屏保护"""
        # 在后台线程中执行耗时操作
        threading.Thread(target=self._unhide_process_thread, args=(process_text,), daemon=True).start()
        
    def _unhide_process_thread(self, process_text):
        """在后台线程中取消进程的反截屏保护"""
        # 提取进程名
        process_name = None
        if " [" in process_text and process_text.endswith("]"):
            # 窗口列表格式: "窗口标题 [进程名]"
            process_name = process_text.split(" [")[-1][:-1]
        elif " (" in process_text and process_text.endswith(")"):
            # 进程列表格式: "进程名 (PID: 1234)"
            process_name = process_text.split(" (")[0]
        else:
            # 自定义添加的项目格式，直接作为进程名处理
            process_name = process_text
            
        if not process_name:
            return
            
        # 查找进程ID
        import psutil
        target_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] == process_name:
                    target_pid = proc.info['pid']
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        if not target_pid:
            return
            
        # 注入AffinityUnhide.dll取消反截屏保护
        dll_injector = DLLInjector()
        success = dll_injector.inject_affinity_unhide_dll(target_pid)
        if success:
            # 更新状态（在主线程中执行）
            self.after(0, lambda: self.status_label.configure(text=f"已向进程 {process_name} 注入AffinityUnhide.dll取消反截屏保护"))
            
        # 如果启用了子进程注入，则也对子进程执行相同操作
        if hasattr(self, 'child_process_injection_var') and self.child_process_injection_var.get():
            child_processes = self._get_child_processes(process_name)
            for child_process_name in child_processes:
                for child_proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if child_proc.info['name'] == child_process_name:
                            child_pid = child_proc.info['pid']
                            dll_injector.inject_affinity_unhide_dll(child_pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass

    def _rehide_process(self, process_text, listbox):
        """重新应用进程的反截屏保护"""
        # 在后台线程中执行耗时操作
        threading.Thread(target=self._rehide_process_thread, args=(process_text, listbox), daemon=True).start()
        
    def _rehide_process_thread(self, process_text, listbox):
        """在后台线程中重新应用进程的反截屏保护"""
        # 提取进程名
        process_name = None
        if " [" in process_text and process_text.endswith("]"):
            # 窗口列表格式: "窗口标题 [进程名]"
            process_name = process_text.split(" [")[-1][:-1]
        elif " (" in process_text and process_text.endswith(")"):
            # 进程列表格式: "进程名 (PID: 1234)"
            process_name = process_text.split(" (")[0]
        else:
            # 自定义添加的项目格式，直接作为进程名处理
            process_name = process_text
            
        if not process_name:
            return
            
        # 查找进程ID
        import psutil
        target_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] == process_name:
                    target_pid = proc.info['pid']
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        if not target_pid:
            return
            
        # 确定当前是哪个列表（模式一还是模式二）
        is_mode1 = (listbox == self.mode1_listbox)
            
        # 注入对应的DLL重新应用反截屏保护
        dll_injector = DLLInjector()
        if is_mode1:
            # 模式一使用AffinityTrans.dll
            success = dll_injector.inject_affinity_trans_dll(target_pid)
            if success:
                # 更新状态（在主线程中执行）
                self.after(0, lambda: self.status_label.configure(text=f"已向进程 {process_name} 注入AffinityTrans.dll重新应用反截屏保护"))
        else:
            # 模式二使用AffinityHide.dll
            success = dll_injector.inject_affinity_hide_dll(target_pid)
            if success:
                # 更新状态（在主线程中执行）
                self.after(0, lambda: self.status_label.configure(text=f"已向进程 {process_name} 注入AffinityHide.dll重新应用反截屏保护"))
                
        # 如果启用了子进程注入，则也对子进程执行相同操作
        if hasattr(self, 'child_process_injection_var') and self.child_process_injection_var.get():
            child_processes = self._get_child_processes(process_name)
            for child_process_name in child_processes:
                for child_proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if child_proc.info['name'] == child_process_name:
                            child_pid = child_proc.info['pid']
                            
                            # 根据模式注入对应的DLL
                            if is_mode1:
                                dll_injector.inject_affinity_trans_dll(child_pid)
                            else:
                                dll_injector.inject_affinity_hide_dll(child_pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass

    def add_to_current_mode_from_list(self, listbox):
        """将列表中的项目添加到当前模式"""
        selected_indices = listbox.curselection()
        added_count = 0
        
        for index in selected_indices:
            item_text = listbox.get(index)
            
            # 确定目标列表框
            if self.current_mode == 1:
                target_listbox = self.mode1_listbox
                target_name = "模式一"
            elif self.current_mode == 2:
                target_listbox = self.mode2_listbox
                target_name = "模式二"
            
            # 检查是否已存在相同项目（去除状态指示器前缀后比较）
            exists = False
            for i in range(target_listbox.size()):
                existing_item = target_listbox.get(i)
                # 去除状态指示器前缀进行比较
                clean_existing = existing_item[2:] if existing_item.startswith("● ") else existing_item
                if clean_existing == item_text:
                    exists = True
                    break
            
            # 如果不存在，则检查是否已经在另一个列表中
            if not exists:
                # 确定另一个列表框
                other_listbox = self.mode2_listbox if target_listbox == self.mode1_listbox else self.mode1_listbox
                other_mode_name = "模式二" if target_name == "模式一" else "模式一"
                already_exists_in_other = False
                
                for i in range(other_listbox.size()):
                    existing_item = other_listbox.get(i)
                    clean_existing = existing_item[2:] if existing_item.startswith("● ") else existing_item
                    if clean_existing == item_text:
                        already_exists_in_other = True
                        break
                        
                if already_exists_in_other:
                    self.status_label.configure(text=f"项目 '{item_text}' 已存在于 {other_mode_name} 中，无法同时添加到两个列表")
                    continue  # 跳过这个项目
            
            # 如果不存在，则添加
            if not exists:
                target_index = target_listbox.size()
                target_listbox.insert(target_index, item_text)
                # 设置默认状态为启用
                setattr(target_listbox, f'item_{target_index}_status', 'enabled')
                added_count += 1
                
        if added_count > 0:
            # 应用反截屏保护
            self.apply_anti_screenshot_protection(target_listbox)
            # 自动保存配置
            self.save_data(show_status=False)
            self.status_label.configure(text=f"已向 {target_name} 添加 {added_count} 个项目")
        else:
            self.status_label.configure(text="所选项目已存在于当前模式中或已在另一模式中")
        
    def add_to_current_mode_from_list(self, listbox):
        """将列表中的项目添加到当前模式"""
        selected_indices = listbox.curselection()
        added_count = 0
        
        for index in selected_indices:
            item_text = listbox.get(index)
            
            # 确定目标列表框
            if self.current_mode == 1:
                target_listbox = self.mode1_listbox
                target_name = "模式一"
            elif self.current_mode == 2:
                target_listbox = self.mode2_listbox
                target_name = "模式二"
            
            # 检查是否已存在相同项目（去除状态指示器前缀后比较）
            exists = False
            for i in range(target_listbox.size()):
                existing_item = target_listbox.get(i)
                # 去除状态指示器前缀进行比较
                clean_existing = existing_item[2:] if existing_item.startswith("● ") else existing_item
                if clean_existing == item_text:
                    exists = True
                    break
            
            # 如果不存在，则检查是否已经在另一个列表中
            if not exists:
                # 确定另一个列表框
                other_listbox = self.mode2_listbox if target_listbox == self.mode1_listbox else self.mode1_listbox
                other_mode_name = "模式二" if target_name == "模式一" else "模式一"
                already_exists_in_other = False
                
                for i in range(other_listbox.size()):
                    existing_item = other_listbox.get(i)
                    clean_existing = existing_item[2:] if existing_item.startswith("● ") else existing_item
                    if clean_existing == item_text:
                        already_exists_in_other = True
                        break
                        
                if already_exists_in_other:
                    self.status_label.configure(text=f"项目 '{item_text}' 已存在于 {other_mode_name} 中，无法同时添加到两个列表")
                    continue  # 跳过这个项目
            
            # 如果不存在，则添加
            if not exists:
                target_index = target_listbox.size()
                target_listbox.insert(target_index, item_text)
                # 设置默认状态为启用
                setattr(target_listbox, f'item_{target_index}_status', 'enabled')
                added_count += 1
                
        if added_count > 0:
            # 在后台线程中应用反截屏保护
            threading.Thread(target=self._apply_anti_screenshot_protection_thread, args=(target_listbox,), daemon=True).start()
            # 自动保存配置
            self.save_data(show_status=False)
            self.status_label.configure(text=f"已向 {target_name} 添加 {added_count} 个项目")
        else:
            self.status_label.configure(text="所选项目已存在于当前模式中或已在另一模式中")
    def add_to_current_mode(self):
        """将选中的窗口或进程添加到当前模式"""
        # 从窗口列表获取选中项
        window_selected = [self.window_listbox.get(i) for i in self.window_listbox.curselection()]
        # 从进程列表获取选中项
        process_selected = [self.process_listbox.get(i) for i in self.process_listbox.curselection()]
        
        # 确定目标列表框
        if self.current_mode == 1:
            target_listbox = self.mode1_listbox
            target_name = "模式一"
        elif self.current_mode == 2:
            target_listbox = self.mode2_listbox
            target_name = "模式二"
            
        # 添加到当前模式
        added_count = 0
        for item_text in window_selected + process_selected:
            # 检查是否已存在相同项目（去除状态指示器前缀后比较）
            exists = False
            for i in range(target_listbox.size()):
                existing_item = target_listbox.get(i)
                # 去除状态指示器前缀进行比较
                clean_existing = existing_item[2:] if existing_item.startswith("● ") else existing_item
                if clean_existing == item_text:
                    exists = True
                    break
            
            # 如果不存在，则检查是否已经在另一个列表中
            if not exists:
                # 确定另一个列表框
                other_listbox = self.mode2_listbox if target_listbox == self.mode1_listbox else self.mode1_listbox
                other_mode_name = "模式二" if target_name == "模式一" else "模式一"
                already_exists_in_other = False
                
                for i in range(other_listbox.size()):
                    existing_item = other_listbox.get(i)
                    clean_existing = existing_item[2:] if existing_item.startswith("● ") else existing_item
                    if clean_existing == item_text:
                        already_exists_in_other = True
                        break
                        
                if already_exists_in_other:
                    self.status_label.configure(text=f"项目 '{item_text}' 已存在于 {other_mode_name} 中，无法同时添加到两个列表")
                    continue  # 跳过这个项目
            
            # 如果不存在，则添加
            if not exists:
                target_index = target_listbox.size()
                target_listbox.insert(target_index, item_text)
                # 设置默认状态为启用
                setattr(target_listbox, f'item_{target_index}_status', 'enabled')
                added_count += 1
                
        if added_count > 0:
            # 在后台线程中应用反截屏保护
            threading.Thread(target=self._apply_anti_screenshot_protection_thread, args=(target_listbox,), daemon=True).start()
            # 自动保存配置
            self.save_data(show_status=False)
            self.status_label.configure(text=f"已向 {target_name} 添加 {added_count} 个项目")
        else:
            self.status_label.configure(text="所选项目已存在于当前模式中或已在另一模式中")
    def toggle_mode(self):
        """切换模式"""
        if self.current_mode == 1:
            self.current_mode = 2
            self.toggle_button.configure(text="当前模式: 模式二")
        else:
            self.current_mode = 1
            self.toggle_button.configure(text="当前模式: 模式一")
        # 自动保存配置
        self.save_data(show_status=False)

    def change_theme(self):
        """更改主题"""
        theme = self.theme_var.get()
        ctk.set_appearance_mode(theme)
        
        # 根据主题更改列表框颜色
        if theme == "Dark":
            # 深色主题：黑底白字
            listbox_bg = "black"
            listbox_fg = "white"
        else:
            # 浅色主题：白底黑字
            listbox_bg = "white"
            listbox_fg = "black"
            
        # 更新所有列表框的颜色
        for listbox in [self.mode1_listbox, self.mode2_listbox, self.window_listbox, self.process_listbox]:
            listbox.config(bg=listbox_bg, fg=listbox_fg)
        # 自动保存配置
        self.save_data(show_status=False)
        
    def toggle_anti_screenshot(self):
        """切换程序自身的反截屏保护"""
        try:
            # 只有在启用开关时才执行反截屏保护操作
            if self.anti_screenshot_switch_var.get():
                # 直接调用DisplayAffinityManager设置程序自身的反截屏保护
                self.display_affinity_manager.set_anti_screenshot_enabled(True)
                self.display_affinity_manager.start_affinity_thread()
                self.status_label.configure(text="已启用程序自身反截屏保护")
            else:
                # 关闭反截屏保护
                self.display_affinity_manager.set_anti_screenshot_enabled(False)
                self.display_affinity_manager.stop_affinity_thread()
                self.status_label.configure(text="已禁用程序自身反截屏保护")
            # 自动保存配置
            self.save_data(show_status=False)
        except Exception as e:
            self.status_label.configure(text=f"切换反截屏保护时出错: {str(e)}")

    def refresh_processes_list(self):
        """刷新进程列表"""
        if self.process_loading:
            return
            
        self.process_loading = True
        self.progress_bar.pack(side="right", padx=5, pady=5)  # 显示进度条
        self.status_label.configure(text="正在获取进程列表...")
        self.refresh_processes_btn.configure(state="disabled")
        
        # 创建并启动进程加载线程
        def load_processes():
            loader = ProcessLoader(self.on_processes_loaded)
            loader.run()
            
        thread = threading.Thread(target=load_processes)
        thread.daemon = True
        thread.start()
        
    def on_processes_loaded(self, processes):
        """进程加载完成回调"""
        # 在主线程中更新UI
        self.after(0, lambda: self._update_process_list(processes))
        
    def _update_process_list(self, processes):
        self.process_listbox.delete(0, tk.END)
        
        # 逐个添加进程到列表（懒加载）
        for display_text, process_name in processes:
            self.process_listbox.insert(tk.END, display_text)
            
        self.status_label.configure(text=f"已刷新进程列表，共找到 {len(processes)} 个不同的进程")
        self.progress_bar.pack_forget()  # 隐藏进度条
        self.refresh_processes_btn.configure(state="normal")
        self.process_loading = False
        
    def refresh_windows_list(self):
        """刷新窗口列表"""
        if self.window_loading:
            return
            
        self.window_loading = True
        self.progress_bar.pack(side="right", padx=5, pady=5)  # 显示进度条
        self.status_label.configure(text="正在获取窗口列表...")
        self.refresh_windows_btn.configure(state="disabled")
        
        # 创建并启动窗口加载线程
        def load_windows():
            loader = WindowLoader(self.on_windows_loaded)
            loader.run()
            
        thread = threading.Thread(target=load_windows)
        thread.daemon = True
        thread.start()
        
    def on_windows_loaded(self, windows):
        """窗口加载完成回调"""
        # 在主线程中更新UI
        self.after(0, lambda: self._update_window_list(windows))
        
    def _update_window_list(self, windows):
        self.window_listbox.delete(0, tk.END)
        
        # 逐个添加窗口到列表（懒加载）
        for display_text, process_name in windows:
            self.window_listbox.insert(tk.END, display_text)
            
        self.status_label.configure(text=f"已刷新窗口列表，共找到 {len(windows)} 个不同的窗口")
        self.progress_bar.pack_forget()  # 隐藏进度条
        self.refresh_windows_btn.configure(state="normal")
        self.window_loading = False
        
    def refresh_current_tab(self):
        """刷新当前标签页"""
        current_tab = self.tab_view.get()
        if current_tab == "控制":
            self.refresh_processes_list()
            self.refresh_windows_list()
        elif current_tab == "设置":
            pass
        elif current_tab == "关于":
            pass
            
    def auto_refresh(self):
        """自动刷新"""
        if self.show_lists_refresh:
            self.refresh_processes_list()
            self.refresh_windows_list()
            self.show_lists_refresh = False
            
        # 安排下一次自动刷新
        self.after(10000, self.auto_refresh)
        
    def initial_refresh(self):
        """初始化刷新"""
        # 尝试加载配置文件
        self.load_data()
        
        # 刷新进程和窗口列表
        self.refresh_processes_list()
        self.refresh_windows_list()
        self.show_lists_refresh = False

# 添加主程序入口点
if __name__ == "__main__":
    # 避免在子进程中创建GUI
    import sys
    if len(sys.argv) > 1:
        # 这是一个子进程调用，不要创建GUI
        sys.exit(0)
        
    app = MainWindow()
    app.mainloop()
import sys
import os
import json
try:
    import psutil
    import win32gui
    import win32process
except ImportError as e:
    print(f"导入模块失败: {e}")
    print("请安装所需的依赖包:")
    print("pip install psutil pywin32")
    sys.exit(1)

import customtkinter as ctk
from tkinter import messagebox, simpledialog
import tkinter as tk
from tkinter import ttk
import threading
import time
import queue

# 引入 DisplayAffinityManager
from display_affinity_manager import DisplayAffinityManager
# 引入 DLLInjector
from dll_injector import DLLInjector

# 设置customtkinter的外观模式和主题
ctk.set_appearance_mode("Light")  # 默认设置为浅色模式以符合用户偏好
ctk.set_default_color_theme("blue")  # 可选: "blue", "green", "dark-blue"


class ProcessLoader:
    """进程列表加载线程"""
    def __init__(self, callback):
        self.callback = callback
        self.process_dict = {}
        
    def run(self):
        try:
            # 收集所有进程信息
            for proc in psutil.process_iter():
                try:
                    pid = proc.pid
                    name = proc.name()
                    
                    try:
                        ppid = proc.ppid()
                    except:
                        ppid = 0
                    
                    if name not in self.process_dict:
                        self.process_dict[name] = {
                            'pids': [pid],
                            'ppids': [ppid],
                            'count': 1
                        }
                    else:
                        self.process_dict[name]['pids'].append(pid)
                        self.process_dict[name]['ppids'].append(ppid)
                        self.process_dict[name]['count'] += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # 格式化输出
            processes = []
            for name, info in self.process_dict.items():
                if info['count'] == 1:
                    process_info = f"{name} (PID: {info['pids'][0]})"
                else:
                    process_info = f"{name} ({info['count']} 个实例)"
                processes.append((process_info, name))
                
            # 调用回调函数传递结果
            self.callback(sorted(processes, key=lambda x: x[0]))
        except Exception as e:
            self.callback([])


class WindowLoader:
    """窗口列表加载线程"""
    def __init__(self, callback):
        self.callback = callback
        
    def run(self):
        windows = []
        
        def enum_windows_callback(hwnd, windows_list):
            if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
                try:
                    window_text = win32gui.GetWindowText(hwnd)
                    _, pid = win32process.GetWindowThreadProcessId(hwnd)
                    process_name = "unknown"
                    try:
                        process = psutil.Process(pid)
                        process_name = process.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    # 使用标准格式: "窗口标题 [进程名]"
                    window_info = f"{window_text} [{process_name}]"
                    windows_list.append((window_info, process_name))
                except Exception:
                    pass
            return True
            
        try:
            win32gui.EnumWindows(enum_windows_callback, windows)
            self.callback(sorted(windows, key=lambda x: x[0]))
        except Exception as e:
            self.callback([])


class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # 配置窗口
        self.title("反截屏管理程序")
        self.geometry("900x700")  # 保持原窗口尺寸
        
        # 初始化 DisplayAffinityManager (保留用于兼容性)
        self.display_affinity_manager = DisplayAffinityManager()
        # 使用DLL注入方式替代原有的反截屏功能
        # self.display_affinity_manager.set_anti_screenshot_enabled(True)
        # self.display_affinity_manager.get_current_process_id()  # 确保进程ID是最新的
        # self.display_affinity_manager.start_affinity_thread()
        
        # 添加全屏反截屏状态跟踪
        self.fullscreen_anti_screenshot_enabled = False
        
        # 防止反截屏保护重复应用的标志
        self._anti_screenshot_applying = False
        
        # 创建UI组件管理器
        self.ui_components = UIComponents(self)
        
        # 创建主布局
        self.ui_components.create_main_layout()
        
        # 初始化组件
        self.init_components()
        
        # 初始化加载器
        self.process_loader = None
        self.window_loader = None
        self.process_loading = False
        self.window_loading = False
        
        # 初始化定时器
        self.after(10000, self.auto_refresh)  # 每10秒自动刷新一次
        
        # 窗口完全初始化后刷新列表
        self.show_lists_refresh = True
        self.after(100, self.initial_refresh)

        
    def init_components(self):
        """初始化所有组件"""
        # 创建左侧模式一列表
        self.ui_components.create_mode1_section()
        
        # 创建左侧模式二列表
        self.ui_components.create_mode2_section()
        
        # 创建控制标签页
        self.ui_components.create_control_tab()
        
        # 创建设置标签页
        self.ui_components.create_settings_tab()
        
        # 创建关于标签页
        self.ui_components.create_about_tab()
        
    def _delayed_init_anti_screenshot_protection(self):
        """延迟初始化程序自身的反截屏保护"""
        # 检查设置中反截屏功能是否启用
        if hasattr(self, 'anti_screenshot_switch_var') and self.anti_screenshot_switch_var.get():
            try:
                # 使用DisplayAffinityManager为程序自身启用反截屏保护
                self.display_affinity_manager.set_anti_screenshot_enabled(True)
                self.display_affinity_manager.start_affinity_thread()
                self.status_label.configure(text="程序启动成功，已启用自身反截屏保护")
            except Exception as e:
                self.status_label.configure(text=f"启用反截屏保护时出错: {str(e)}")
        else:
            # 如果反截屏功能关闭，则不执行任何操作
            self.status_label.configure(text="程序启动成功，自身反截屏保护已禁用")
        
    def create_mode1_section(self):
        """创建模式一列表区域"""
        self.mode1_frame = ctk.CTkFrame(self.left_frame)
        self.mode1_frame.pack(fill="both", expand=True, padx=5, pady=2)
        
        # 模式一标题
        mode1_label = ctk.CTkLabel(self.mode1_frame, text="模式一", font=ctk.CTkFont(size=14, weight="bold"))
        mode1_label.pack(pady=(3, 0))
        
        # 模式一列表框
        self.mode1_listbox_frame = ctk.CTkFrame(self.mode1_frame)
        self.mode1_listbox_frame.pack(fill="both", expand=True, padx=5, pady=3)
        
        self.mode1_listbox = tk.Listbox(
            self.mode1_listbox_frame, 
            bg="white", 
            fg="black",
            selectbackground="#3B8ED0",
            selectforeground="white"
        )
        self.mode1_listbox.pack(side="left", fill="both", expand=True)
        
        # 添加滚动条
        mode1_scrollbar = ctk.CTkScrollbar(self.mode1_listbox_frame, command=self.mode1_listbox.yview)
        mode1_scrollbar.pack(side="right", fill="y")
        self.mode1_listbox.configure(yscrollcommand=mode1_scrollbar.set)
        
        # 绑定右键菜单
        self.mode1_listbox.bind("<Button-3>", lambda e: self.show_mode_list_context_menu(e, self.mode1_listbox, "模式一"))
        
        # 模式一按钮框架
        mode1_buttons_frame = ctk.CTkFrame(self.mode1_frame)
        mode1_buttons_frame.pack(fill="x", padx=5, pady=(0, 3))
        
        self.mode1_add_btn = ctk.CTkButton(mode1_buttons_frame, text="添加", width=50, height=25, 
                                          font=ctk.CTkFont(size=14), command=lambda: self.add_custom_item(self.mode1_listbox, "模式一"))
        self.mode1_add_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)
        
        self.mode1_remove_btn = ctk.CTkButton(mode1_buttons_frame, text="移除", width=50, height=25,
                                             font=ctk.CTkFont(size=14), command=lambda: self.remove_selected_item(self.mode1_listbox, "模式一"))
        self.mode1_remove_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)
        
        self.mode1_clear_btn = ctk.CTkButton(mode1_buttons_frame, text="清空", width=50, height=25,
                                            font=ctk.CTkFont(size=14), command=lambda: self.clear_list(self.mode1_listbox, "模式一"))
        self.mode1_clear_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)
        
    def create_mode2_section(self):
        """创建模式二列表区域"""
        self.mode2_frame = ctk.CTkFrame(self.left_frame)
        self.mode2_frame.pack(fill="both", expand=True, padx=5, pady=2)
        
        # 模式二标题
        mode2_label = ctk.CTkLabel(self.mode2_frame, text="模式二", font=ctk.CTkFont(size=14, weight="bold"))
        mode2_label.pack(pady=(3, 0))
        
        # 模式二列表框
        self.mode2_listbox_frame = ctk.CTkFrame(self.mode2_frame)
        self.mode2_listbox_frame.pack(fill="both", expand=True, padx=5, pady=3)
        
        self.mode2_listbox = tk.Listbox(
            self.mode2_listbox_frame, 
            bg="white", 
            fg="black",
            selectbackground="#3B8ED0",
            selectforeground="white"
        )
        self.mode2_listbox.pack(side="left", fill="both", expand=True)
        
        # 添加滚动条
        mode2_scrollbar = ctk.CTkScrollbar(self.mode2_listbox_frame, command=self.mode2_listbox.yview)
        mode2_scrollbar.pack(side="right", fill="y")
        self.mode2_listbox.configure(yscrollcommand=mode2_scrollbar.set)
        
        # 绑定右键菜单
        self.mode2_listbox.bind("<Button-3>", lambda e: self.show_mode_list_context_menu(e, self.mode2_listbox, "模式二"))
        
        # 模式二按钮框架
        mode2_buttons_frame = ctk.CTkFrame(self.mode2_frame)
        mode2_buttons_frame.pack(fill="x", padx=5, pady=(0, 3))
        
        self.mode2_add_btn = ctk.CTkButton(mode2_buttons_frame, text="添加", width=50, height=25,
                                          font=ctk.CTkFont(size=14), command=lambda: self.add_custom_item(self.mode2_listbox, "模式二"))
        self.mode2_add_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)
        
        self.mode2_remove_btn = ctk.CTkButton(mode2_buttons_frame, text="移除", width=50, height=25,
                                             font=ctk.CTkFont(size=14), command=lambda: self.remove_selected_item(self.mode2_listbox, "模式二"))
        self.mode2_remove_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)
        
        self.mode2_clear_btn = ctk.CTkButton(mode2_buttons_frame, text="清空", width=50, height=25,
                                            font=ctk.CTkFont(size=14), command=lambda: self.clear_list(self.mode2_listbox, "模式二"))
        self.mode2_clear_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)

    def create_control_tab(self):
        """创建控制标签页"""
        # 创建按钮框架，将模式切换按钮和刷新按钮放在同一行
        button_frame = ctk.CTkFrame(self.control_tab)
        button_frame.pack(pady=5, padx=10, fill="x")
        
        # 创建切换按钮
        self.current_mode = 1  # 1表示模式一，2表示模式二
        self.toggle_button = ctk.CTkButton(button_frame, text="当前模式: 模式一", 
                                          command=self.toggle_mode, 
                                          font=ctk.CTkFont(size=12, weight="bold"),
                                          width=150, height=30)
        self.toggle_button.pack(side="left", padx=(0, 10))
        
        # 添加刷新按钮
        self.refresh_windows_btn = ctk.CTkButton(button_frame, text="刷新窗口列表", width=120, command=self.refresh_windows_list)
        self.refresh_windows_btn.pack(side="left", padx=(0, 5))
        
        self.refresh_processes_btn = ctk.CTkButton(button_frame, text="刷新进程列表", width=120, command=self.refresh_processes_list)
        self.refresh_processes_btn.pack(side="left", padx=(0, 5))
        
        # 创建窗口列表区域
        window_frame = ctk.CTkFrame(self.control_tab)
        window_frame.pack(fill="both", expand=True, padx=10, pady=3)
        
        window_label = ctk.CTkLabel(window_frame, text="窗口列表 (双击添加)", font=ctk.CTkFont(size=12, weight="bold"))
        window_label.pack(pady=(3, 0))
        
        # 窗口列表框
        self.window_listbox_frame = ctk.CTkFrame(window_frame)
        self.window_listbox_frame.pack(fill="both", expand=True, padx=5, pady=3)
        
        self.window_listbox = tk.Listbox(
            self.window_listbox_frame,
            bg="white",
            fg="black",
            selectmode=tk.EXTENDED,
            selectbackground="#3B8ED0",
            selectforeground="white"
        )
        self.window_listbox.pack(side="left", fill="both", expand=True)
        self.window_listbox.bind("<Double-Button-1>", lambda e: self.add_to_current_mode_from_list(self.window_listbox))
        
        # 添加滚动条
        window_scrollbar = ctk.CTkScrollbar(self.window_listbox_frame, command=self.window_listbox.yview)
        window_scrollbar.pack(side="right", fill="y")
        self.window_listbox.configure(yscrollcommand=window_scrollbar.set)
        
        # 创建进程列表区域
        process_frame = ctk.CTkFrame(self.control_tab)
        process_frame.pack(fill="both", expand=True, padx=10, pady=3)
        
        process_label = ctk.CTkLabel(process_frame, text="进程列表 (双击添加)", font=ctk.CTkFont(size=12, weight="bold"))
        process_label.pack(pady=(3, 0))
        
        # 进程列表框
        self.process_listbox_frame = ctk.CTkFrame(process_frame)
        self.process_listbox_frame.pack(fill="both", expand=True, padx=5, pady=3)
        
        self.process_listbox = tk.Listbox(
            self.process_listbox_frame,
            bg="white",
            fg="black",
            selectmode=tk.EXTENDED,
            selectbackground="#3B8ED0",
            selectforeground="white"
        )
        self.process_listbox.pack(side="left", fill="both", expand=True)
        self.process_listbox.bind("<Double-Button-1>", lambda e: self.add_to_current_mode_from_list(self.process_listbox))
        
        # 添加滚动条
        process_scrollbar = ctk.CTkScrollbar(self.process_listbox_frame, command=self.process_listbox.yview)
        process_scrollbar.pack(side="right", fill="y")
        self.process_listbox.configure(yscrollcommand=process_scrollbar.set)
        
        # 添加说明标签
        instruction_label = ctk.CTkLabel(self.control_tab, text="说明：双击列表项可添加到当前模式", 
                                        text_color="blue", font=ctk.CTkFont(size=12))
        instruction_label.pack(pady=3)
        
    def create_settings_tab(self):
        """创建设置标签页"""
        settings_label = ctk.CTkLabel(self.settings_tab, text="程序设置", font=ctk.CTkFont(size=16, weight="bold"))
        settings_label.pack(pady=5)
        
        # 主题设置
        theme_label = ctk.CTkLabel(self.settings_tab, text="主题设置", font=ctk.CTkFont(size=14, weight="bold"))
        theme_label.pack(pady=(5, 2), anchor="w", padx=10)
        
        # 主题切换框架
        theme_frame = ctk.CTkFrame(self.settings_tab)
        theme_frame.pack(fill="x", padx=10, pady=1)
        
        theme_label = ctk.CTkLabel(theme_frame, text="选择主题:")
        theme_label.pack(side="left", padx=10, pady=1)
        
        # 主题选项
        self.theme_var = ctk.StringVar(value="Light")  # 默认主题
        light_radio = ctk.CTkRadioButton(theme_frame, text="浅色主题", variable=self.theme_var, value="Light", command=self.change_theme)
        light_radio.pack(side="left", padx=10, pady=1)