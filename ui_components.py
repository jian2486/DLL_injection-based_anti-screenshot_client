import customtkinter as ctk
import tkinter as tk
from tkinter import simpledialog
import psutil


class UIComponents:
    """界面组件类，负责创建和管理UI元素"""
    
    def __init__(self, main_window):
        """
        初始化UI组件
        
        Args:
            main_window: 主窗口实例
        """
        self.main_window = main_window
        
    def create_main_layout(self):
        """创建主布局框架"""
        # 创建主框架
        self.main_frame = ctk.CTkFrame(self.main_window, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # 创建状态栏
        self.status_frame = ctk.CTkFrame(self.main_frame)
        self.status_frame.pack(fill="x", side="bottom", padx=5, pady=5)
        
        self.main_window.status_label = ctk.CTkLabel(self.status_frame, text="就绪", anchor="w")
        self.main_window.status_label.pack(side="left", padx=5, pady=5, fill="x", expand=True)
        
        # 创建进度条（初始隐藏）
        self.main_window.progress_bar = ctk.CTkProgressBar(self.status_frame)
        self.main_window.progress_bar.pack(side="right", padx=5, pady=5)
        self.main_window.progress_bar.set(0)
        self.main_window.progress_bar.pack_forget()  # 初始隐藏
        
        # 创建主内容框架
        self.content_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # 创建水平分割框架
        self.split_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.split_frame.pack(fill="both", expand=True)
        
        # 创建左侧区域（固定宽度200像素）
        self.main_window.left_frame = ctk.CTkFrame(self.split_frame, width=200, fg_color="transparent")
        self.main_window.left_frame.pack(side="left", fill="y", padx=(0, 5))
        self.main_window.left_frame.pack_propagate(False)  # 保持固定宽度
        
        # 创建右侧主控区
        self.main_window.right_frame = ctk.CTkFrame(self.split_frame, fg_color="transparent")
        self.main_window.right_frame.pack(side="right", fill="both", expand=True)
        
        # 创建标签页视图
        self.main_window.tab_view = ctk.CTkTabview(self.main_window.right_frame)
        self.main_window.tab_view.pack(fill="both", expand=True, padx=5, pady=5)
        
        # 添加标签页
        self.main_window.control_tab = self.main_window.tab_view.add("控制")
        self.main_window.settings_tab = self.main_window.tab_view.add("设置")
        self.main_window.about_tab = self.main_window.tab_view.add("关于")
        
    def create_mode1_section(self):
        """创建模式一列表区域"""
        self.main_window.mode1_frame = ctk.CTkFrame(self.main_window.left_frame)
        self.main_window.mode1_frame.pack(fill="both", expand=True, padx=5, pady=2)
        
        # 模式一标题
        mode1_label = ctk.CTkLabel(self.main_window.mode1_frame, text="模式一", font=ctk.CTkFont(size=14, weight="bold"))
        mode1_label.pack(pady=(3, 0))
        
        # 模式一列表框
        self.main_window.mode1_listbox_frame = ctk.CTkFrame(self.main_window.mode1_frame)
        self.main_window.mode1_listbox_frame.pack(fill="both", expand=True, padx=5, pady=3)
        
        self.main_window.mode1_listbox = tk.Listbox(
            self.main_window.mode1_listbox_frame, 
            bg="white", 
            fg="black",
            selectbackground="#3B8ED0",
            selectforeground="white"
        )
        self.main_window.mode1_listbox.pack(side="left", fill="both", expand=True)
        
        # 添加滚动条
        mode1_scrollbar = ctk.CTkScrollbar(self.main_window.mode1_listbox_frame, command=self.main_window.mode1_listbox.yview)
        mode1_scrollbar.pack(side="right", fill="y")
        self.main_window.mode1_listbox.configure(yscrollcommand=mode1_scrollbar.set)
        
        # 绑定右键菜单
        self.main_window.mode1_listbox.bind("<Button-3>", lambda e: self.main_window.show_mode_list_context_menu(e, self.main_window.mode1_listbox, "模式一"))
        
        # 模式一按钮框架
        mode1_buttons_frame = ctk.CTkFrame(self.main_window.mode1_frame)
        mode1_buttons_frame.pack(fill="x", padx=5, pady=(0, 3))
        
        self.main_window.mode1_add_btn = ctk.CTkButton(mode1_buttons_frame, text="添加", width=50, height=25, 
                                              font=ctk.CTkFont(size=14), command=lambda: self.main_window.add_custom_item(self.main_window.mode1_listbox, "模式一"))
        self.main_window.mode1_add_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)
        
        self.main_window.mode1_remove_btn = ctk.CTkButton(mode1_buttons_frame, text="移除", width=50, height=25,
                                                 font=ctk.CTkFont(size=14), command=lambda: self.main_window.remove_selected_item(self.main_window.mode1_listbox, "模式一"))
        self.main_window.mode1_remove_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)
        
        self.main_window.mode1_clear_btn = ctk.CTkButton(mode1_buttons_frame, text="清空", width=50, height=25,
                                                font=ctk.CTkFont(size=14), command=lambda: self.main_window.clear_list(self.main_window.mode1_listbox, "模式一"))
        self.main_window.mode1_clear_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)
        
    def create_mode2_section(self):
        """创建模式二列表区域"""
        self.main_window.mode2_frame = ctk.CTkFrame(self.main_window.left_frame)
        self.main_window.mode2_frame.pack(fill="both", expand=True, padx=5, pady=2)
        
        # 模式二标题
        mode2_label = ctk.CTkLabel(self.main_window.mode2_frame, text="模式二", font=ctk.CTkFont(size=14, weight="bold"))
        mode2_label.pack(pady=(3, 0))
        
        # 模式二列表框
        self.main_window.mode2_listbox_frame = ctk.CTkFrame(self.main_window.mode2_frame)
        self.main_window.mode2_listbox_frame.pack(fill="both", expand=True, padx=5, pady=3)
        
        self.main_window.mode2_listbox = tk.Listbox(
            self.main_window.mode2_listbox_frame, 
            bg="white", 
            fg="black",
            selectbackground="#3B8ED0",
            selectforeground="white"
        )
        self.main_window.mode2_listbox.pack(side="left", fill="both", expand=True)
        
        # 添加滚动条
        mode2_scrollbar = ctk.CTkScrollbar(self.main_window.mode2_listbox_frame, command=self.main_window.mode2_listbox.yview)
        mode2_scrollbar.pack(side="right", fill="y")
        self.main_window.mode2_listbox.configure(yscrollcommand=mode2_scrollbar.set)
        
        # 绑定右键菜单
        self.main_window.mode2_listbox.bind("<Button-3>", lambda e: self.main_window.show_mode_list_context_menu(e, self.main_window.mode2_listbox, "模式二"))
        
        # 模式二按钮框架
        mode2_buttons_frame = ctk.CTkFrame(self.main_window.mode2_frame)
        mode2_buttons_frame.pack(fill="x", padx=5, pady=(0, 3))
        
        self.main_window.mode2_add_btn = ctk.CTkButton(mode2_buttons_frame, text="添加", width=50, height=25,
                                              font=ctk.CTkFont(size=14), command=lambda: self.main_window.add_custom_item(self.main_window.mode2_listbox, "模式二"))
        self.main_window.mode2_add_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)
        
        self.main_window.mode2_remove_btn = ctk.CTkButton(mode2_buttons_frame, text="移除", width=50, height=25,
                                                 font=ctk.CTkFont(size=14), command=lambda: self.main_window.remove_selected_item(self.main_window.mode2_listbox, "模式二"))
        self.main_window.mode2_remove_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)
        
        self.main_window.mode2_clear_btn = ctk.CTkButton(mode2_buttons_frame, text="清空", width=50, height=25,
                                                font=ctk.CTkFont(size=14), command=lambda: self.main_window.clear_list(self.main_window.mode2_listbox, "模式二"))
        self.main_window.mode2_clear_btn.pack(side="left", padx=2, pady=2, fill="x", expand=True)

    def create_control_tab(self):
        """创建控制标签页"""
        # 创建按钮框架，将模式切换按钮和刷新按钮放在同一行
        button_frame = ctk.CTkFrame(self.main_window.control_tab)
        button_frame.pack(pady=5, padx=10, fill="x")
        
        # 创建切换按钮
        self.main_window.current_mode = 1  # 1表示模式一，2表示模式二
        self.main_window.toggle_button = ctk.CTkButton(button_frame, text="当前模式: 模式一", 
                                              command=self.main_window.toggle_mode, 
                                              font=ctk.CTkFont(size=12, weight="bold"),
                                              width=150, height=30)
        self.main_window.toggle_button.pack(side="left", padx=(0, 10))
        
        # 添加刷新按钮
        self.main_window.refresh_windows_btn = ctk.CTkButton(button_frame, text="刷新窗口列表", width=120, command=self.main_window.refresh_windows_list)
        self.main_window.refresh_windows_btn.pack(side="left", padx=(0, 5))
        
        self.main_window.refresh_processes_btn = ctk.CTkButton(button_frame, text="刷新进程列表", width=120, command=self.main_window.refresh_processes_list)
        self.main_window.refresh_processes_btn.pack(side="left", padx=(0, 5))
        
        # 创建窗口列表区域
        window_frame = ctk.CTkFrame(self.main_window.control_tab)
        window_frame.pack(fill="both", expand=True, padx=10, pady=3)
        
        window_label = ctk.CTkLabel(window_frame, text="窗口列表 (双击添加)", font=ctk.CTkFont(size=12, weight="bold"))
        window_label.pack(pady=(3, 0))
        
        # 窗口列表框
        self.main_window.window_listbox_frame = ctk.CTkFrame(window_frame)
        self.main_window.window_listbox_frame.pack(fill="both", expand=True, padx=5, pady=3)
        
        self.main_window.window_listbox = tk.Listbox(
            self.main_window.window_listbox_frame,
            bg="white",
            fg="black",
            selectmode=tk.EXTENDED,
            selectbackground="#3B8ED0",
            selectforeground="white"
        )
        self.main_window.window_listbox.pack(side="left", fill="both", expand=True)
        self.main_window.window_listbox.bind("<Double-Button-1>", lambda e: self.main_window.add_to_current_mode_from_list(self.main_window.window_listbox))
        
        # 添加滚动条
        window_scrollbar = ctk.CTkScrollbar(self.main_window.window_listbox_frame, command=self.main_window.window_listbox.yview)
        window_scrollbar.pack(side="right", fill="y")
        self.main_window.window_listbox.configure(yscrollcommand=window_scrollbar.set)
        
        # 创建进程列表区域
        process_frame = ctk.CTkFrame(self.main_window.control_tab)
        process_frame.pack(fill="both", expand=True, padx=10, pady=3)
        
        process_label = ctk.CTkLabel(process_frame, text="进程列表 (双击添加)", font=ctk.CTkFont(size=12, weight="bold"))
        process_label.pack(pady=(3, 0))
        
        # 进程列表框
        self.main_window.process_listbox_frame = ctk.CTkFrame(process_frame)
        self.main_window.process_listbox_frame.pack(fill="both", expand=True, padx=5, pady=3)
        
        self.main_window.process_listbox = tk.Listbox(
            self.main_window.process_listbox_frame,
            bg="white",
            fg="black",
            selectmode=tk.EXTENDED,
            selectbackground="#3B8ED0",
            selectforeground="white"
        )
        self.main_window.process_listbox.pack(side="left", fill="both", expand=True)
        self.main_window.process_listbox.bind("<Double-Button-1>", lambda e: self.main_window.add_to_current_mode_from_list(self.main_window.process_listbox))
        
        # 添加滚动条
        process_scrollbar = ctk.CTkScrollbar(self.main_window.process_listbox_frame, command=self.main_window.process_listbox.yview)
        process_scrollbar.pack(side="right", fill="y")
        self.main_window.process_listbox.configure(yscrollcommand=process_scrollbar.set)
        
        # 添加说明标签
        instruction_label = ctk.CTkLabel(self.main_window.control_tab, text="说明：双击列表项可添加到当前模式", 
                                        text_color="blue", font=ctk.CTkFont(size=12))
        instruction_label.pack(pady=3)
        
    def create_settings_tab(self):
        """创建设置标签页"""
        settings_label = ctk.CTkLabel(self.main_window.settings_tab, text="程序设置", font=ctk.CTkFont(size=16, weight="bold"))
        settings_label.pack(pady=5)
        
        # 主题设置
        theme_label = ctk.CTkLabel(self.main_window.settings_tab, text="主题设置", font=ctk.CTkFont(size=14, weight="bold"))
        theme_label.pack(pady=(5, 2), anchor="w", padx=10)
        
        # 主题切换框架
        theme_frame = ctk.CTkFrame(self.main_window.settings_tab)
        theme_frame.pack(fill="x", padx=10, pady=1)
        
        theme_label = ctk.CTkLabel(theme_frame, text="选择主题:")
        theme_label.pack(side="left", padx=10, pady=1)
        
        # 主题选项
        self.main_window.theme_var = ctk.StringVar(value="Light")  # 默认主题
        light_radio = ctk.CTkRadioButton(theme_frame, text="浅色主题", variable=self.main_window.theme_var, value="Light", command=self.main_window.change_theme)
        light_radio.pack(side="left", padx=10, pady=1)
        
        dark_radio = ctk.CTkRadioButton(theme_frame, text="深色主题", variable=self.main_window.theme_var, value="Dark", command=self.main_window.change_theme)
        dark_radio.pack(side="left", padx=10, pady=1)
        
        # 反截屏设置
        anti_screenshot_label = ctk.CTkLabel(self.main_window.settings_tab, text="反截屏设置", font=ctk.CTkFont(size=14, weight="bold"))
        anti_screenshot_label.pack(pady=(10, 1), anchor="w", padx=10)
        
        # 程序自身反截屏保护说明
        program_anti_screenshot_desc = ctk.CTkLabel(
            self.main_window.settings_tab, 
            text="程序自身反截屏保护（防止本程序界面被截屏）", 
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        program_anti_screenshot_desc.pack(pady=(0, 1), anchor="w", padx=15)
        
        # 程序自身反截屏功能开关
        anti_screenshot_frame = ctk.CTkFrame(self.main_window.settings_tab)
        anti_screenshot_frame.pack(fill="x", padx=10, pady=1)
        
        anti_screenshot_label = ctk.CTkLabel(anti_screenshot_frame, text="启用程序自身反截屏保护:")
        anti_screenshot_label.pack(side="left", padx=10, pady=1)
        
        # 反截屏开关
        self.main_window.anti_screenshot_switch_var = ctk.BooleanVar(value=True)  # 默认启用
        self.main_window.anti_screenshot_switch = ctk.CTkSwitch(
            anti_screenshot_frame, 
            text="", 
            variable=self.main_window.anti_screenshot_switch_var, 
            command=self.main_window.toggle_anti_screenshot
        )
        self.main_window.anti_screenshot_switch.pack(side="left", padx=10, pady=5)
        
        # 子进程注入设置
        child_process_injection_desc = ctk.CTkLabel(
            self.main_window.settings_tab,
            text="子进程注入设置",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        child_process_injection_desc.pack(pady=(10, 2), anchor="w", padx=10)
        
        child_process_injection_note = ctk.CTkLabel(
            self.main_window.settings_tab,
            text="向指定程序的所有子进程注入反截屏保护",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        child_process_injection_note.pack(pady=(0, 2), anchor="w", padx=15)
        
        # 子进程注入开关
        child_process_injection_frame = ctk.CTkFrame(self.main_window.settings_tab)
        child_process_injection_frame.pack(fill="x", padx=10, pady=2)
        
        child_process_injection_label = ctk.CTkLabel(child_process_injection_frame, text="启用子进程注入:")
        child_process_injection_label.pack(side="left", padx=10, pady=5)
        
        # 子进程注入开关，默认关闭
        self.main_window.child_process_injection_var = ctk.BooleanVar(value=False)
        self.main_window.child_process_injection_switch = ctk.CTkSwitch(
            child_process_injection_frame,
            text="",
            variable=self.main_window.child_process_injection_var
        )
        self.main_window.child_process_injection_switch.pack(side="left", padx=10, pady=5)
        
        # 模式列表反截屏保护说明
        mode_anti_screenshot_desc = ctk.CTkLabel(
            self.main_window.settings_tab, 
            text="模式列表反截屏保护（通过DLL注入保护列表中的进程）", 
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        mode_anti_screenshot_desc.pack(pady=(5, 2), anchor="w", padx=15)
        
        mode_anti_screenshot_note = ctk.CTkLabel(
            self.main_window.settings_tab,
            text="在模式一和模式二列表中添加进程后，将自动向这些进程注入AffinityHide.dll",
            font=ctk.CTkFont(size=10),
            text_color="gray"
        )
        mode_anti_screenshot_note.pack(pady=(0, 2), anchor="w", padx=20)
        
        # 功能按钮区域
        functions_label = ctk.CTkLabel(self.main_window.settings_tab, text="功能操作", font=ctk.CTkFont(size=14, weight="bold"))
        functions_label.pack(pady=(10, 2), anchor="w", padx=10)
        
        # 功能按钮框架
        functions_frame = ctk.CTkFrame(self.main_window.settings_tab)
        functions_frame.pack(fill="x", padx=10, pady=2)
        
        # 将按钮放在一行里
        buttons_frame = ctk.CTkFrame(functions_frame, fg_color="transparent")
        buttons_frame.pack(fill="x", padx=10, pady=5)
        
        # 保存和加载按钮放在同一行
        save_btn = ctk.CTkButton(buttons_frame, text="保存", width=80, height=25, 
                                font=ctk.CTkFont(size=11), command=lambda: self.main_window.save_data(show_status=True))
        save_btn.pack(side="left", padx=5)
        
        load_btn = ctk.CTkButton(buttons_frame, text="加载", width=80, height=25,
                                font=ctk.CTkFont(size=11), command=self.main_window.load_data)
        load_btn.pack(side="left", padx=5)
        
    def create_about_tab(self):
        """创建关于标签页"""
        about_label = ctk.CTkLabel(self.main_window.about_tab, text="反截屏管理程序", font=ctk.CTkFont(size=16, weight="bold"))
        about_label.pack(pady=(5, 2))
        
        version_label = ctk.CTkLabel(self.main_window.about_tab, text="版本 1.0")
        version_label.pack()
        
        description_label = ctk.CTkLabel(self.main_window.about_tab, text="基于Windows Display Affinity技术和DLL注入的进程窗口反截屏保护工具")
        description_label.pack(pady=3)
        
        features_label = ctk.CTkLabel(self.main_window.about_tab, text="\n核心技术特性：", font=ctk.CTkFont(weight="bold"))
        features_label.pack(anchor="w", padx=10)
        
        feature_list = ctk.CTkLabel(self.main_window.about_tab, text=
            "- 基于DLL注入技术实现反截屏保护\n"
            "- 使用多种Affinity DLL防止屏幕录制\n"
            "- 支持进程级和窗口级精细控制\n"
            "- 多线程实时监控和更新窗口亲和性\n"
            "- 支持配置持久化和主题切换\n"
            "- 使用psutil库进行系统进程管理",
            justify="left", anchor="w")
        feature_list.pack(padx=10, pady=3, anchor="w")
        
        # 添加DLL说明
        dll_label = ctk.CTkLabel(self.main_window.about_tab, text="\nDLL功能说明：", font=ctk.CTkFont(weight="bold"))
        dll_label.pack(anchor="w", padx=10)
        
        dll_list = ctk.CTkLabel(self.main_window.about_tab, text=
            "- AffinityHide.dll: 模式二反截屏保护\n"
            "- AffinityTrans.dll: 模式一反截屏保护\n"
            "- AffinityUnhide.dll: 取消反截屏保护\n"
            "- AffinityStatus.dll: 检查进程保护状态",
            justify="left", anchor="w")
        dll_list.pack(padx=10, pady=3, anchor="w")
        
        # 添加技术说明
        tech_label = ctk.CTkLabel(self.main_window.about_tab, text="\n技术说明", font=ctk.CTkFont(size=14, weight="bold"))
        tech_label.pack(pady=(10, 2), anchor="w", padx=10)
        
        tech_text = ctk.CTkLabel(self.main_window.about_tab, text=
            "1. 利用Windows API实现DLL远程注入\n"
            "2. 通过DLL中的SetWindowDisplayAffinity API设置窗口属性\n"
            "3. 使用FindWindowEx遍历系统窗口句柄\n"
            "4. 多线程异步处理避免界面卡顿\n"
            "5. JSON格式配置文件存储用户设置\n"
            "6. 基于CustomTkinter现代UI框架构建",
            justify="left", anchor="w")
        tech_text.pack(padx=10, pady=3, anchor="w")