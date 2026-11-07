# -*- coding: utf-8 -*-
"""
界面模块
========

基于 tkinter / ttk 的图形界面，包含：

  * normalize_target()           URL 规范化与校验（缺少协议时补全 http://）
  * get_user_input_and_validate() 获取并校验用户输入（独立函数）
  * AuthorizeDialog              开始扫描前的授权确认对话框
  * CustomParamsDialog           “自定义”档位的参数设置对话框
  * ReportWindow                 扫描报告预览与保存窗口
  * ScannerApp                   主窗口

线程模型：
    扫描逻辑在后台 threading.Thread 中执行，只通过 queue.Queue
    向界面线程发送消息；所有 tkinter 控件操作都在主线程完成。

超强力扫描：
    勾选后在开始扫描时（或点击“一键打开”时）用相同参数启动 N 个
    独立的扫描器窗口进程（--child-scan=<base64(json)>），子窗口自动
    开始扫描、数量无上限、可一键关闭；子窗口自身不能再开孙窗口。
"""

import base64
import json
import os
import queue
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
from datetime import datetime

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .config import (
    CUSTOM_INTENSITY,
    DEFAULT_CUSTOM_CONFIG,
    DEFAULT_INTENSITY,
    INTENSITY_LEVELS,
    THREADS_LIMIT,
    custom_config_to_text,
    describe_config,
    normalize_custom_config,
)
from .scanner import run_scan

# ---------------------------------------------------------------------------
# 外观常量：集中放置，便于统一调整配色与字体
# ---------------------------------------------------------------------------
WINDOW_TITLE = "Web 安全测试工具"
WINDOW_SIZE = "800x600"
MIN_WIDTH = 720
MIN_HEIGHT = 520

COLOR_BG = "#f4f6f9"          # 窗口背景
COLOR_PANEL = "#ffffff"       # 面板背景
COLOR_TEXT = "#22272e"        # 主要文字
COLOR_MUTED = "#6b7280"       # 次要文字 / 占位符
COLOR_ACCENT = "#1a73e8"      # 主按钮
COLOR_ACCENT_ACTIVE = "#1557b0"
COLOR_BORDER = "#d7dce3"
COLOR_INFO = "#24292f"        # 信息日志
COLOR_WARNING = "#a15c00"     # 警告日志
COLOR_RISK = "#c62828"        # 风险日志
COLOR_SYSTEM = "#0b5cad"      # 阶段/系统日志

URL_PLACEHOLDER = "请输入目标 URL 或 IP，如 http://test.example.com"

# 强度下拉框的可选项：三档固定强度 + 自定义
LEVEL_CHOICES = list(INTENSITY_LEVELS.keys()) + [CUSTOM_INTENSITY]

# 超强力扫描：子窗口进程通过命令行参数 --child-scan=<base64(json)> 接收扫描参数
CHILD_ARG_PREFIX = "--child-scan="


def encode_child_payload(payload):
    """把子窗口参数（dict）编码成可通过命令行传递的 base64 字符串。"""
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def decode_child_payload(text):
    """解析 --child-scan= 参数；失败返回 None。"""
    try:
        data = base64.b64decode(text.encode("ascii"))
        payload = json.loads(data.decode("utf-8"))
        if isinstance(payload, dict) and payload.get("target"):
            return payload
    except Exception:
        pass
    return None


def child_command_prefix():
    """
    返回启动子窗口进程的命令行前缀。

    - 打包后（PyInstaller frozen）：直接再次运行自身 exe；
    - 源码运行：优先用 pythonw.exe（无控制台窗口闪现），
      找不到时退回当前解释器。
    """
    if getattr(sys, "frozen", False):
        return [sys.executable]

    executable = sys.executable
    directory, name = os.path.split(executable)
    if name.lower().startswith("python."):
        pythonw = os.path.join(directory, "pythonw.exe")
        if os.path.exists(pythonw):
            executable = pythonw

    # gui.py 位于 <项目根>/websectool/ 下：
    #   abspath -> ...\websectool\gui.py
    #   第 1 层 dirname -> ...\websectool
    #   第 2 层 dirname -> 项目根
    project_root = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
    main_py = os.path.join(project_root, "main.py")
    if os.path.exists(main_py):
        return [executable, main_py]
    # 兜底：按当前启动脚本原样再开一份
    return [executable, os.path.abspath(sys.argv[0])]


def child_popen_kwargs():
    """子进程启动参数：Windows 下隐藏可能弹出的控制台窗口。"""
    kwargs = {"close_fds": True}
    if sys.platform == "win32":
        # CREATE_NO_WINDOW = 0x08000000
        kwargs["creationflags"] = 0x08000000
    return kwargs


def _ui_font(size=10, bold=False):
    """返回界面字体元组；Windows 下优先使用微软雅黑。"""
    family = "Microsoft YaHei UI"
    return (family, size, "bold") if bold else (family, size)


def _mono_font(size=10):
    """日志区域使用等宽字体，时间戳更容易对齐。"""
    return ("Consolas", size)


# ---------------------------------------------------------------------------
# 输入校验
# ---------------------------------------------------------------------------
def normalize_target(raw_value):
    """
    规范化并校验目标地址。

    规则：
      * 去掉首尾空白；
      * 缺少 http:// 或 https:// 前缀时自动补全 http://；
      * 只允许 http / https 协议；
      * 必须包含有效主机名或 IP，端口号必须在 1-65535 之间。

    成功返回规范化后的 URL；失败抛出 ValueError（消息可直接展示给用户）。
    """
    value = (raw_value or "").strip()
    if not value or value == URL_PLACEHOLDER:
        raise ValueError("请输入目标 URL 或 IP 地址。")
    if any(ch.isspace() for ch in value):
        raise ValueError("目标地址中不能包含空格。")

    # 已显式写了协议时，只接受 http / https
    if "://" in value:
        scheme = value.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            raise ValueError("仅支持 http:// 或 https:// 协议。")

    if not value.lower().startswith(("http://", "https://")):
        value = "http://" + value

    parts = urllib.parse.urlsplit(value)
    if parts.scheme not in ("http", "https"):
        raise ValueError("仅支持 http:// 或 https:// 协议。")
    if not parts.hostname:
        raise ValueError("目标地址中缺少有效的主机名或 IP。")

    try:
        port = parts.port
    except ValueError:
        raise ValueError("目标地址的端口号无效。")
    if port is not None and not (1 <= port <= 65535):
        raise ValueError("端口号必须在 1-65535 之间。")

    path = parts.path or "/"
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, path, parts.query, "")
    )


def get_user_input_and_validate(url_value, level_value, custom_config=None):
    """
    获取并校验用户输入（独立函数，主流程在启动扫描前调用）。

    参数：
        url_value      输入框中的目标地址
        level_value    下拉框选中的强度（含“自定义”）
        custom_config  选中“自定义”时，由“自定义参数”对话框校验好的配置字典

    返回：
        (config, "")              校验通过，config 形如
                                  {"target": "...", "level": "中强度",
                                   "config": None 或自定义参数字典}
        (None, "错误提示")         校验失败
    """
    try:
        target = normalize_target(url_value)
    except ValueError as exc:
        return None, str(exc)

    if level_value == CUSTOM_INTENSITY:
        # 自定义档位必须已经通过对话框校验并保存了参数
        if not isinstance(custom_config, dict) or not custom_config.get("paths"):
            return None, "请先点击“自定义参数…”设置并校验自定义扫描参数。"
        return {"target": target, "level": level_value,
                "config": dict(custom_config)}, ""

    if level_value not in INTENSITY_LEVELS:
        return None, "请选择有效的扫描强度。"

    return {"target": target, "level": level_value, "config": None}, ""


def _center_on_parent(window, parent):
    """把窗口居中显示在父窗口上方（并确保不超出屏幕）。"""
    window.update_idletasks()
    width = max(window.winfo_width(), window.winfo_reqwidth())
    height = max(window.winfo_height(), window.winfo_reqheight())
    parent_x = parent.winfo_rootx()
    parent_y = parent.winfo_rooty()
    parent_width = parent.winfo_width()
    parent_height = parent.winfo_height()
    x = parent_x + max(0, (parent_width - width) // 2)
    y = parent_y + max(0, (parent_height - height) // 3)

    # 避免窗口被推到屏幕之外
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = max(0, min(x, screen_width - width - 20))
    y = max(0, min(y, screen_height - height - 40))
    window.geometry("+%d+%d" % (x, y))


# ---------------------------------------------------------------------------
# 授权确认对话框
# ---------------------------------------------------------------------------
class AuthorizeDialog(tk.Toplevel):
    """
    开始扫描前的授权确认对话框。

    用户必须勾选“我确认拥有该目标的测试授权”后，“确认开始”按钮才可用。
    关闭窗口或点击“取消”视为未授权。
    """

    def __init__(self, parent, target, level):
        tk.Toplevel.__init__(self, parent)
        self.result = False
        self.title("授权确认")
        self.configure(bg=COLOR_BG)
        self.resizable(False, False)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

        container = ttk.Frame(self, padding=20)
        container.pack(fill="both", expand=True)

        ttk.Label(
            container,
            text="开始前请确认测试授权",
            font=_ui_font(12, bold=True),
            foreground=COLOR_RISK,
        ).pack(anchor="w")

        info = (
            "本工具仅用于您拥有管理权限、或已获得明确书面授权的测试环境。\n"
            "未经授权对第三方系统进行扫描，可能违反法律法规，并承担相应责任。\n\n"
            "本次扫描目标：%s\n"
            "扫描强度：%s" % (target, level)
        )
        ttk.Label(
            container,
            text=info,
            justify="left",
            wraplength=460,
            foreground=COLOR_TEXT,
        ).pack(anchor="w", pady=(10, 14))

        self.confirm_var = tk.BooleanVar(value=False)
        check = ttk.Checkbutton(
            container,
            text="我确认拥有该目标的测试授权",
            variable=self.confirm_var,
            command=self._on_toggle,
        )
        check.pack(anchor="w")

        button_bar = ttk.Frame(container)
        button_bar.pack(fill="x", pady=(18, 0))

        self.confirm_button = ttk.Button(
            button_bar,
            text="确认开始",
            style="Accent.TButton",
            command=self._on_confirm,
        )
        self.confirm_button.pack(side="right")
        self.confirm_button.state(["disabled"])

        ttk.Button(
            button_bar,
            text="取消",
            command=self._on_cancel,
        ).pack(side="right", padx=(0, 10))

        # 回车确认 / Esc 取消
        self.bind("<Return>", lambda event: self._on_confirm())
        self.bind("<Escape>", lambda event: self._on_cancel())

        _center_on_parent(self, parent)
        self.grab_set()
        check.focus_set()
        self.wait_window(self)

    def _on_toggle(self):
        """根据复选框状态启用或禁用“确认开始”按钮。"""
        if self.confirm_var.get():
            self.confirm_button.state(["!disabled"])
        else:
            self.confirm_button.state(["disabled"])

    def _on_confirm(self):
        if not self.confirm_var.get():
            return  # 未勾选授权时不做任何事
        self.result = True
        self.destroy()

    def _on_cancel(self):
        self.result = False
        self.destroy()


# ---------------------------------------------------------------------------
# 自定义参数对话框
# ---------------------------------------------------------------------------
class CustomParamsDialog(tk.Toplevel):
    """
    “自定义参数”对话框：让用户自行设置扫描参数。

    可设置项与 INTENSITY_LEVELS 中的字段一致：
        请求间隔、并发线程数、超时、重试次数、最多测试表单数、
        每表单最多字段数、端口列表、路径字典。

    点击“确定”时由 config.normalize_custom_config() 统一校验，
    校验失败会留在对话框内并提示原因；成功后结果保存在 self.result。
    """

    def __init__(self, parent, config):
        tk.Toplevel.__init__(self, parent)
        self.result = None
        self.title("自定义扫描参数")
        self.configure(bg=COLOR_BG)
        self.resizable(False, False)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

        container = ttk.Frame(self, padding=16)
        container.pack(fill="both", expand=True)

        ttk.Label(
            container,
            text="自定义扫描参数",
            font=_ui_font(12, bold=True),
        ).pack(anchor="w")
        ttk.Label(
            container,
            text=("以下参数仅在扫描强度选择“%s”时生效；"
                  "并发线程数上限为 %s（仅为避免误填超大数值，"
                  "不再做 5 线程的安全限制）。" % (CUSTOM_INTENSITY,
                                            THREADS_LIMIT)),
            style="Muted.TLabel",
            wraplength=520,
            justify="left",
        ).pack(anchor="w", pady=(6, 12))

        values = custom_config_to_text(config)

        # -- 数值参数：两列网格，便于阅读 ----------------------------------
        grid = ttk.Frame(container)
        grid.pack(fill="x")
        number_fields = (
            ("delay", "请求间隔（秒）"),
            ("threads", "并发线程数"),
            ("timeout", "请求超时（秒）"),
            ("retries", "重试次数"),
            ("max_forms", "最多测试表单数"),
            ("max_fields_per_form", "每表单最多字段数"),
        )
        self.vars = {}
        for index, (key, label) in enumerate(number_fields):
            row, column = divmod(index, 2)
            cell = ttk.Frame(grid)
            cell.grid(row=row, column=column, sticky="w",
                      padx=(0, 20), pady=4)
            ttk.Label(cell, text=label, width=16, anchor="w").pack(side="left")
            var = tk.StringVar(value=values.get(key, ""))
            ttk.Entry(cell, textvariable=var, width=12).pack(side="left")
            self.vars[key] = var

        # -- 端口列表 ------------------------------------------------------
        ttk.Label(
            container,
            text="端口列表（逗号或空格分隔，1-65535）",
        ).pack(anchor="w", pady=(12, 2))
        self.ports_var = tk.StringVar(value=values.get("ports", ""))
        ttk.Entry(container, textvariable=self.ports_var).pack(fill="x")

        # -- 路径字典 ------------------------------------------------------
        ttk.Label(
            container,
            text="路径字典（每行一条，缺少开头的 / 会自动补全，# 开头为注释）",
        ).pack(anchor="w", pady=(12, 2))
        text_frame = ttk.Frame(container)
        text_frame.pack(fill="both", expand=True)
        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side="right", fill="y")
        self.paths_text = tk.Text(
            text_frame,
            height=12,
            width=64,
            wrap="none",
            font=_mono_font(9),
            relief="solid",
            borderwidth=1,
            yscrollcommand=scrollbar.set,
        )
        self.paths_text.pack(side="left", fill="both", expand=True)
        scrollbar.configure(command=self.paths_text.yview)
        self.paths_text.insert("1.0", values.get("paths", ""))

        # -- 按钮区 --------------------------------------------------------
        button_bar = ttk.Frame(container)
        button_bar.pack(fill="x", pady=(14, 0))
        ttk.Button(
            button_bar, text="确定", style="Accent.TButton",
            command=self._on_confirm,
        ).pack(side="right")
        ttk.Button(
            button_bar, text="取消", command=self._on_cancel,
        ).pack(side="right", padx=(0, 10))
        ttk.Button(
            button_bar, text="恢复默认", command=self._on_reset,
        ).pack(side="left")

        self.bind("<Escape>", lambda event: self._on_cancel())
        _center_on_parent(self, parent)
        self.grab_set()
        self.wait_window(self)

    def _collect(self):
        """收集界面上的原始输入（字符串），交给 config 模块校验。"""
        raw = {key: var.get() for key, var in self.vars.items()}
        raw["ports"] = self.ports_var.get()
        raw["paths"] = self.paths_text.get("1.0", "end")
        return raw

    def _on_reset(self):
        """恢复为“中强度”的默认参数。"""
        values = custom_config_to_text(DEFAULT_CUSTOM_CONFIG)
        for key, var in self.vars.items():
            var.set(values.get(key, ""))
        self.ports_var.set(values.get("ports", ""))
        self.paths_text.delete("1.0", "end")
        self.paths_text.insert("1.0", values.get("paths", ""))

    def _on_confirm(self):
        config, error = normalize_custom_config(self._collect())
        if error:
            messagebox.showwarning("参数有误", error, parent=self)
            return
        self.result = config
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()


# ---------------------------------------------------------------------------
# 报告预览窗口
# ---------------------------------------------------------------------------
class ReportWindow(tk.Toplevel):
    """扫描报告预览窗口，支持另存为 .txt 文件。"""

    def __init__(self, parent, report_text, target, stopped):
        tk.Toplevel.__init__(self, parent)
        self.report_text = report_text
        self.target = target
        self.title("扫描报告预览" + ("（扫描已停止）" if stopped else ""))
        self.configure(bg=COLOR_BG)
        self.geometry("760x620")
        self.minsize(560, 420)
        self.transient(parent)

        container = ttk.Frame(self, padding=12)
        container.pack(fill="both", expand=True)

        text_frame = ttk.Frame(container)
        text_frame.pack(fill="both", expand=True)

        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side="right", fill="y")

        self.text = tk.Text(
            text_frame,
            wrap="word",
            font=_mono_font(10),
            background=COLOR_PANEL,
            foreground=COLOR_TEXT,
            relief="flat",
            padx=10,
            pady=10,
            yscrollcommand=scrollbar.set,
        )
        self.text.pack(side="left", fill="both", expand=True)
        scrollbar.configure(command=self.text.yview)

        self.text.insert("1.0", report_text)
        self.text.configure(state="disabled")

        button_bar = ttk.Frame(container)
        button_bar.pack(fill="x", pady=(10, 0))

        ttk.Label(
            button_bar,
            text="提示：报告可直接复制，或保存为 .txt 文件。",
            foreground=COLOR_MUTED,
        ).pack(side="left")

        ttk.Button(
            button_bar,
            text="关闭",
            command=self.destroy,
        ).pack(side="right")

        ttk.Button(
            button_bar,
            text="保存报告",
            style="Accent.TButton",
            command=self._save_report,
        ).pack(side="right", padx=(0, 10))

        _center_on_parent(self, parent)
        self.grab_set()

    def _save_report(self):
        """弹出保存对话框，把报告写成 UTF-8 文本文件。"""
        default_name = "web_security_report_%s.txt" % datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )
        path = filedialog.asksaveasfilename(
            parent=self,
            title="保存扫描报告",
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.report_text)
        except OSError as exc:
            messagebox.showerror("保存失败", "无法写入文件：\n%s" % exc, parent=self)
            return
        messagebox.showinfo("保存成功", "报告已保存到：\n%s" % path, parent=self)


# ---------------------------------------------------------------------------
# 主窗口
# ---------------------------------------------------------------------------
class ScannerApp(tk.Tk):
    """工具主窗口。

    child_payload 不为 None 时表示这是“超强力扫描”派生的子窗口：
    参数与主窗口相同、跳过授权确认（主窗口已确认）、自动开始扫描，
    并且不再拥有开启孙窗口的能力。
    """

    def __init__(self, child_payload=None):
        tk.Tk.__init__(self)
        self.child_payload = child_payload
        if child_payload:
            self.title(WINDOW_TITLE + "（超强力扫描窗口）")
        else:
            self.title(WINDOW_TITLE)
        self.geometry(WINDOW_SIZE)
        self.minsize(MIN_WIDTH, MIN_HEIGHT)
        self.configure(bg=COLOR_BG)

        # -- 运行状态 ---------------------------------------------------
        self.scanning = False
        self.stop_event = None
        self.worker = None
        self.message_queue = None
        self._poll_active = False
        self._timer_job = None
        self._scan_start = 0.0
        self._current_stage = "待开始"
        self._report_window = None

        # -- 超强力扫描：本窗口派生出的子扫描进程 -----------------------
        self._children = []          # subprocess.Popen 列表
        self._child_poll_job = None  # 定期清点子进程数量的 after 任务
        # 最近一次确认过的扫描参数（子窗口继承用）
        self._active_payload = None

        # 自定义档位的参数（由 CustomParamsDialog 校验后保存，可在多次扫描间复用）
        self.custom_config = {
            "delay": DEFAULT_CUSTOM_CONFIG["delay"],
            "threads": DEFAULT_CUSTOM_CONFIG["threads"],
            "timeout": DEFAULT_CUSTOM_CONFIG["timeout"],
            "retries": DEFAULT_CUSTOM_CONFIG["retries"],
            "max_forms": DEFAULT_CUSTOM_CONFIG["max_forms"],
            "max_fields_per_form": DEFAULT_CUSTOM_CONFIG["max_fields_per_form"],
            "ports": list(DEFAULT_CUSTOM_CONFIG["ports"]),
            "paths": list(DEFAULT_CUSTOM_CONFIG["paths"]),
        }

        self._configure_style()
        self._build_widgets()
        self._set_scanning_state(False)

        # 子窗口：套用主窗口传来的参数并自动开始扫描。
        # 授权确认已由主窗口完成，这里不再重复弹出，也不再显示超强力扫描行。
        if child_payload:
            self._apply_child_payload(child_payload)
            self.after(400, self._auto_start_as_child)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # 子窗口（超强力扫描派生）
    # ------------------------------------------------------------------
    def _apply_child_payload(self, payload):
        """把主窗口传来的参数回填到界面控件。"""
        self.url_var.set(payload.get("target", ""))
        self.url_entry.configure(foreground=COLOR_TEXT)
        level = payload.get("level")
        if level in LEVEL_CHOICES:
            self.level_var.set(level)
        if payload.get("config"):
            self.custom_config = dict(payload["config"])
        self.continuous_var.set(bool(payload.get("continuous")))
        self._update_level_hint()

    def _auto_start_as_child(self):
        """子窗口自动开始扫描（跳过授权确认，参数继承自主窗口）。"""
        if self.scanning or not self.child_payload:
            return
        payload = self.child_payload
        target = payload.get("target", "")
        level = payload.get("level", DEFAULT_INTENSITY)
        level_config = payload.get("config")
        continuous = bool(payload.get("continuous"))
        if not target:
            return

        active_config = level_config if level_config is not None \
            else INTENSITY_LEVELS.get(level, INTENSITY_LEVELS[DEFAULT_INTENSITY])

        self.progress.configure(value=0)
        self.elapsed_var.set("用时：00:00")
        self._set_stage("准备中")
        self._set_scanning_state(True)

        self.message_queue = queue.Queue()
        self.stop_event = threading.Event()
        self._scan_start = time.monotonic()
        self._poll_active = True

        self.append_log("系统", "=" * 30)
        self.append_log("系统",
                        "开始扫描：%s（强度：%s）" % (target, level))
        self.append_log("信息",
                        "本次参数：%s。" % describe_config(active_config))
        self.append_log("系统",
                        "本窗口由超强力扫描自动打开，参数与授权继承自主窗口。")
        if continuous:
            self.append_log("系统", "持续扫描已开启：将持续循环，直到点击“停止扫描”。")

        self.worker = threading.Thread(
            target=self._scan_worker,
            args=(target, level, level_config, continuous),
            name="scan-worker",
            daemon=True,
        )
        self.worker.start()

        self._tick_timer()
        self.after(80, self._poll_messages)

    # ------------------------------------------------------------------
    # 样式
    # ------------------------------------------------------------------
    def _configure_style(self):
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure("TFrame", background=COLOR_BG)
        style.configure("Panel.TFrame", background=COLOR_PANEL)
        style.configure(
            "TLabel", background=COLOR_BG, foreground=COLOR_TEXT
        )
        style.configure(
            "Panel.TLabel", background=COLOR_PANEL, foreground=COLOR_TEXT
        )
        style.configure(
            "Muted.TLabel", background=COLOR_BG, foreground=COLOR_MUTED
        )
        style.configure(
            "Title.TLabel",
            background=COLOR_BG,
            foreground=COLOR_TEXT,
            font=_ui_font(11, bold=True),
        )
        style.configure("TButton", font=_ui_font(10), padding=(12, 5))
        style.configure(
            "Accent.TButton",
            font=_ui_font(10, bold=True),
            padding=(14, 6),
            background=COLOR_ACCENT,
            foreground="#ffffff",
        )
        style.map(
            "Accent.TButton",
            background=[("disabled", "#a9c3ea"), ("active", COLOR_ACCENT_ACTIVE)],
            foreground=[("disabled", "#f0f0f0")],
        )
        style.configure("TEntry", padding=4)
        style.configure("TCombobox", padding=3)
        style.configure(
            "TLabelframe",
            background=COLOR_BG,
            bordercolor=COLOR_BORDER,
            relief="solid",
        )
        style.configure(
            "TLabelframe.Label",
            background=COLOR_BG,
            foreground=COLOR_TEXT,
            font=_ui_font(10, bold=True),
        )
        style.configure(
            "TProgressbar",
            troughcolor="#e3e7ee",
            background=COLOR_ACCENT,
            bordercolor=COLOR_BORDER,
            lightcolor=COLOR_ACCENT,
            darkcolor=COLOR_ACCENT,
        )
        style.configure("TCheckbutton", background=COLOR_BG)

    # ------------------------------------------------------------------
    # 界面布局
    # ------------------------------------------------------------------
    def _build_widgets(self):
        outer = ttk.Frame(self, padding=(16, 14, 16, 12))
        outer.pack(fill="both", expand=True)

        self._build_top_area(outer)
        self._build_log_area(outer)
        self._build_bottom_area(outer)

    def _build_top_area(self, parent):
        """顶部：目标输入、强度选择、开始/停止按钮。"""
        top = ttk.Frame(parent)
        top.pack(fill="x")

        ttk.Label(top, text="目标 URL", font=_ui_font(10, bold=True)).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            top,
            text="扫描强度",
            font=_ui_font(10, bold=True),
        ).grid(row=0, column=2, sticky="w", padx=(16, 8))

        # 目标输入框 + 占位提示
        self.url_var = tk.StringVar(value=URL_PLACEHOLDER)
        self.url_entry = ttk.Entry(
            top,
            textvariable=self.url_var,
            font=_ui_font(10),
        )
        self.url_entry.grid(
            row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0)
        )
        self.url_entry.configure(foreground=COLOR_MUTED)
        self.url_entry.bind("<FocusIn>", self._on_url_focus_in)
        self.url_entry.bind("<FocusOut>", self._on_url_focus_out)

        # 强度下拉框（三档固定强度 + 自定义）
        self.level_var = tk.StringVar(value=DEFAULT_INTENSITY)
        self.level_box = ttk.Combobox(
            top,
            textvariable=self.level_var,
            values=LEVEL_CHOICES,
            state="readonly",
            width=10,
        )
        self.level_box.grid(
            row=1, column=2, sticky="w", padx=(16, 0), pady=(6, 0)
        )

        # 按钮区
        self.start_button = ttk.Button(
            top,
            text="开始扫描",
            style="Accent.TButton",
            command=self._start_scan,
        )
        self.start_button.grid(
            row=0, column=3, rowspan=2, sticky="e", padx=(16, 0)
        )

        self.stop_button = ttk.Button(
            top,
            text="停止扫描",
            command=self._stop_scan,
        )
        self.stop_button.grid(
            row=0, column=4, rowspan=2, sticky="e", padx=(10, 0)
        )

        top.columnconfigure(0, weight=1)
        top.columnconfigure(1, weight=1)
        top.columnconfigure(2, weight=0)

        # 强度说明文字（随下拉框变化，帮助用户理解参数差异）
        # 右侧放“自定义参数…”按钮，仅在选择“自定义”档位时可用。
        hint_row = ttk.Frame(parent)
        hint_row.pack(fill="x", pady=(6, 10))

        self.custom_button = ttk.Button(
            hint_row,
            text="自定义参数…",
            command=self._open_custom_params,
        )
        self.custom_button.pack(side="right")

        self.level_hint = ttk.Label(
            hint_row, text="", style="Muted.TLabel"
        )
        self.level_hint.pack(side="left", fill="x", expand=True)

        self.level_var.trace_add("write", self._on_level_changed)
        self._update_level_hint()

        # 持续扫描开关：勾选后每轮扫描结束会自动开始下一轮，
        # 直到用户点击“停止扫描”才结束（在后台线程里循环执行）。
        options_row = ttk.Frame(parent)
        options_row.pack(fill="x", pady=(0, 10))

        self.continuous_var = tk.BooleanVar(value=False)
        self.continuous_check = ttk.Checkbutton(
            options_row,
            text="持续扫描（循环执行，直到点击“停止扫描”）",
            variable=self.continuous_var,
        )
        self.continuous_check.pack(side="left")

        # 超强力扫描行：勾选后开始扫描时按指定数量打开相同参数的
        # 扫描器子窗口并自动开扫；数量无上限，可一键打开 / 一键关闭。
        # 子窗口自身不再显示这一行（避免无限派生孙窗口）。
        if self.child_payload is None:
            ultra_row = ttk.Frame(parent)
            ultra_row.pack(fill="x", pady=(0, 10))

            self.ultra_var = tk.BooleanVar(value=False)
            self.ultra_check = ttk.Checkbutton(
                ultra_row,
                text="超强力扫描",
                variable=self.ultra_var,
            )
            self.ultra_check.pack(side="left")

            ttk.Label(ultra_row, text="窗口数量").pack(
                side="left", padx=(12, 4)
            )
            self.ultra_count_var = tk.StringVar(value="4")
            self.ultra_count_entry = ttk.Entry(
                ultra_row, textvariable=self.ultra_count_var, width=6
            )
            self.ultra_count_entry.pack(side="left")

            self.ultra_open_button = ttk.Button(
                ultra_row,
                text="一键打开",
                command=self._one_click_open,
            )
            self.ultra_open_button.pack(side="left", padx=(10, 0))

            self.ultra_close_button = ttk.Button(
                ultra_row,
                text="一键关闭",
                command=self._one_click_close,
            )
            self.ultra_close_button.pack(side="left", padx=(8, 0))

            self.ultra_status_var = tk.StringVar(value="子窗口：0 个运行中")
            ttk.Label(
                ultra_row, textvariable=self.ultra_status_var,
                style="Muted.TLabel",
            ).pack(side="left", padx=(14, 0))

    def _build_log_area(self, parent):
        """中部：带时间戳的彩色日志。"""
        log_frame = ttk.LabelFrame(parent, text="扫描日志", padding=8)
        log_frame.pack(fill="both", expand=True)

        scrollbar = ttk.Scrollbar(log_frame)
        scrollbar.pack(side="right", fill="y")

        self.log_text = tk.Text(
            log_frame,
            wrap="word",
            font=_mono_font(10),
            # 只作为最小高度提示：日志区会随窗口用 expand 自动拉伸，
            # 这里给小一点的值，避免窗口较小时把底部状态栏挤出可视区域。
            height=12,
            background=COLOR_PANEL,
            foreground=COLOR_INFO,
            relief="flat",
            padx=8,
            pady=8,
            yscrollcommand=scrollbar.set,
        )
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar.configure(command=self.log_text.yview)

        # 不同日志级别使用不同颜色
        self.log_text.tag_configure("信息", foreground=COLOR_INFO)
        self.log_text.tag_configure("警告", foreground=COLOR_WARNING)
        self.log_text.tag_configure(
            "风险", foreground=COLOR_RISK, font=("Consolas", 10, "bold")
        )
        self.log_text.tag_configure(
            "系统", foreground=COLOR_SYSTEM, font=("Consolas", 10, "bold")
        )
        self.log_text.configure(state="disabled")

    def _build_bottom_area(self, parent):
        """底部：进度条 + 状态栏（阶段、用时）。"""
        bottom = ttk.Frame(parent)
        bottom.pack(fill="x", pady=(12, 0))

        self.progress = ttk.Progressbar(
            bottom,
            orient="horizontal",
            mode="determinate",
            maximum=100,
            value=0,
        )
        self.progress.pack(fill="x")

        status = ttk.Frame(bottom)
        status.pack(fill="x", pady=(8, 0))

        self.stage_var = tk.StringVar(value="阶段：待开始")
        self.elapsed_var = tk.StringVar(value="用时：00:00")

        ttk.Label(
            status,
            textvariable=self.stage_var,
            foreground=COLOR_TEXT,
        ).pack(side="left")

        ttk.Label(
            status,
            textvariable=self.elapsed_var,
            foreground=COLOR_MUTED,
        ).pack(side="right")

        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(
            status,
            textvariable=self.status_var,
            foreground=COLOR_MUTED,
        ).pack(side="left", padx=(18, 0))

    # ------------------------------------------------------------------
    # 占位提示与强度说明
    # ------------------------------------------------------------------
    def _on_url_focus_in(self, _event=None):
        if self.url_var.get() == URL_PLACEHOLDER:
            self.url_var.set("")
            self.url_entry.configure(foreground=COLOR_TEXT)

    def _on_url_focus_out(self, _event=None):
        if not self.url_var.get().strip():
            self.url_var.set(URL_PLACEHOLDER)
            self.url_entry.configure(foreground=COLOR_MUTED)

    def _on_level_changed(self, *_args):
        self._update_level_hint()
        self._update_custom_button()

    def _resolve_config(self):
        """返回当前档位对应的参数配置（自定义档位返回用户保存的配置）。"""
        level = self.level_var.get()
        if level == CUSTOM_INTENSITY:
            return self.custom_config
        return INTENSITY_LEVELS.get(level)

    def _update_level_hint(self):
        """刷新强度说明文字与自定义参数提示。"""
        level = self.level_var.get()
        cfg = self._resolve_config()
        if not cfg:
            self.level_hint.configure(text="")
            return
        prefix = "当前档位参数：" if level != CUSTOM_INTENSITY else "自定义参数："
        self.level_hint.configure(
            text=("%s%s" % (prefix, describe_config(cfg)))
        )

    def _update_custom_button(self):
        """只有选择“自定义”档位且当前未在扫描时，按钮才可用。"""
        if self.level_var.get() == CUSTOM_INTENSITY and not self.scanning:
            self.custom_button.state(["!disabled"])
        else:
            self.custom_button.state(["disabled"])

    def _open_custom_params(self):
        """打开“自定义参数”对话框，并把校验通过的配置保存下来。"""
        if self.scanning:
            return
        dialog = CustomParamsDialog(self, self.custom_config)
        if dialog.result:
            self.custom_config = dialog.result
            self._update_level_hint()
            self.append_log(
                "系统",
                "已更新自定义参数：%s" % describe_config(self.custom_config),
            )

    # ------------------------------------------------------------------
    # 超强力扫描：批量打开 / 关闭相同参数的子扫描窗口
    # ------------------------------------------------------------------
    def _build_child_payload(self, target, level, level_config, continuous):
        """组装传给子窗口进程的参数字典（与原窗口完全一致）。"""
        return {
            "target": target,
            "level": level,
            "config": dict(level_config) if level_config else None,
            "continuous": bool(continuous),
        }

    def _parse_ultra_count(self):
        """解析“窗口数量”输入；必须是不小于 1 的整数，无上限。"""
        text = (self.ultra_count_var.get() or "").strip()
        try:
            count = int(text)
        except ValueError:
            return None, "窗口数量必须是整数。"
        if count < 1:
            return None, "窗口数量必须不小于 1。"
        return count, ""

    def _spawn_child_windows(self, count):
        """以当前扫描参数启动 count 个子扫描窗口进程（数量无上限）。"""
        payload = self._active_payload
        if payload is None:
            self.append_log("警告", "没有可继承的扫描参数，无法打开子窗口。")
            return

        command_prefix = child_command_prefix()
        argument = CHILD_ARG_PREFIX + encode_child_payload(payload)
        popen_kwargs = child_popen_kwargs()
        opened = 0
        for _index in range(count):
            try:
                process = subprocess.Popen(
                    command_prefix + [argument], **popen_kwargs
                )
            except OSError as exc:
                self.append_log("风险", "启动子扫描窗口失败：%s" % exc)
                break
            self._children.append(process)
            opened += 1

        if opened:
            self.append_log(
                "系统",
                "超强力扫描：已打开 %s 个相同参数的子扫描窗口，"
                "当前共 %s 个运行中。" % (opened, self._running_child_count()),
            )
            self._update_ultra_status()
            self._start_child_poll()

    def _running_child_count(self):
        """统计仍存活的子进程数量。"""
        return sum(
            1 for process in self._children if process.poll() is None
        )

    def _update_ultra_status(self):
        self.ultra_status_var.set(
            "子窗口：%s 个运行中" % self._running_child_count()
        )

    def _start_child_poll(self):
        """定期清点子进程数量（子窗口可能被用户手动关闭）。"""
        if self._child_poll_job is not None:
            return
        self._child_poll_job = self.after(1000, self._poll_children)

    def _poll_children(self):
        self._child_poll_job = None
        # 清理已退出的子进程句柄
        self._children = [
            process for process in self._children if process.poll() is None
        ]
        self._update_ultra_status()
        if self._children:
            self._child_poll_job = self.after(1000, self._poll_children)

    def _one_click_open(self):
        """“一键打开”：按输入数量打开子扫描窗口。

        - 主窗口正在扫描：直接继承当前扫描参数（授权已在开始时确认）；
        - 主窗口空闲：先校验输入并弹出授权确认，确认后才打开子窗口。
        """
        count, error = self._parse_ultra_count()
        if error:
            messagebox.showwarning("参数有误", error, parent=self)
            return

        if self.scanning:
            self._spawn_child_windows(count)
            return

        validated, error = get_user_input_and_validate(
            self.url_var.get(), self.level_var.get(), self.custom_config
        )
        if error:
            messagebox.showwarning("输入有误", error, parent=self)
            return

        target = validated["target"]
        level = validated["level"]
        level_config = validated["config"]
        active_config = level_config if level_config is not None \
            else INTENSITY_LEVELS[level]
        level_label = level
        if level == CUSTOM_INTENSITY:
            level_label = "%s（%s）" % (level, describe_config(active_config))

        dialog = AuthorizeDialog(self, target, level_label)
        if not dialog.result:
            self.status_var.set("已取消（未确认授权）")
            return

        self.url_var.set(target)
        self.url_entry.configure(foreground=COLOR_TEXT)
        self._active_payload = self._build_child_payload(
            target, level, level_config, self.continuous_var.get()
        )
        self._spawn_child_windows(count)

    def _one_click_close(self):
        """“一键关闭”：终止所有由本窗口打开的子扫描窗口进程。"""
        closed = self._terminate_children()
        if closed:
            self.append_log(
                "系统", "超强力扫描：已一键关闭 %s 个子扫描窗口。" % closed
            )
        self._update_ultra_status()

    def _terminate_children(self):
        """结束全部子进程；返回关闭数量。静默执行，不写日志。"""
        closed = 0
        for process in self._children:
            if process.poll() is None:
                try:
                    process.terminate()
                    closed += 1
                except OSError:
                    pass
        # 给子进程一点退出时间，仍未退出的强制结束
        deadline = time.monotonic() + 3.0
        for process in self._children:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except OSError:
                    pass
            except OSError:
                pass
        self._children = []
        if self._child_poll_job is not None:
            try:
                self.after_cancel(self._child_poll_job)
            except (tk.TclError, ValueError):
                pass
            self._child_poll_job = None
        return closed

    # ------------------------------------------------------------------
    # 日志与状态
    # ------------------------------------------------------------------
    def append_log(self, level, message):
        """向日志区追加一行带时间戳的记录（主线程调用）。"""
        timestamp = time.strftime("%H:%M:%S")
        line = "[%s] %s\n" % (timestamp, message)

        self.log_text.configure(state="normal")
        self.log_text.insert("end", line, level)
        self.log_text.see("end")

        # 限制日志行数，避免长时间运行占用过多内存
        total_lines = int(self.log_text.index("end-1c").split(".")[0])
        if total_lines > 4000:
            self.log_text.delete("1.0", "1000.0")

        self.log_text.configure(state="disabled")

    def _set_stage(self, stage):
        self._current_stage = stage
        self.stage_var.set("阶段：%s" % stage)

    def _set_scanning_state(self, scanning):
        """根据是否在扫描切换按钮可用状态。"""
        self.scanning = scanning
        if scanning:
            self.start_button.state(["disabled"])
            self.stop_button.state(["!disabled"])
            self.status_var.set("扫描中…")
            # 扫描过程中不允许改变扫描模式
            self.continuous_check.state(["disabled"])
            if self.child_payload is None:
                # 超强力扫描开关同样锁定，但“一键打开/关闭”扫描中仍可用
                self.ultra_check.state(["disabled"])
        else:
            self.start_button.state(["!disabled"])
            self.stop_button.state(["disabled"])
            self.status_var.set("就绪")
            self.continuous_check.state(["!disabled"])
            if self.child_payload is None:
                self.ultra_check.state(["!disabled"])
        self._update_custom_button()

    def _tick_timer(self):
        """每秒刷新一次已用时。"""
        if not self.scanning:
            return
        elapsed = int(time.monotonic() - self._scan_start)
        self.elapsed_var.set(
            "用时：%02d:%02d" % (elapsed // 60, elapsed % 60)
        )
        self._timer_job = self.after(500, self._tick_timer)

    # ------------------------------------------------------------------
    # 开始扫描
    # ------------------------------------------------------------------
    def _start_scan(self):
        """校验输入 -> 授权确认 -> 启动后台扫描线程。"""
        if self.scanning:
            return

        validated, error = get_user_input_and_validate(
            self.url_var.get(), self.level_var.get(), self.custom_config
        )
        if error:
            messagebox.showwarning("输入有误", error, parent=self)
            self.url_entry.focus_set()
            return

        target = validated["target"]
        level = validated["level"]
        # 自定义档位使用对话框保存的参数，固定档位从 INTENSITY_LEVELS 读取
        level_config = validated["config"]
        active_config = level_config if level_config is not None \
            else INTENSITY_LEVELS[level]
        # 是否开启“持续扫描”：勾选后由后台线程循环执行，直到用户停止
        continuous = bool(self.continuous_var.get())
        # 是否开启“超强力扫描”：子窗口数量无上限
        ultra = bool(self.ultra_var.get()) if self.child_payload is None \
            else False

        # URL 校验通过后，回填规范化结果，方便用户看到实际扫描地址
        self.url_var.set(target)
        self.url_entry.configure(foreground=COLOR_TEXT)

        level_label = level
        if level == CUSTOM_INTENSITY:
            level_label = "%s（%s）" % (level, describe_config(active_config))

        dialog = AuthorizeDialog(self, target, level_label)
        if not dialog.result:
            self.status_var.set("已取消（未确认授权）")
            return

        # 超强力扫描：先校验窗口数量，数量非法则不开始整个扫描
        ultra_count = 0
        if ultra:
            ultra_count, ultra_error = self._parse_ultra_count()
            if ultra_error:
                messagebox.showwarning("参数有误", ultra_error, parent=self)
                return

        # 记录本次确认过的参数，供“一键打开”和子窗口继承使用
        self._active_payload = self._build_child_payload(
            target, level, level_config, continuous
        )

        # 重置运行状态
        self.progress.configure(value=0)
        self.elapsed_var.set("用时：00:00")
        self._set_stage("准备中")
        self._set_scanning_state(True)

        self.message_queue = queue.Queue()
        self.stop_event = threading.Event()
        self._scan_start = time.monotonic()
        self._poll_active = True

        self.append_log("系统", "=" * 30)
        self.append_log("系统", "开始扫描：%s（强度：%s）" % (target, level))
        self.append_log("信息", "本次参数：%s。" % describe_config(active_config))
        if continuous:
            self.append_log("系统", "持续扫描已开启：将持续循环，直到点击“停止扫描”。")
        if ultra:
            self.append_log(
                "系统",
                "超强力扫描已开启：将打开 %s 个相同参数的子扫描窗口。"
                % ultra_count,
            )

        self.worker = threading.Thread(
            target=self._scan_worker,
            args=(target, level, level_config, continuous),
            name="scan-worker",
            daemon=True,
        )
        self.worker.start()

        # 超强力扫描：在主窗口开始扫描的同时打开子窗口
        if ultra:
            self._spawn_child_windows(ultra_count)

        self._tick_timer()
        self.after(80, self._poll_messages)

    def _scan_worker(self, target, level, level_config, continuous=False):
        """后台线程：执行扫描，只通过消息队列与界面通信。

        continuous=True 时进入持续扫描模式：每轮结束后自动开始下一轮，
        直到用户点击“停止扫描”（设置 stop_event）才退出。
        """
        try:
            report, stopped = run_scan(
                target, level, self.message_queue, self.stop_event,
                level_config=level_config,
                continuous=continuous,
            )
            self.message_queue.put(("done", report, stopped))
        except Exception:
            self.message_queue.put(("error", traceback.format_exc()))

    # ------------------------------------------------------------------
    # 消息队列轮询
    # ------------------------------------------------------------------
    def _poll_messages(self):
        """在主线程中消费后台线程的消息，刷新界面。"""
        if not self._poll_active:
            return

        try:
            while True:
                message = self.message_queue.get_nowait()
                kind = message[0]

                if kind == "log":
                    self.append_log(message[1], message[2])
                elif kind == "progress":
                    self.progress.configure(value=max(0, min(100, message[1])))
                elif kind == "stage":
                    self._set_stage(message[1])
                elif kind == "done":
                    self._poll_active = False
                    self._finish_scan(message[1], message[2])
                    return
                elif kind == "error":
                    self._poll_active = False
                    self._handle_worker_error(message[1])
                    return
        except queue.Empty:
            pass

        if self._poll_active:
            self.after(80, self._poll_messages)

    def _finish_scan(self, report_text, stopped):
        """扫描结束后的界面收尾工作，并弹出报告预览。"""
        self._set_scanning_state(False)
        if self._timer_job is not None:
            self.after_cancel(self._timer_job)
            self._timer_job = None

        elapsed = int(time.monotonic() - self._scan_start)
        self.elapsed_var.set(
            "用时：%02d:%02d" % (elapsed // 60, elapsed % 60)
        )

        if stopped:
            self._set_stage("已停止")
            self.status_var.set("扫描已停止")
            # 保留停止时的阶段进度，方便判断扫描进行到哪里
        else:
            self._set_stage("完成")
            self.status_var.set("扫描完成")
            self.progress.configure(value=100)

        self.worker = None
        self._show_report(report_text, stopped)

    def _handle_worker_error(self, detail):
        """后台线程出现未预期异常时的处理。"""
        self._set_scanning_state(False)
        if self._timer_job is not None:
            self.after_cancel(self._timer_job)
            self._timer_job = None
        self._set_stage("出错")
        self.status_var.set("扫描出错")
        self.append_log("风险", "扫描过程出现异常，已中止。")
        for line in detail.strip().splitlines()[-6:]:
            self.append_log("风险", line)
        messagebox.showerror(
            "扫描出错",
            "扫描过程中出现异常，详情见日志区。\n\n%s"
            % detail.strip().splitlines()[-1],
            parent=self,
        )

    def _show_report(self, report_text, stopped):
        """打开报告预览窗口（同一时间只保留一个）。"""
        if self._report_window is not None:
            try:
                exists = self._report_window.winfo_exists()
            except (tk.TclError, AttributeError):
                exists = False
            if exists:
                self._report_window.destroy()
        self._report_window = ReportWindow(
            self,
            report_text,
            self.url_var.get(),
            stopped,
        )

    # ------------------------------------------------------------------
    # 停止与关闭
    # ------------------------------------------------------------------
    def _stop_scan(self):
        """设置停止标志，让后台线程在下一个检查点退出。

        同时关闭“超强力扫描”打开的子扫描窗口（停止 = 全部停止）。
        """
        if not self.scanning or self.stop_event is None:
            return
        self.stop_event.set()
        self.stop_button.state(["disabled"])
        self.status_var.set("正在停止…")
        self.append_log("警告", "已请求停止扫描，等待当前请求结束…")
        if self.child_payload is None and self._children:
            closed = self._terminate_children()
            if closed:
                self.append_log(
                    "系统", "已同步关闭 %s 个子扫描窗口。" % closed
                )
            self._update_ultra_status()

    def _on_close(self):
        """关闭窗口；扫描进行中先确认，并关闭全部子扫描窗口。"""
        if self.scanning:
            if not messagebox.askyesno(
                "确认退出",
                "扫描仍在进行中，退出将中止扫描。\n是否确定退出？",
                parent=self,
            ):
                return
            if self.stop_event is not None:
                self.stop_event.set()
        # 主窗口关闭时一并结束子窗口，避免留下无人管理的扫描进程
        if self.child_payload is None:
            self._terminate_children()
        self.destroy()


def parse_argv(argv=None):
    """
    解析命令行参数，返回子窗口参数字典（普通启动返回 None）。

    用法：
        WebSecurityScanner.exe --child-scan=<base64(json)>
    该参数由“超强力扫描”在派生子窗口时自动附加，普通用户无需使用。
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    for item in argv:
        if item.startswith(CHILD_ARG_PREFIX):
            return decode_child_payload(item[len(CHILD_ARG_PREFIX):])
    return None


def main():
    """程序入口，便于被打包工具调用。"""
    app = ScannerApp(child_payload=parse_argv())
    app.mainloop()


if __name__ == "__main__":
    main()
