# -*- coding: utf-8 -*-
"""
Web 安全测试工具 —— 程序入口
=============================

请先阅读 README.md 并确认您拥有目标系统的测试授权。

运行方式（源码）：
    python main.py

打包为单个 exe（Windows）：
    pip install pyinstaller
    pyinstaller --onefile --windowed --name WebSecurityScanner main.py

打包结果位于 dist\\WebSecurityScanner.exe，可脱离 Python 环境双击运行。
"""

import sys
import traceback


def _enable_high_dpi():
    """
    在 Windows 上开启 DPI 感知，避免高分屏下界面模糊。
    非 Windows 平台或调用失败时静默忽略。
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes

        try:
            # Windows 8.1+：按显示器 DPI 感知
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def _report_fatal_error(message):
    """打包为 --windowed 后没有控制台，用对话框报告启动错误。"""
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("启动失败", message)
        root.destroy()
    except Exception:
        # 连对话框都无法显示时，退化为标准错误输出
        sys.stderr.write(message + "\n")


def main():
    _enable_high_dpi()

    try:
        # 延迟导入，确保导入阶段的异常也能被捕获并提示
        from websectool.gui import ScannerApp, parse_argv

        # 解析 --child-scan= 参数：存在时本进程是“超强力扫描”派生的子窗口
        app = ScannerApp(child_payload=parse_argv())
        app.mainloop()
    except Exception:
        _report_fatal_error(
            "程序启动失败，请检查运行环境。\n\n%s"
            % traceback.format_exc(limit=3)
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
