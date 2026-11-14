# -*- coding: utf-8 -*-
"""
websectool
==========

Web 安全测试工具的内部包。

模块划分：
    config.py   配置模块：INTENSITY_LEVELS 强度档位、payload、特征库
    scanner.py  扫描模块：HTTP 请求、端口/目录/表单检测、报告生成
    gui.py      界面模块：主窗口、授权确认、报告预览、输入校验

本包只依赖 Python 标准库，便于使用 PyInstaller 打包为单个可执行文件。
"""

__version__ = "1.1.0"
__all__ = ["config", "scanner", "gui"]
