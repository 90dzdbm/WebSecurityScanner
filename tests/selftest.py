# -*- coding: utf-8 -*-
"""
自检脚本（开发用）
==================

启动本地靶场，验证扫描模块与界面模块的基本功能：

    python tests/selftest.py

检查内容：
  1. URL 规范化与校验
  2. 自定义档位参数的解析与校验（不再限制为 5 线程）
  3. 信息收集 / 目录探测 / 表单检测能发现靶场中的测试场景
  4. 端口扫描能识别开放端口
  5. 停止标志能让扫描安全退出并生成不完整报告
  6. 使用自定义参数的扫描能正常完成并在报告中标注
  7. 持续扫描模式会循环执行多轮，并可被主动停止
  8. 主窗口能够正常创建
"""

import os
import queue
import re
import sys
import threading
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.join(PROJECT_ROOT, "tests")
for path in (PROJECT_ROOT, TESTS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

from lab_server import serve  # noqa: E402
from websectool.scanner import run_scan, scan_ports  # noqa: E402


def check(condition, description):
    status = "通过" if condition else "失败"
    print("[%s] %s" % (status, description))
    if not condition:
        check.failures.append(description)


check.failures = []


def test_normalize_target():
    from websectool.gui import normalize_target, get_user_input_and_validate

    cases = [
        ("127.0.0.1:8765", "http://127.0.0.1:8765/"),
        ("example.com/path?a=1", "http://example.com/path?a=1"),
        ("https://example.com/x#frag", "https://example.com/x"),
        ("  http://example.com  ", "http://example.com/"),
    ]
    for raw, expected in cases:
        try:
            actual = normalize_target(raw)
        except ValueError as exc:
            actual = "错误：%s" % exc
        check(actual == expected, "URL 规范化 %r -> %s" % (raw, actual))

    bad_values = ["", "   ", "http://", "ftp://example.com",
                  "http://exa mple.com", "http://host:99999"]
    for raw in bad_values:
        try:
            normalize_target(raw)
            rejected = False
        except ValueError:
            rejected = True
        check(rejected, "非法输入被拒绝：%r" % raw)

    config, error = get_user_input_and_validate("example.com", "中强度")
    check(config is not None and not error and config["target"] ==
          "http://example.com/", "独立校验函数返回有效配置")
    config, error = get_user_input_and_validate("example.com", "不存在的档位")
    check(config is None and bool(error), "非法强度被拒绝")


def test_custom_config():
    """校验“自定义”档位参数的解析与范围限制。"""
    from websectool.config import (DEFAULT_CUSTOM_CONFIG,
                                   custom_config_to_text,
                                   normalize_custom_config)

    # 用 chr(10) 构造多行路径文本，避免源码中的转义歧义
    paths_text = "admin" + chr(10) + "/login" + chr(10) + chr(10) \
        + "# 注释行" + chr(10)
    raw = {
        "delay": "0.2", "threads": "3", "timeout": "2.5", "retries": "0",
        "max_forms": "3", "max_fields_per_form": "2",
        "ports": "80, 443 8080；8080",
        "paths": paths_text,
    }
    config, error = normalize_custom_config(raw)
    check(config is not None and not error, "自定义参数校验通过")
    if config:
        check(config["delay"] == 0.2 and config["threads"] == 3,
              "自定义数值参数解析正确：delay=%s threads=%s"
              % (config["delay"], config["threads"]))
        check(config["ports"] == [80, 443, 8080],
              "端口支持多种分隔符并去重：%s" % config["ports"])
        check(config["paths"] == ["/admin", "/login"],
              "路径自动补 / 并忽略空行与注释：%s" % config["paths"])

    # 默认自定义参数经 custom_config_to_text 转换后应能原样通过校验
    default_config, error = normalize_custom_config(
        custom_config_to_text(DEFAULT_CUSTOM_CONFIG))
    check(default_config is not None and not error
          and default_config["ports"] == DEFAULT_CUSTOM_CONFIG["ports"]
          and default_config["paths"] == DEFAULT_CUSTOM_CONFIG["paths"],
          "默认自定义参数可原样回填并通过校验")

    # 并发线程数已去掉 5 线程的安全限制，只保留 THREADS_LIMIT 上限
    high_threads, high_error = normalize_custom_config(
        dict(raw, threads="16"))
    check(high_threads is not None and not high_error
          and high_threads["threads"] == 16,
          "并发线程数可以超过 5：threads=16")
    too_many, too_many_error = normalize_custom_config(
        dict(raw, threads="201"))
    check(too_many is None and bool(too_many_error),
          "并发线程数超过 THREADS_LIMIT 被拒绝：threads=201")

    # 越界/非法参数必须被拒绝
    bad_cases = [("threads", "0"), ("delay", "abc"),
                 ("timeout", "0.1"), ("ports", "0"), ("ports", "70000"),
                 ("ports", ""), ("paths", ""), ("retries", "9")]
    for key, value in bad_cases:
        broken = dict(raw)
        broken[key] = value
        cfg, err = normalize_custom_config(broken)
        check(cfg is None and bool(err),
              "非法自定义参数被拒绝：%s=%r" % (key, value))


def test_scan(port):
    target = "http://127.0.0.1:%s/" % port
    messages = queue.Queue()
    stop_event = threading.Event()

    started = time.monotonic()
    report, stopped = run_scan(target, "中强度", messages, stop_event)
    elapsed = time.monotonic() - started

    logs = []
    stages = []
    progress_values = []
    while not messages.empty():
        message = messages.get_nowait()
        if message[0] == "log":
            logs.append(message[2])
        elif message[0] == "stage":
            stages.append(message[1])
        elif message[0] == "progress":
            progress_values.append(message[1])

    check(not stopped, "完整扫描正常结束（耗时 %.1f 秒）" % elapsed)
    check("信息收集" in stages and "报告输出" in stages,
          "五个阶段依次执行：%s" % "、".join(stages))
    check(progress_values and max(progress_values) == 100,
          "进度条最终到达 100%")

    text = "\n".join(logs)
    check("授权测试靶场" in text, "信息收集提取到页面标题")
    check("开放端口" in text or "未检测到开放端口" in text,
          "端口扫描阶段有输出")
    check("/admin/" in text or "/backup.zip" in text,
          "目录探测发现可访问路径")
    check("疑似 SQL 注入" in report, "检测到 SQL 注入迹象")
    check("疑似反射型 XSS" in report, "检测到反射型 XSS 迹象")
    check("扫描强度   ：中强度" in report, "报告包含扫描强度")
    check("目标 URL" in report and target in report, "报告包含目标 URL")
    check("风险汇总" in report, "报告包含风险汇总")

    # 端口扫描：靶场端口应开放，未监听的端口应关闭
    open_ports = scan_ports(
        "127.0.0.1", [port, 1], timeout=0.5, threads=2,
        stop_event=threading.Event(),
    )
    check(port in open_ports and 1 not in open_ports,
          "端口扫描正确识别开放/关闭端口：%s" % open_ports)


def test_custom_scan(port):
    """使用“自定义”档位参数执行一次完整扫描。"""
    from websectool.config import CUSTOM_INTENSITY

    target = "http://127.0.0.1:%s/" % port
    custom = {
        "delay": 0.05, "threads": 2, "timeout": 2.0, "retries": 0,
        "max_forms": 2, "max_fields_per_form": 2,
        "ports": [port], "paths": ["/admin/", "/robots.txt"],
    }
    messages = queue.Queue()
    report, stopped = run_scan(target, CUSTOM_INTENSITY, messages,
                               threading.Event(), level_config=custom)

    check(not stopped, "自定义参数扫描正常结束")
    check("扫描强度   ：自定义" in report, "报告标注自定义档位")
    check("参数来源   ：用户自定义" in report, "报告标注参数来源为自定义")
    check("/admin/" in report, "使用自定义路径字典进行探测")
    check("并发 2" in report and "重试 0 次" in report,
          "报告包含自定义参数数值")


def test_stop(port):
    target = "http://127.0.0.1:%s/" % port
    messages = queue.Queue()
    stop_event = threading.Event()
    result = {}

    def worker():
        result["value"] = run_scan(target, "低强度", messages, stop_event)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    time.sleep(1.2)
    stop_event.set()
    thread.join(timeout=20)

    report, stopped = result.get("value", ("", False))
    logs = []
    while not messages.empty():
        message = messages.get_nowait()
        if message[0] == "log":
            logs.append(message[2])

    check(stopped, "停止标志使扫描安全退出")
    check(any("扫描已停止" in line for line in logs), "日志提示“扫描已停止”")
    check("已停止" in report, "停止后仍生成部分报告")


def test_ultra_payload():
    """超强力扫描：子窗口参数编码/解码与命令行构造。"""
    from websectool.gui import (CHILD_ARG_PREFIX, child_command_prefix,
                                decode_child_payload,
                                encode_child_payload)

    payload = {
        "target": "http://127.0.0.1:8765/",
        "level": "自定义",
        "config": {"delay": 0.05, "threads": 8, "timeout": 2.0,
                   "retries": 0, "max_forms": 2, "max_fields_per_form": 2,
                   "ports": [8765], "paths": ["/admin/"]},
        "continuous": True,
    }
    encoded = encode_child_payload(payload)
    decoded = decode_child_payload(encoded)
    check(decoded == payload, "子窗口参数 base64 编码可无损还原")
    check(decode_child_payload("not-base64!!") is None,
          "损坏的参数编码被拒绝")
    check(decode_child_payload(encode_child_payload({"no_target": 1})) is None,
          "缺少 target 的参数字典被拒绝")

    prefix = child_command_prefix()
    check(isinstance(prefix, list) and prefix
          and all(isinstance(item, str) for item in prefix),
          "子窗口命令行前缀有效：%s" % prefix)
    check(len(prefix) == 2 and prefix[1].endswith("main.py")
          and os.path.exists(prefix[1]),
          "源码模式下子窗口命令行指向项目 main.py")
    command = prefix + [CHILD_ARG_PREFIX + encoded]
    check(command[-1].startswith(CHILD_ARG_PREFIX),
          "完整命令行包含 --child-scan= 参数")


def test_continuous_scan(port):
    """持续扫描：多轮循环执行，并在主动停止后汇总为一份报告。"""
    from websectool.config import CUSTOM_INTENSITY, THREADS_LIMIT

    target = "http://127.0.0.1:%s/" % port
    # 用小字典 + 无间隔，让每一轮很快结束，便于观察多轮循环
    custom = {
        "delay": 0.0, "threads": 4, "timeout": 2.0, "retries": 0,
        "max_forms": 2, "max_fields_per_form": 2,
        "ports": [port], "paths": ["/robots.txt"],
    }
    messages = queue.Queue()
    stop_event = threading.Event()
    result = {}

    def worker():
        result["value"] = run_scan(
            target, CUSTOM_INTENSITY, messages, stop_event,
            level_config=custom, continuous=True,
        )

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    # 持续扫描会一直循环，这里等几秒后主动停止（模拟点击“停止扫描”）
    time.sleep(6.0)
    stop_event.set()
    thread.join(timeout=60)

    report, stopped = result.get("value", ("", False))
    logs = []
    stages = []
    while not messages.empty():
        message = messages.get_nowait()
        if message[0] == "log":
            logs.append(message[2])
        elif message[0] == "stage":
            stages.append(message[1])

    check(stopped, "持续扫描在主动停止后退出")
    check("持续扫描" in report, "报告标注为持续扫描模式")
    match = re.search(r"完成轮次\s*：\s*(\d+)\s*轮", report)
    rounds = int(match.group(1)) if match else 0
    check(rounds >= 2, "主动停止前持续循环了多轮：%s 轮" % rounds)
    check(any(str(name).startswith("第 2 轮") for name in stages),
          "第二轮阶段名称带轮次前缀")
    check("累计风险" in report, "持续扫描报告包含累计风险统计")
    check(THREADS_LIMIT >= 200,
          "线程上限已放宽（不再限制为 5）：THREADS_LIMIT=%s" % THREADS_LIMIT)


def test_gui():
    try:
        import tkinter as tk
        from websectool.gui import ScannerApp, CUSTOM_INTENSITY

        app = ScannerApp()
        app.update_idletasks()
        app.update()
        title = app.title()
        size = (app.winfo_width(), app.winfo_height())
        hint = app.level_hint.cget("text")
        custom_disabled = app.custom_button.instate(["disabled"])
        app.level_var.set(CUSTOM_INTENSITY)
        app.update()
        custom_enabled = app.custom_button.instate(["!disabled"])
        custom_hint = app.level_hint.cget("text")
        continuous_enabled = app.continuous_check.instate(["!disabled"])
        continuous_default = bool(app.continuous_var.get())
        ultra_exists = hasattr(app, "ultra_check")
        app.destroy()

        # 子窗口不应有超强力扫描行（防止无限派生孙窗口）
        child = ScannerApp(child_payload={
            "target": "http://127.0.0.1:1/", "level": "低强度",
            "config": None, "continuous": False,
        })
        child_exists = hasattr(child, "ultra_check")
        child.destroy()
        check(title == "Web 安全测试工具", "窗口标题正确：%s" % title)
        check(size[0] >= 720 and size[1] >= 520,
              "窗口尺寸合理：%sx%s" % size)
        check("并发" in hint, "强度参数提示正常显示")
        check(custom_disabled, "非自定义档位时“自定义参数”按钮禁用")
        check(custom_enabled, "选择自定义档位后“自定义参数”按钮启用")
        check(continuous_enabled, "持续扫描开关在就绪状态下可用")
        check(not continuous_default, "持续扫描开关默认为关闭")
        check(ultra_exists, "主窗口包含超强力扫描控制行")
        check(not child_exists, "子窗口不再显示超强力扫描行（防止无限派生）")
        check(custom_hint.startswith("自定义参数："),
              "自定义档位显示参数提示：%s" % custom_hint)
    except tk.TclError as exc:
        print("[跳过] 无图形环境，跳过界面测试：%s" % exc)


def main():
    server, _thread = serve(0)
    port = server.server_address[1]
    print("本地靶场端口：%s\n" % port)
    try:
        test_normalize_target()
        test_custom_config()
        test_scan(port)
        test_custom_scan(port)
        test_ultra_payload()
        test_continuous_scan(port)
        test_stop(port)
        test_gui()
    finally:
        server.shutdown()
        server.server_close()

    print("\n结果：%s" % (
        "全部通过" if not check.failures
        else "%s 项失败：%s" % (len(check.failures),
                               "；".join(check.failures))
    ))
    return 0 if not check.failures else 1


if __name__ == "__main__":
    sys.exit(main())
