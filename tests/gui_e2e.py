# -*- coding: utf-8 -*-
"""
界面端到端自检（开发用）
========================

用真实的 ScannerApp 走完整流程：
    校验输入 -> （自动确认授权）-> 后台线程扫描 -> 队列刷新界面 -> 报告回调

不弹出真实对话框，便于自动化验证线程/队列/界面刷新逻辑。

    python tests/gui_e2e.py
"""

import os
import re
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.join(PROJECT_ROOT, "tests")
for path in (PROJECT_ROOT, TESTS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

from lab_server import serve  # noqa: E402
from websectool import gui  # noqa: E402

captured = {}


class FakeAuthorizeDialog(object):
    """自动返回“已授权”，替代真实对话框。"""

    def __init__(self, parent, target, level):
        self.result = True


class FakeReportWindow(object):
    """记录报告内容，替代真实报告窗口。"""

    def __init__(self, parent, report_text, target, stopped):
        captured["report"] = report_text
        captured["target"] = target
        captured["stopped"] = stopped


class FakeCustomParamsDialog(object):
    """自动返回一份修改过的配置，替代真实的“自定义参数”对话框。"""

    def __init__(self, parent, config):
        updated = dict(config)
        updated["threads"] = 1
        self.result = updated


def pump(app, timeout, condition):
    """阻塞刷新界面事件，直到条件满足或超时。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        app.update()
        if condition():
            return True
        time.sleep(0.03)
    return False


def main():
    gui.AuthorizeDialog = FakeAuthorizeDialog
    gui.ReportWindow = FakeReportWindow
    gui.CustomParamsDialog = FakeCustomParamsDialog

    server, _thread = serve(0)
    port = server.server_address[1]
    target = "127.0.0.1:%s" % port
    print("靶场：http://%s" % target)

    app = gui.ScannerApp()
    failures = []

    def check(condition, description):
        print("[%s] %s" % ("通过" if condition else "失败", description))
        if not condition:
            failures.append(description)

    try:
        # ---- 第一次：完整扫描 ----
        app.url_var.set(target)
        app.level_var.set("高强度")
        app._start_scan()

        finished = pump(
            app, 60,
            lambda: (not app.scanning) and "report" in captured,
        )
        check(finished, "界面流程在超时前完成")
        check(app.progress.cget("value") == 100, "进度条到达 100")
        check(app.stage_var.get() == "阶段：完成",
              "状态栏显示完成：%s" % app.stage_var.get())
        log_content = app.log_text.get("1.0", "end")
        check("扫描完成" in log_content, "日志包含完成提示")
        check("疑似 SQL 注入" in log_content
              or "疑似反射型 XSS" in log_content,
              "日志包含检测到的风险")
        check("疑似 SQL 注入" in captured.get("report", ""),
              "报告包含 SQL 注入迹象")
        check(app.start_button.instate(["!disabled"]),
              "扫描结束后开始按钮恢复可用")
        check(app.stop_button.instate(["disabled"]),
              "扫描结束后停止按钮禁用")

        # ---- 第二次：中途停止 ----
        captured.clear()
        app._start_scan()
        pump(app, 5, lambda: app.scanning)
        time.sleep(0.6)
        app.update()
        app._stop_scan()
        stopped_ok = pump(
            app, 30,
            lambda: (not app.scanning) and "report" in captured,
        )
        check(stopped_ok, "停止后界面流程正常收尾")
        check(app.stage_var.get() == "阶段：已停止",
              "停止后状态栏显示已停止：%s" % app.stage_var.get())
        log_content = app.log_text.get("1.0", "end")
        check("扫描已停止" in log_content, "日志提示“扫描已停止”")
        check("已停止" in captured.get("report", ""),
              "停止后的报告标注已停止")

        # ---- 第三次：自定义参数对话框 + 自定义档位扫描 ----
        captured.clear()
        app.level_var.set(gui.CUSTOM_INTENSITY)
        app.update()
        check(app.custom_button.instate(["!disabled"]),
              "选择自定义档位后“自定义参数”按钮启用")

        app._open_custom_params()
        app.update()
        check(app.custom_config["threads"] == 1,
              "对话框返回的配置已保存到界面")
        log_content = app.log_text.get("1.0", "end")
        check("已更新自定义参数" in log_content, "日志提示自定义参数已更新")

        # 换成便于快速完成的小配置，缩短端到端测试时间
        app.custom_config = {
            "delay": 0.05, "threads": 2, "timeout": 2.0, "retries": 0,
            "max_forms": 2, "max_fields_per_form": 2,
            "ports": [port], "paths": ["/admin/"],
        }
        app._start_scan()
        custom_ok = pump(
            app, 60,
            lambda: (not app.scanning) and "report" in captured,
        )
        check(custom_ok, "自定义档位扫描在超时前完成")
        check(app.progress.cget("value") == 100, "自定义扫描进度到达 100")
        check("扫描强度   ：自定义" in captured.get("report", ""),
              "报告标注自定义档位")
        check("参数来源   ：用户自定义" in captured.get("report", ""),
              "报告标注参数来源为自定义")

        # ---- 第四次：持续扫描（勾选开关，多轮后主动停止）----
        captured.clear()
        # 用很小的自定义配置让每轮都很快结束，便于观察多轮循环
        app.custom_config = {
            "delay": 0.05, "threads": 2, "timeout": 2.0, "retries": 0,
            "max_forms": 2, "max_fields_per_form": 2,
            "ports": [port], "paths": ["/robots.txt"],
        }
        app.continuous_var.set(True)
        app.update()
        check(app.continuous_check.instate(["!disabled"]),
              "就绪状态下可以勾选持续扫描")
        app._start_scan()
        pump(app, 5, lambda: app.scanning)
        time.sleep(6.0)
        app.update()
        check(app.continuous_check.instate(["disabled"]),
              "扫描过程中持续扫描开关被禁用")
        app._stop_scan()
        continuous_ok = pump(
            app, 60,
            lambda: (not app.scanning) and "report" in captured,
        )
        check(continuous_ok, "持续扫描停止后界面正常收尾")
        report_text = captured.get("report", "")
        check("持续扫描" in report_text, "报告标注为持续扫描模式")
        match = re.search(r"完成轮次\s*：\s*(\d+)\s*轮", report_text)
        rounds = int(match.group(1)) if match else 0
        check(rounds >= 2, "主动停止前完成了多轮扫描：%s 轮" % rounds)
        check(app.continuous_check.instate(["!disabled"]),
              "停止后持续扫描开关恢复可用")
        app.continuous_var.set(False)

        # ---- 第五次：超强力扫描（真实打开/关闭子扫描窗口进程）----
        captured.clear()
        app.custom_config = {
            "delay": 0.05, "threads": 2, "timeout": 2.0, "retries": 0,
            "max_forms": 1, "max_fields_per_form": 1,
            "ports": [port], "paths": ["/robots.txt"],
        }
        app.level_var.set(gui.CUSTOM_INTENSITY)
        app.ultra_count_var.set("2")
        app.update()
        check(hasattr(app, "ultra_check") and app.ultra_check.instate(["!disabled"]),
              "主窗口显示超强力扫描开关且就绪时可用")

        app._one_click_open()
        app.update()
        spawned_ok = pump(
            app, 20, lambda: len(app._children) == 2
            and all(process.poll() is None for process in app._children),
        )
        check(spawned_ok, "一键打开：2 个子扫描窗口进程已启动")

        # 子窗口进程应自动开始扫描（等靶场日志出现来自子窗口的请求）
        time.sleep(4.0)
        app.update()
        log_content = app.log_text.get("1.0", "end")
        check("已打开 2 个相同参数的子扫描窗口" in log_content,
              "日志提示已打开子窗口")

        # 扫描中点“开始扫描”会按数量再开子窗口；这里直接测试一键关闭
        app._one_click_close()
        app.update()
        closed_ok = pump(
            app, 20, lambda: len(app._children) == 0,
        )
        check(closed_ok, "一键关闭：全部子扫描窗口进程已退出")
        log_content = app.log_text.get("1.0", "end")
        check("已一键关闭 2 个子扫描窗口" in log_content,
              "日志提示已一键关闭")
        check("子窗口：0 个运行中" in app.ultra_status_var.get(),
              "子窗口计数已清零：%s" % app.ultra_status_var.get())

        # 数量输入校验
        app.ultra_count_var.set("abc")
        count, error = app._parse_ultra_count()
        check(count is None and bool(error), "非整数窗口数量被拒绝")
        app.ultra_count_var.set("0")
        count, error = app._parse_ultra_count()
        check(count is None and bool(error), "窗口数量 0 被拒绝")
        app.ultra_count_var.set("9999")
        count, error = app._parse_ultra_count()
        check(count == 9999 and not error, "窗口数量无上限（9999 被接受）")
    finally:
        # 无论测试是否通过，都清理掉派生出的子扫描窗口进程
        try:
            app._terminate_children()
        except Exception:
            pass
        if app.winfo_exists():
            app.destroy()
        server.shutdown()
        server.server_close()

    print("\n结果：%s" % (
        "全部通过" if not failures
        else "%s 项失败：%s" % (len(failures), "；".join(failures))
    ))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
