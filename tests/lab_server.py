# -*- coding: utf-8 -*-
"""
本地测试靶场（仅用于验证本工具自身功能）
==========================================

只监听 127.0.0.1 的回环地址，不对外网开放。包含：

  * 首页：标题、链接、GET 表单、POST 表单
  * /admin/、/backup.zip、/robots.txt 等可访问路径
  * /search：把查询参数原样反射到页面（用于验证 XSS 迹象检测）
  * /login：用户名包含单引号时返回数据库错误特征（用于验证 SQL 注入迹象检测）
  * 其他路径返回 404

运行：
    python tests/lab_server.py [端口]
默认端口 8765。
"""

import html
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_PORT = 8765

INDEX_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>授权测试靶场</title></head>
<body>
  <h1>Web 安全测试本地靶场</h1>
  <p>仅用于验证扫描工具的功能，请勿用于其他用途。</p>
  <ul>
    <li><a href="/admin/">管理后台</a></li>
    <li><a href="/backup.zip">备份文件</a></li>
    <li><a href="/missing-page">不存在的页面</a></li>
  </ul>
  <h2>登录</h2>
  <form action="/login" method="post">
    <input name="username" value="admin">
    <input name="password" type="password" value="">
    <input type="submit" value="登录">
  </form>
  <h2>搜索</h2>
  <form action="/search" method="get">
    <input name="q" value="">
    <button type="submit">搜索</button>
  </form>
</body>
</html>
"""


class LabHandler(BaseHTTPRequestHandler):
    """极简的测试服务，故意保留一些不安全的响应行为。"""

    server_version = "LabServer/1.0"
    sys_version = ""

    # -- 工具方法 -------------------------------------------------------
    def _send(self, status, body, content_type="text/html; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Lab-Server", "local-test-only")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        # 减少测试时的控制台噪音
        sys.stderr.write("[lab] %s\n" % (fmt % args))

    # -- 路由 -----------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self._send(200, INDEX_HTML)
        elif path == "/admin/" or path == "/admin":
            self._send(200, "<html><title>管理后台</title><h1>后台</h1></html>")
        elif path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin/\n",
                       "text/plain; charset=utf-8")
        elif path == "/backup.zip":
            self._send(200, b"PK\x03\x04fake-backup-for-lab", "application/zip")
        elif path == "/login":
            self._send(200, "<html><title>登录</title><p>请使用 POST 登录。</p></html>")
        elif path == "/search":
            query = urllib.parse.parse_qs(parsed.query)
            keyword = query.get("q", [""])[0]
            # 故意原样反射，用于验证 XSS 反射迹象
            self._send(
                200,
                "<html><title>搜索结果</title><p>关键词：%s</p></html>" % keyword,
            )
        else:
            self._send(404, "<html><title>404</title><h1>Not Found</h1></html>")

    def do_POST(self):
        if urllib.parse.urlsplit(self.path).path != "/login":
            self._send(404, "<html><h1>Not Found</h1></html>")
            return

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        form = urllib.parse.parse_qs(raw)
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]

        if "'" in username or "'" in password:
            # 模拟数据库报错，用于验证 SQL 注入迹象检测
            self._send(
                500,
                "<html><title>登录错误</title><h1>Database Error</h1>"
                "<p>You have an error in your SQL syntax; "
                "check the manual that corresponds to your MySQL server "
                "version for the right syntax to use near ''' at line 1</p>"
                "</html>",
            )
        elif "<script>" in username or "<script>" in password:
            # 故意原样反射，用于验证 XSS 反射迹象检测
            self._send(
                200,
                "<html><title>登录结果</title><p>用户：%s</p></html>" % username,
            )
        else:
            self._send(
                200,
                "<html><title>登录结果</title>"
                "<p>登录失败：用户 %s 不存在。</p></html>"
                % html.escape(username),
            )


def serve(port=DEFAULT_PORT):
    """启动测试服务；返回 (server, thread)。port 为 0 时由系统分配。"""
    import threading

    server = ThreadingHTTPServer(("127.0.0.1", port), LabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def main():
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print("端口必须是整数。")
            return 1

    server, _thread = serve(port)
    print("本地测试靶场已启动：http://127.0.0.1:%s" % server.server_address[1])
    print("按 Ctrl+C 停止。")
    try:
        while True:
            import time

            time.sleep(1)
    except KeyboardInterrupt:
        print("\n正在停止…")
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
