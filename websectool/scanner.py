# -*- coding: utf-8 -*-
"""
扫描模块
========

包含：
  * HTTP 请求封装（超时、重试、忽略自签名证书）
  * HTML 解析（标题 / 链接 / 表单）
  * TCP 端口探测
  * 目录探测（线程池 + 请求间隔 + 软 404 过滤）
  * 表单 SQL 注入 / XSS 初步迹象检测（无害 payload）
  * 扫描主流程 run_scan() 与文本报告生成 build_report()
  * 持续扫描模式：每轮结束后自动开始下一轮，直到用户主动停止

扫描过程通过 queue.Queue 与界面通信，不直接操作任何 tkinter 控件：
    ("log", "信息"/"警告"/"风险"/"系统", 文本)
    ("progress", 0-100 的整数)
    ("stage", 阶段名称)
扫描结束后由界面线程负责显示报告。
"""

import html.parser
import http.client
import http.cookiejar
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from .config import (
    AGGRESSIVE_MARKER,
    AGGRESSIVE_PAYLOADS,
    AGGRESSIVE_TIME_SLEEP,
    AGGRESSIVE_TIME_THRESHOLD,
    INTENSITY_LEVELS,
    PAYLOADS,
    SENSITIVE_PATH_KEYWORDS,
    SKIP_INPUT_TYPES,
    SQL_ERROR_PATTERNS,
    USER_AGENT,
)

# 单个响应最多读取的字节数，避免超大页面占满内存
MAX_BODY_BYTES = 2 * 1024 * 1024

# 失败重试时的退避基数（秒）
RETRY_BACKOFF = 0.4

# 安全测试环境经常使用自签名证书，这里不做证书校验。
# 如果目标对证书有严格要求，可以改回默认的 ssl.create_default_context()。
_SSL_CONTEXT = ssl.create_default_context()
_SSL_CONTEXT.check_hostname = False
_SSL_CONTEXT.verify_mode = ssl.CERT_NONE


class ScanStopped(Exception):
    """用户点击“停止扫描”后，在检查点抛出，用于安全退出。"""


class RequestFailed(Exception):
    """HTTP 请求在重试后仍然失败。"""


class HttpResponse(object):
    """简化后的 HTTP 响应对象。"""

    __slots__ = ("status", "headers", "body", "url")

    def __init__(self, status, headers, body, url):
        self.status = status
        self.headers = headers
        self.body = body
        self.url = url


def build_opener():
    """创建一个带 Cookie 处理的 opener，用于需要保持会话的请求。"""
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=_SSL_CONTEXT),
    )
    opener.addheaders = [
        ("User-Agent", USER_AGENT),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8"),
    ]
    return opener


def _read_response(resp):
    """读取并关闭响应，统一转换为 HttpResponse。"""
    try:
        raw = resp.read(MAX_BODY_BYTES)
        status = int(getattr(resp, "status", None) or getattr(resp, "code", 0) or 0)
        headers = dict(resp.headers.items())
        charset = resp.headers.get_content_charset()
        final_url = resp.geturl()
    finally:
        try:
            resp.close()
        except Exception:
            pass

    try:
        body = raw.decode(charset or "utf-8", errors="replace")
    except LookupError:
        body = raw.decode("utf-8", errors="replace")
    return HttpResponse(status, headers, body, final_url)


def fetch(url, method="GET", data=None, timeout=5.0, retries=2,
          opener=None, stop_event=None):
    """
    发起一次 HTTP 请求，带超时与重试。

    参数：
        url       请求地址
        method    GET / POST
        data      POST 的 bytes 请求体；GET 时必须为 None
        retries   失败重试次数（不含首次）
        opener    可选的 opener（需要 Cookie 时传入）
        stop_event 停止标志，如果在重试等待期间被设置则抛 ScanStopped
    返回：
        HttpResponse
    异常：
        ScanStopped / RequestFailed
    """
    method = method.upper()
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

    last_error = None
    for attempt in range(retries + 1):
        if stop_event is not None and stop_event.is_set():
            raise ScanStopped()

        try:
            if opener is not None:
                response = opener.open(req, timeout=timeout)
            else:
                response = urllib.request.urlopen(
                    req, timeout=timeout, context=_SSL_CONTEXT
                )
            return _read_response(response)

        except urllib.error.HTTPError as exc:
            # HTTPError 本身也是一个响应（4xx/5xx），保留状态码和正文
            try:
                return _read_response(exc)
            except Exception as read_error:
                raise RequestFailed("读取错误响应失败：%s" % read_error)

        except (urllib.error.URLError, ssl.SSLError,
                http.client.HTTPException, OSError) as exc:
            last_error = exc
            if attempt < retries:
                wait_seconds = RETRY_BACKOFF * (attempt + 1)
                if stop_event is not None:
                    # 用 wait 代替 sleep，停止时能立即返回
                    if stop_event.wait(wait_seconds):
                        raise ScanStopped()
                else:
                    time.sleep(wait_seconds)

    reason = getattr(last_error, "reason", last_error)
    raise RequestFailed("请求失败：%s" % reason)


def header_value(headers, name):
    """大小写不敏感地读取响应头。"""
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return ""


def _short(text, limit=160):
    """把过长文本压缩成一行，便于写入日志。"""
    value = str(text).replace("\r", " ").replace("\n", " ").strip()
    if len(value) <= limit:
        return value
    return value[:limit] + "…"


class PageParser(html.parser.HTMLParser):
    """
    提取页面标题、链接和表单。

    forms 中每个表单的结构：
        {"action": 原始 action, "method": "get"/"post", "inputs": [
            {"name": 字段名, "type": 字段类型, "value": 默认值}, ...
        ]}
    """

    def __init__(self):
        html.parser.HTMLParser.__init__(self, convert_charrefs=True)
        self.title_parts = []
        self._in_title = False
        self.links = []
        self.forms = []
        self._current_form = None
        self._current_textarea = None
        self._current_select = None
        self._option_uses_text = False

    # -- HTMLParser 回调 -------------------------------------------------
    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)

        if tag == "title":
            self._in_title = True
            return

        if tag in ("a", "area", "link"):
            href = attributes.get("href")
            if href:
                self.links.append(href)
            return

        if tag == "form":
            self._current_form = {
                "action": attributes.get("action", ""),
                "method": (attributes.get("method") or "get").lower(),
                "inputs": [],
            }
            self.forms.append(self._current_form)
            return

        if self._current_form is None:
            return

        if tag == "input":
            name = attributes.get("name")
            if name:
                self._current_form["inputs"].append({
                    "name": name,
                    "type": (attributes.get("type") or "text").lower(),
                    "value": attributes.get("value", ""),
                })
        elif tag == "textarea":
            name = attributes.get("name")
            if name:
                field = {"name": name, "type": "textarea", "value": ""}
                self._current_form["inputs"].append(field)
                self._current_textarea = field
        elif tag == "select":
            name = attributes.get("name")
            if name:
                field = {"name": name, "type": "select", "value": ""}
                self._current_form["inputs"].append(field)
                self._current_select = field
                self._option_uses_text = False
        elif tag == "option" and self._current_select is not None:
            value = attributes.get("value")
            if value is not None:
                self._current_select["value"] = value
            else:
                self._option_uses_text = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._current_form = None
            self._current_textarea = None
            self._current_select = None
        elif tag == "textarea":
            self._current_textarea = None
        elif tag == "select":
            self._current_select = None
        elif tag == "option":
            self._option_uses_text = False

    def handle_data(self, data):
        if self._in_title:
            self.title_parts.append(data)
        elif self._current_textarea is not None:
            self._current_textarea["value"] += data
        elif (self._current_select is not None
              and self._option_uses_text
              and not self._current_select["value"]):
            text = data.strip()
            if text:
                self._current_select["value"] = text

    @property
    def title(self):
        return " ".join("".join(self.title_parts).split())


def _shutdown_pool(pool):
    """尽快关闭线程池；不等待排队任务（运行中的请求受超时约束）。"""
    try:
        pool.shutdown(wait=False, cancel_futures=True)
    except TypeError:  # Python 3.8 没有 cancel_futures 参数
        pool.shutdown(wait=False)


def scan_ports(host, ports, timeout, threads, stop_event, on_progress=None):
    """
    对指定主机的端口做 TCP 连接探测。

    返回：开放端口列表（升序）。
    只判断端口能否建立连接，不发送任何应用层数据。
    """
    # 不再限制为 5 线程：按配置直接使用，仅保证至少 1 个线程
    workers = max(1, int(threads))
    open_ports = []

    def probe(port):
        if stop_event.is_set():
            return None
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port
        except OSError:
            return None

    pool = ThreadPoolExecutor(max_workers=workers)
    futures = [pool.submit(probe, port) for port in ports]
    done = 0
    try:
        for future in as_completed(futures):
            if stop_event.is_set():
                for item in futures:
                    item.cancel()
                raise ScanStopped()
            port = future.result()
            done += 1
            if port is not None:
                open_ports.append(port)
            if on_progress:
                on_progress(done, len(ports))
    finally:
        _shutdown_pool(pool)

    return sorted(open_ports)


def probe_directories(base_url, paths, cfg, stop_event, on_progress=None):
    """
    按字典并发探测路径。

    每个请求前等待 cfg["delay"] 秒；线程数由配置的 threads 决定（不再限制为 5）。
    返回每个路径的探测结果（包括失败项）。
    """
    workers = max(1, int(cfg["threads"]))
    delay = float(cfg["delay"])
    results = []

    def probe(path):
        if stop_event.is_set():
            return None
        # 请求间隔：用 Event.wait 实现，停止时可立即中断等待
        if delay > 0 and stop_event.wait(delay):
            return None
        if stop_event.is_set():
            return None

        url = urllib.parse.urljoin(base_url, path)
        try:
            response = fetch(
                url,
                timeout=float(cfg["timeout"]),
                retries=int(cfg["retries"]),
                stop_event=stop_event,
            )
            return {
                "path": path,
                "url": url,
                "status": response.status,
                "length": len(response.body),
            }
        except ScanStopped:
            return None
        except RequestFailed as exc:
            return {
                "path": path,
                "url": url,
                "status": 0,
                "length": 0,
                "error": str(exc),
            }

    pool = ThreadPoolExecutor(max_workers=workers)
    futures = [pool.submit(probe, path) for path in paths]
    done = 0
    try:
        for future in as_completed(futures):
            if stop_event.is_set():
                for item in futures:
                    item.cancel()
                raise ScanStopped()
            item = future.result()
            done += 1
            if item is not None:
                results.append(item)
            if on_progress:
                on_progress(done, len(paths))
    finally:
        _shutdown_pool(pool)

    return results


def detect_soft_404(base_url, cfg, stop_event):
    """
    请求一个随机不存在的路径，作为“软 404”基线。
    如果站点对所有路径都返回 200，随机页面的状态码和长度可用于过滤误报。
    """
    probe_path = "/__wst_%s__" % uuid.uuid4().hex[:10]
    probe_url = urllib.parse.urljoin(base_url, probe_path)
    try:
        response = fetch(
            probe_url,
            timeout=float(cfg["timeout"]),
            retries=0,
            stop_event=stop_event,
        )
    except RequestFailed:
        return None
    if response.status == 200:
        return {"status": response.status, "length": len(response.body)}
    return None


def is_soft_404(item, soft_404):
    """判断探测结果是否与软 404 基线过于相似。"""
    if not soft_404:
        return False
    if item["status"] != soft_404["status"]:
        return False
    tolerance = max(32, int(soft_404["length"] * 0.02))
    return abs(item["length"] - soft_404["length"]) <= tolerance


def submit_form(action_url, method, fields, cfg, opener, stop_event):
    """按表单的 method 提交字段，返回 HttpResponse。"""
    encoded = urllib.parse.urlencode(fields)
    if method == "post":
        return fetch(
            action_url,
            method="POST",
            data=encoded.encode("utf-8"),
            timeout=float(cfg["timeout"]),
            retries=int(cfg["retries"]),
            opener=opener,
            stop_event=stop_event,
        )

    separator = "&" if "?" in action_url else "?"
    url = action_url + (separator + encoded if encoded else "")
    return fetch(
        url,
        timeout=float(cfg["timeout"]),
        retries=int(cfg["retries"]),
        opener=opener,
        stop_event=stop_event,
    )


def find_sql_error(body, baseline_body=""):
    """
    在响应正文中查找“基线中不存在”的数据库错误特征。
    只返回命中的特征字符串，不提取任何数据。
    """
    lowered = body.lower()
    baseline_lowered = (baseline_body or "").lower()
    for pattern in SQL_ERROR_PATTERNS:
        if pattern in lowered and pattern not in baseline_lowered:
            return pattern
    return None


def is_sensitive_path(path):
    """根据关键字判断路径是否属于敏感路径。"""
    lowered = (path or "").lower()
    return any(keyword in lowered for keyword in SENSITIVE_PATH_KEYWORDS)


def _new_result(target, level_name):
    """初始化扫描结果容器。"""
    return {
        "target": target,
        "level": level_name,
        "config": {},
        "started": datetime.now(),
        "ended": None,
        "stopped": False,
        "reachable": True,
        "final_url": target,
        "info": {
            "status": 0,
            "server": "",
            "powered_by": "",
            "title": "",
            "links": [],
            "form_count": 0,
            "missing_headers": [],
        },
        "forms_data": [],
        "open_ports": [],
        "dir_hits": [],
        "form_tests": [],
        "findings": [],
    }


def _run_round(target, level_name, cfg, q, stop_event, round_index=0,
               aggressive=False):
    """
    执行一轮完整的五阶段扫描，并生成这一轮的文本报告。

    参数：
        target        已校验的目标 URL
        level_name    强度档位名称（低强度/中强度/高强度/自定义）
        cfg           本轮的参数配置字典（由 run_scan 解析后传入）
        q             与界面通信的 queue.Queue
        stop_event    threading.Event，用于安全停止
        round_index   持续扫描时的轮次序号（从 1 开始）；0 表示单轮扫描
        aggressive    True 时启用“有害化攻击模式”：追加时间盲注、
                      命令注入回显等更具攻击性的探针（仍为非破坏性）

    返回：
        (report_text, stopped, result)
    """
    result = _new_result(target, level_name)
    result["config"] = dict(cfg)
    result["aggressive"] = bool(aggressive)
    result["round"] = round_index
    scan_started = time.monotonic()

    # -- 内部辅助函数 ---------------------------------------------------
    def log(level, message):
        q.put(("log", level, message))

    def add_finding(level, title, detail=""):
        result["findings"].append({
            "level": level,
            "title": title,
            "detail": detail,
        })

    def stage(name, percent):
        # 持续扫描时给阶段名加上轮次前缀，方便在状态栏区分第几轮
        label = ("第 %s 轮 · %s" % (round_index, name)) if round_index else name
        q.put(("stage", label))
        q.put(("progress", int(percent)))
        log("系统", "==== %s ====" % label)

    def progress(percent):
        q.put(("progress", max(0, min(100, int(percent)))))

    def pause():
        """按档位间隔等待；停止时立即抛 ScanStopped。"""
        delay = float(cfg["delay"])
        if delay > 0 and stop_event.wait(delay):
            raise ScanStopped()

    stopped = False
    try:
        if aggressive:
            log("警告",
                "有害化攻击模式已开启：将追加时间盲注、命令注入回显等激进探针"
                "（探针保持非破坏性，但可能触发目标 WAF/IDS 告警）。")
        # ================================================================
        # 1. 信息收集
        # ================================================================
        stage("信息收集", 3)
        opener = build_opener()
        page = None
        try:
            page = fetch(
                target,
                timeout=float(cfg["timeout"]),
                retries=int(cfg["retries"]),
                opener=opener,
                stop_event=stop_event,
            )
        except RequestFailed as exc:
            result["reachable"] = False
            log("风险", "无法访问目标首页：%s" % _short(exc, 200))
            add_finding("中", "目标首页无法访问", _short(exc, 200))

        if page is not None:
            info = result["info"]
            info["status"] = page.status
            result["final_url"] = page.url
            log("信息", "HTTP 状态码：%s，最终地址：%s" % (page.status, page.url))
            if page.status >= 400:
                log("警告", "首页返回错误状态码 %s，后续结果可能不完整。" % page.status)
                add_finding("低", "首页返回异常状态码", "HTTP %s" % page.status)

            # 打印常见响应头（只记录，不保存 Cookie 值）
            for name in (
                "Server", "X-Powered-By", "Content-Type",
                "X-Frame-Options", "Content-Security-Policy",
                "Strict-Transport-Security", "X-Content-Type-Options",
                "Referrer-Policy",
            ):
                value = header_value(page.headers, name)
                if value:
                    log("信息", "响应头 %s：%s" % (name, _short(value)))

            server = header_value(page.headers, "Server")
            powered_by = header_value(page.headers, "X-Powered-By")
            if server:
                info["server"] = server
                add_finding("低", "服务器版本信息泄露", server)
            if powered_by:
                info["powered_by"] = powered_by
                add_finding("低", "技术栈信息泄露", "X-Powered-By: %s" % powered_by)
            if header_value(page.headers, "Set-Cookie"):
                log("信息", "响应包含 Set-Cookie（未记录具体 Cookie 值）。")

            # 安全响应头检查
            missing_headers = []
            for name in (
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
            ):
                if not header_value(page.headers, name):
                    missing_headers.append(name)
            if (urllib.parse.urlsplit(page.url).scheme == "https"
                    and not header_value(page.headers, "Strict-Transport-Security")):
                missing_headers.append("Strict-Transport-Security")
            if missing_headers:
                info["missing_headers"] = missing_headers
                log("警告", "缺少安全响应头：%s" % "、".join(missing_headers))
                add_finding("低", "缺少安全响应头", "、".join(missing_headers))

            # 解析 HTML
            parser = PageParser()
            try:
                parser.feed(page.body)
            except Exception as exc:
                log("警告", "HTML 解析出现异常：%s" % _short(exc))

            title = parser.title
            info["title"] = title
            log("信息", "页面标题：%s" % (title or "未检测到"))

            links = []
            seen_links = set()
            for href in parser.links:
                href = (href or "").strip()
                if not href or href.lower().startswith(
                        ("javascript:", "mailto:", "tel:", "#")):
                    continue
                absolute = urllib.parse.urljoin(page.url, href)
                if absolute in seen_links:
                    continue
                seen_links.add(absolute)
                links.append(absolute)
                if len(links) >= 50:
                    break
            info["links"] = links

            forms = parser.forms[:20]
            result["forms_data"] = forms
            info["form_count"] = len(forms)
            log("信息", "发现链接 %s 个，表单 %s 个。"
                % (len(links), len(forms)))
            for index, form in enumerate(forms[:10], 1):
                action = urllib.parse.urljoin(
                    page.url, form.get("action") or page.url
                )
                method = (form.get("method") or "get").upper()
                log("信息", "表单 %s：%s %s，字段 %s 个。"
                    % (index, method, action, len(form.get("inputs", []))))

        progress(15)

        # ================================================================
        # 2. 端口扫描
        # ================================================================
        stage("端口扫描", 15)
        split = urllib.parse.urlsplit(result["final_url"])
        host = split.hostname or urllib.parse.urlsplit(target).hostname or ""
        if not host:
            log("警告", "无法解析目标主机名，跳过端口扫描。")
            progress(30)
        else:
            try:
                ip_address = socket.gethostbyname(host)
            except OSError:
                ip_address = "解析失败"
            log("信息", "目标主机：%s（%s），待检测端口：%s 个。"
                % (host, ip_address, len(cfg["ports"])))

            open_ports = scan_ports(
                host,
                cfg["ports"],
                float(cfg["timeout"]),
                int(cfg["threads"]),
                stop_event,
                on_progress=lambda done, total: progress(
                    15 + (done / float(total)) * 15
                ),
            )
            result["open_ports"] = open_ports
            if open_ports:
                log("警告", "开放端口：%s"
                    % "、".join(str(port) for port in open_ports))
                extra_ports = [
                    port for port in open_ports if port not in (80, 443)
                ]
                if extra_ports:
                    add_finding(
                        "中",
                        "存在额外的开放端口",
                        "、".join(str(port) for port in extra_ports),
                    )
            else:
                log("信息", "未检测到开放端口（目标可能不可达或被防火墙过滤）。")
        progress(30)

        # ================================================================
        # 3. 目录探测
        # ================================================================
        stage("目录探测", 30)
        if not result["reachable"]:
            log("警告", "目标首页不可达，跳过目录探测。")
            progress(70)
        else:
            base_url = result["final_url"]
            soft_404 = detect_soft_404(base_url, cfg, stop_event)
            if soft_404:
                log("信息", "软 404 基线：HTTP %s，长度 %s。"
                    % (soft_404["status"], soft_404["length"]))
            log("信息", "使用字典探测 %s 条路径，并发 %s，请求间隔 %s 秒。"
                % (len(cfg["paths"]),
                   int(cfg["threads"]),
                   cfg["delay"]))

            directory_items = probe_directories(
                base_url,
                cfg["paths"],
                cfg,
                stop_event,
                on_progress=lambda done, total: progress(
                    30 + (done / float(total)) * 40
                ),
            )

            dir_hits = []
            restricted_paths = []
            request_errors = 0
            for item in directory_items:
                if item["status"] == 0:
                    request_errors += 1
                    continue

                status = item["status"]
                if status == 404:
                    continue
                if is_soft_404(item, soft_404):
                    continue

                if status == 200:
                    dir_hits.append(item)
                    if is_sensitive_path(item["path"]):
                        log("风险", "敏感路径可访问：%s（HTTP 200，长度 %s）"
                            % (item["path"], item["length"]))
                        add_finding("中", "敏感路径可直接访问", item["path"])
                    else:
                        log("警告", "发现可访问路径：%s（HTTP 200，长度 %s）"
                            % (item["path"], item["length"]))
                elif status in (301, 302, 303, 307, 308):
                    dir_hits.append(item)
                    log("信息", "路径重定向：%s（HTTP %s）"
                        % (item["path"], status))
                elif status in (401, 403):
                    dir_hits.append(item)
                    restricted_paths.append(item["path"])
                    log("警告", "路径存在但受限：%s（HTTP %s）"
                        % (item["path"], status))
                elif status >= 500:
                    log("警告", "路径返回服务器错误：%s（HTTP %s）"
                        % (item["path"], status))
                else:
                    log("信息", "路径响应：%s（HTTP %s）"
                        % (item["path"], status))

            if restricted_paths:
                add_finding(
                    "低",
                    "发现存在但受限的路径",
                    "、".join(restricted_paths[:10]),
                )
            result["dir_hits"] = dir_hits
            if request_errors:
                log("信息", "%s 条路径请求失败（超时或连接错误）。"
                    % request_errors)
            if not dir_hits:
                log("信息", "未发现可访问的敏感路径。")
            progress(70)

        # ================================================================
        # 4. 表单漏洞检测（无害 payload，只记录异常响应）
        # ================================================================
        stage("表单漏洞检测", 70)
        forms_data = result["forms_data"]
        if not result["reachable"]:
            log("警告", "目标首页不可达，跳过表单检测。")
            progress(95)
        elif not forms_data:
            log("信息", "首页未发现表单，跳过表单检测。")
            progress(95)
        else:
            base_url = result["final_url"]
            base_host = urllib.parse.urlsplit(base_url).netloc.lower()
            testable_forms = []

            for form in forms_data[:int(cfg.get("max_forms", 6))]:
                action_url = urllib.parse.urljoin(
                    base_url, form.get("action") or base_url
                )
                # 安全边界：只测试与目标同主机的表单，避免请求第三方系统
                if urllib.parse.urlsplit(action_url).netloc.lower() != base_host:
                    log("信息", "跳过提交到其他主机的表单：%s" % action_url)
                    continue

                fields = [
                    field for field in form.get("inputs", [])
                    if field.get("name")
                    and field.get("type") not in SKIP_INPUT_TYPES
                ]
                if not fields:
                    continue
                testable_forms.append((
                    action_url,
                    (form.get("method") or "get").lower(),
                    fields,
                    form.get("inputs", []),
                ))

            if not testable_forms:
                log("信息", "没有可测试的表单（可能均指向外部主机或无输入字段）。")
                progress(95)
            else:
                max_fields = int(cfg.get("max_fields_per_form", 4))
                total_forms = len(testable_forms)

                for index, (action_url, method, fields, inputs) in \
                        enumerate(testable_forms, 1):
                    if stop_event.is_set():
                        raise ScanStopped()

                    log("系统", "测试表单 %s/%s：%s %s"
                        % (index, total_forms, method.upper(), action_url))

                    # 表单默认值（用于构造基线请求）
                    defaults = {}
                    for field in inputs:
                        name = field.get("name")
                        if (name
                                and field.get("type") not in SKIP_INPUT_TYPES
                                and name not in defaults):
                            defaults[name] = field.get("value", "")

                    baseline = None
                    baseline_elapsed = 0.0
                    baseline_started = time.monotonic()
                    try:
                        baseline = submit_form(
                            action_url, method, defaults, cfg, opener, stop_event
                        )
                        baseline_elapsed = time.monotonic() - baseline_started
                    except RequestFailed as exc:
                        log("警告", "表单基线请求失败：%s" % _short(exc, 120))

                    issues = []
                    tested_requests = 0

                    # 有害化攻击模式：追加更多 SQL 变体、时间盲注与命令注入回显探针
                    if aggressive:
                        probes = []
                        for _name in ("sqli_error", "xss", "cmdi"):
                            for _payload in AGGRESSIVE_PAYLOADS[_name]:
                                probes.append((_name, _payload))
                        for _payload in AGGRESSIVE_PAYLOADS["sqli_time"]:
                            probes.append(("sqli_time", _payload))
                    else:
                        probes = list(PAYLOADS.items())

                    for field in fields[:max_fields]:
                        field_name = field["name"]
                        for payload_name, payload in probes:
                            if stop_event.is_set():
                                raise ScanStopped()
                            pause()

                            data = dict(defaults)
                            data[field_name] = payload
                            request_started = time.monotonic()
                            try:
                                response = submit_form(
                                    action_url, method, data,
                                    cfg, opener, stop_event
                                )
                                request_elapsed = (
                                    time.monotonic() - request_started
                                )
                            except RequestFailed as exc:
                                log("警告", "字段 %s 测试请求失败：%s"
                                    % (field_name, _short(exc, 100)))
                                continue

                            tested_requests += 1
                            baseline_body = baseline.body if baseline else ""

                            if payload_name == "xss":
                                # 只判断 payload 是否被原样反射，不执行脚本
                                if (payload in response.body
                                        and payload not in baseline_body):
                                    message = (
                                        "字段 %s 的输入被原样反射到响应中，"
                                        "疑似反射型 XSS（HTTP %s）"
                                        % (field_name, response.status)
                                    )
                                    log("风险", "表单 %s：%s"
                                        % (action_url, message))
                                    issues.append(("高", message))
                                    add_finding(
                                        "高",
                                        "疑似反射型 XSS",
                                        "%s 字段 %s" % (action_url, field_name),
                                    )
                            elif payload_name == "cmdi":
                                # 命令注入回显：只让服务器 echo 固定标记，
                                # 命中说明输入可能被拼接进了系统命令。
                                # 先剔除“整段 payload 被原样反射”的情况，
                                # 避免把单纯的反射误判为命令执行。
                                stripped_body = response.body.replace(payload, "")
                                if (AGGRESSIVE_MARKER in stripped_body
                                        and AGGRESSIVE_MARKER not in baseline_body):
                                    message = (
                                        "字段 %s 的输入疑似被拼接进系统命令，"
                                        "命令回显标记出现在响应中（HTTP %s）"
                                        % (field_name, response.status)
                                    )
                                    log("风险", "表单 %s：%s"
                                        % (action_url, message))
                                    issues.append(("高", message))
                                    add_finding(
                                        "高",
                                        "疑似命令注入",
                                        "%s 字段 %s" % (action_url, field_name),
                                    )
                            elif payload_name == "sqli_time":
                                # 时间盲注：响应被延迟到接近 SLEEP 时长，
                                # 且基线请求明显更快时判定为可疑
                                if (request_elapsed >= AGGRESSIVE_TIME_THRESHOLD
                                        and request_elapsed
                                        > baseline_elapsed + 2.0):
                                    message = (
                                        "字段 %s 的时间盲注探针使响应延迟 "
                                        "%.1f 秒（基线 %.1f 秒）"
                                        % (field_name, request_elapsed,
                                           baseline_elapsed)
                                    )
                                    log("风险", "表单 %s：%s"
                                        % (action_url, message))
                                    issues.append(("高", message))
                                    add_finding(
                                        "高",
                                        "疑似时间盲注",
                                        "%s 字段 %s" % (action_url, field_name),
                                    )
                            else:
                                signature = find_sql_error(
                                    response.body, baseline_body
                                )
                                if signature:
                                    message = (
                                        "字段 %s 的 SQL 注入探针触发数据库"
                                        "错误特征（%s）"
                                        % (field_name, signature)
                                    )
                                    log("风险", "表单 %s：%s"
                                        % (action_url, message))
                                    issues.append(("高", message))
                                    add_finding(
                                        "高",
                                        "疑似 SQL 注入",
                                        "%s 字段 %s" % (action_url, field_name),
                                    )
                                elif (baseline is not None
                                      and response.status >= 500
                                      and baseline.status < 500):
                                    message = (
                                        "字段 %s 的注入探针导致服务器返回"
                                        " HTTP %s" % (field_name, response.status)
                                    )
                                    log("警告", "表单 %s：%s"
                                        % (action_url, message))
                                    issues.append(("中", message))
                                    add_finding(
                                        "中",
                                        "输入触发服务器错误",
                                        "%s 字段 %s" % (action_url, field_name),
                                    )

                    if not issues:
                        log("信息", "表单 %s 未发现明显异常（共发送 %s 次检测请求）。"
                            % (action_url, tested_requests))

                    result["form_tests"].append({
                        "action": action_url,
                        "method": method,
                        "fields": [field["name"] for field in fields],
                        "tested": tested_requests,
                        "issues": issues,
                    })
                    progress(70 + (index / float(total_forms)) * 25)

        # ================================================================
        # 5. 报告输出
        # ================================================================
        stage("报告输出", 96)

    except ScanStopped:
        stopped = True
        log("警告", "扫描已停止")
        q.put(("stage", "已停止"))

    result["stopped"] = stopped
    result["ended"] = datetime.now()
    report = build_report(result)

    if not stopped:
        progress(100)
        q.put(("stage", "完成"))
        if round_index:
            log("信息", "第 %s 轮扫描完成，本轮用时 %s 秒。"
                % (round_index, int(time.monotonic() - scan_started)))
        else:
            log("信息", "扫描完成，用时 %s 秒。"
                % int(time.monotonic() - scan_started))

    return report, stopped, result


def run_scan(target, level_name, q, stop_event, level_config=None,
             continuous=False, aggressive=False):
    """
    扫描主流程（对外入口）。

    参数：
        target        已校验的目标 URL
        level_name    强度档位名称：低强度/中强度/高强度/自定义
        q             与界面通信的 queue.Queue
        stop_event    threading.Event，用于安全停止
        level_config  可选。自定义档位对应的配置字典（由
                      config.normalize_custom_config 校验）；
                      为 None 时从 INTENSITY_LEVELS[level_name] 读取。
        continuous    True 时进入“持续扫描”模式：每一轮五阶段扫描结束后
                      自动开始下一轮，直到用户点击“停止扫描”（设置
                      stop_event）才会结束，并把各轮报告汇总为一份报告。

    返回：
        (report_text, stopped)
    """
    if level_config is not None:
        # 自定义档位：使用界面传入并已校验的参数
        cfg = dict(level_config)
    else:
        cfg = INTENSITY_LEVELS[level_name]

    # ---------------- 单轮扫描 ----------------
    if not continuous:
        report, stopped, _result = _run_round(
            target, level_name, cfg, q, stop_event, aggressive=aggressive
        )
        return report, stopped

    # ---------------- 持续扫描 ----------------
    q.put(("log", "系统",
           "已开启持续扫描：每轮结束后自动开始下一轮，"
           "点击“停止扫描”才会结束。"))
    started = datetime.now()
    results = []
    reports = []
    rounds = 0
    stopped = False

    while not stop_event.is_set():
        rounds += 1
        report, round_stopped, result = _run_round(
            target, level_name, cfg, q, stop_event, round_index=rounds,
            aggressive=aggressive,
        )
        reports.append(report)
        results.append(result)
        if round_stopped:
            stopped = True
            break

        # 轮次之间短暂停顿；用 Event.wait 实现，停止时可立即打断
        gap = max(1.0, float(cfg.get("delay", 0.0)) * 2)
        q.put(("log", "信息",
               "第 %s 轮结束，%s 秒后开始第 %s 轮…"
               "（持续扫描模式，点击“停止扫描”结束）"
               % (rounds, gap, rounds + 1)))
        if stop_event.wait(gap):
            stopped = True
            break

    if stop_event.is_set():
        stopped = True

    ended = datetime.now()
    report = _build_continuous_report(
        target, level_name, cfg, results, reports,
        started, ended, stopped, rounds, aggressive=aggressive,
    )
    q.put(("progress", 100))
    q.put(("stage", "已停止" if stopped else "完成"))

    if stopped:
        q.put(("log", "警告", "持续扫描已停止，共完成 %s 轮。" % rounds))
    else:
        q.put(("log", "信息", "持续扫描结束，共完成 %s 轮。" % rounds))

    return report, stopped


def _build_continuous_report(target, level_name, cfg, results, reports,
                             started, ended, stopped, rounds,
                             aggressive=False):
    """持续扫描模式：把各轮报告与总体统计汇总为一份文本报告。"""
    duration = int((ended - started).total_seconds())

    # 各轮风险合计（不做去重，便于看出重复出现的风险）
    findings = []
    for result in results:
        findings.extend(result.get("findings") or [])
    high = sum(1 for item in findings if item.get("level") == "高")
    medium = sum(1 for item in findings if item.get("level") == "中")
    low = len(findings) - high - medium

    lines = []
    add = lines.append
    add("=" * 64)
    add("              Web 安全测试报告（持续扫描）")
    add("=" * 64)
    add("目标 URL   ：%s" % target)
    add("扫描强度   ：%s" % level_name)
    add("扫描模式   ：持续扫描（循环执行，直到用户主动停止）")
    if aggressive:
        add("检测模式   ：有害化攻击模式（激进探针：时间盲注 / 命令注入回显 / "
            "扩展 SQLi、XSS）")
    add("参数       ：请求间隔 %ss，并发 %s，超时 %ss，重试 %s 次，"
        "字典 %s 条，端口 %s 个"
        % (cfg.get("delay"), cfg.get("threads"), cfg.get("timeout"),
           cfg.get("retries"), len(cfg.get("paths", [])),
           len(cfg.get("ports", []))))
    if level_name not in INTENSITY_LEVELS:
        add("参数来源   ：用户自定义（可在界面“自定义参数”中修改）")
    add("开始时间   ：%s" % _format_time(started))
    add("结束时间   ：%s" % _format_time(ended))
    add("完成轮次   ：%s 轮" % rounds)
    add("扫描状态   ：%s" % ("已停止（由用户主动停止）"
                          if stopped else "完成"))
    add("累计用时   ：%02d:%02d" % (duration // 60, duration % 60))
    add("累计风险   ：高风险 %s 项，中风险 %s 项，低风险 %s 项"
        "（各轮合计，未去重）" % (high, medium, low))
    add("-" * 64)
    if reports:
        add("以下为每一轮的详细报告：")
        add("")
        add("\n\n".join(reports))
    else:
        add("尚未完成任何一轮扫描（扫描在开始前就被停止）。")
    add("=" * 64)
    add("说明：本报告仅用于已获得授权的安全测试环境，请勿用于未授权目标。")
    return "\n".join(lines)


def _format_time(value):
    if not value:
        return "-"
    return value.strftime("%Y-%m-%d %H:%M:%S")


def build_report(result):
    """把扫描结果汇总为纯文本报告。"""
    info = result.get("info", {})
    level = result.get("level", "")
    # 优先使用结果中保存的配置（自定义档位也适用），
    # 其次回退到固定档位配置，保证旧结果也能生成报告。
    cfg = result.get("config") or INTENSITY_LEVELS.get(level, {})
    started = result.get("started")
    ended = result.get("ended") or datetime.now()
    duration = int((ended - started).total_seconds()) if started else 0

    lines = []
    add = lines.append

    add("=" * 64)
    add("                        Web 安全测试报告")
    add("=" * 64)
    add("目标 URL   ：%s" % result.get("target", ""))
    add("扫描强度   ：%s" % level)
    if result.get("aggressive"):
        add("检测模式   ：有害化攻击模式（激进探针：时间盲注 / 命令注入回显 / "
            "扩展 SQLi、XSS）")
    if result.get("round"):
        # 持续扫描模式下标注当前是第几轮
        add("轮次       ：第 %s 轮（持续扫描）" % result["round"])
    if cfg:
        add("参数       ：请求间隔 %ss，并发 %s，超时 %ss，重试 %s 次，"
            "字典 %s 条，端口 %s 个"
            % (cfg.get("delay"), cfg.get("threads"), cfg.get("timeout"),
               cfg.get("retries"), len(cfg.get("paths", [])),
               len(cfg.get("ports", []))))
    if level not in INTENSITY_LEVELS:
        # 自定义档位：额外标注参数来源，便于报告中区分固定档位
        add("参数来源   ：用户自定义（可在界面“自定义参数”中修改）")
    add("开始时间   ：%s" % _format_time(started))
    add("结束时间   ：%s" % _format_time(ended))
    add("扫描状态   ：%s" % ("已停止（结果不完整）"
                          if result.get("stopped") else "完成"))
    add("扫描用时   ：%02d:%02d" % (duration // 60, duration % 60))
    add("-" * 64)

    # ---- 信息收集 ----
    add("【一、信息收集】")
    if info.get("status"):
        add("  HTTP 状态码 ：%s" % info["status"])
        add("  最终 URL    ：%s" % result.get("final_url", ""))
        if info.get("server"):
            add("  Server      ：%s" % info["server"])
        if info.get("powered_by"):
            add("  X-Powered-By：%s" % info["powered_by"])
        add("  页面标题    ：%s" % (info.get("title") or "未检测到"))
        add("  链接数量    ：%s" % len(info.get("links", [])))
        add("  表单数量    ：%s" % info.get("form_count", 0))
        if info.get("missing_headers"):
            add("  缺少安全响应头：%s" % "、".join(info["missing_headers"]))
        if info.get("links"):
            add("  链接示例：")
            for link in info["links"][:10]:
                add("    - %s" % _short(link, 120))
        if result.get("forms_data"):
            add("  表单列表：")
            for index, form in enumerate(result["forms_data"][:10], 1):
                action = urllib.parse.urljoin(
                    result.get("final_url", ""), form.get("action") or ""
                )
                add("    %s. %s %s"
                    % (index, (form.get("method") or "get").upper(), action))
    else:
        add("  未能获取目标首页信息。")
    add("-" * 64)

    # ---- 端口扫描 ----
    add("【二、端口扫描】")
    open_ports = result.get("open_ports") or []
    if open_ports:
        add("  开放端口：%s" % "、".join(str(port) for port in open_ports))
    else:
        add("  未检测到开放端口（目标可能不可达或被防火墙过滤）。")
    add("-" * 64)

    # ---- 目录探测 ----
    add("【三、目录探测】")
    dir_hits = result.get("dir_hits") or []
    if dir_hits:
        for item in dir_hits[:60]:
            add("  [%s] %s  （响应长度 %s）"
                % (item["status"], item["path"], item["length"]))
    else:
        add("  未发现可访问的敏感路径。")
    add("-" * 64)

    # ---- 表单检测 ----
    add("【四、表单漏洞检测】")
    form_tests = result.get("form_tests") or []
    if form_tests:
        for index, item in enumerate(form_tests, 1):
            add("  %s. %s %s"
                % (index, item["method"].upper(), item["action"]))
            add("     字段：%s" % ("、".join(item["fields"]) or "无"))
            if item.get("issues"):
                for issue_level, message in item["issues"]:
                    add("     [%s] %s" % (issue_level, message))
            else:
                add("     未发现明显异常。")
    else:
        add("  未发现可测试的表单。")
    add("-" * 64)

    # ---- 风险汇总 ----
    add("【五、风险汇总】")
    findings = result.get("findings") or []
    if findings:
        order = {"高": 0, "中": 1, "低": 2}
        for item in sorted(findings,
                           key=lambda entry: order.get(entry.get("level"), 9)):
            detail = "：%s" % item["detail"] if item.get("detail") else ""
            add("  [%s] %s%s"
                % (item.get("level", "低"), item.get("title", ""), detail))
        high = sum(1 for item in findings if item.get("level") == "高")
        medium = sum(1 for item in findings if item.get("level") == "中")
        low = len(findings) - high - medium
        add("")
        add("  合计：高风险 %s 项，中风险 %s 项，低风险 %s 项。"
            % (high, medium, low))
    else:
        add("  未发现明显风险。注意：本结果不代表目标绝对安全。")

    add("=" * 64)
    add("说明：本报告仅用于已获得授权的安全测试环境，请勿用于未授权目标。")
    return "\n".join(lines)
