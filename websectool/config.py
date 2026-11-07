# -*- coding: utf-8 -*-
"""
配置模块
========

集中存放扫描强度参数、路径字典、端口列表、检测 payload 等。
修改扫描行为时优先改这里，扫描逻辑本身不需要动。

INTENSITY_LEVELS 中每个档位包含：
    delay                  每次 HTTP 请求前的等待秒数（降低对目标的影响）
    threads                并发线程数（目录探测 / 端口扫描共用，未做 5 线程限制）
    timeout                单次请求超时（秒）
    retries                失败重试次数（不含首次请求）
    paths                  目录探测字典
    ports                  端口扫描列表
    max_forms              单次扫描最多测试的表单数量
    max_fields_per_form    每个表单最多测试的输入字段数量

除三档固定强度外，还提供“自定义”档位（CUSTOM_INTENSITY）：
用户通过界面填写参数，由 normalize_custom_config() 校验规范化后
交给扫描函数使用，扫描逻辑同样只从配置字典读取参数。

扫描主流程还支持“持续扫描”模式（run_scan(..., continuous=True)）：
每一轮五阶段扫描结束后自动开始下一轮，直到用户主动停止。
"""

# 三档扫描强度：低强度（隐蔽）/ 中强度（默认）/ 高强度（快速）
# 注意：并发线程数没有 5 线程的安全限制，可按目标承受能力自行调整；
#       自定义档位的线程数上限见 THREADS_LIMIT。
INTENSITY_LEVELS = {
    # ------------------------------------------------------------------
    # 低强度（隐蔽）：1 秒间隔、单线程、10 条路径、5 秒超时、仅 80/443
    # ------------------------------------------------------------------
    "低强度": {
        "delay": 1.0,
        "threads": 1,
        "timeout": 5.0,
        "retries": 2,
        "max_forms": 4,
        "max_fields_per_form": 4,
        "ports": [80, 443],
        "paths": [
            "/admin/",
            "/login",
            "/robots.txt",
            "/.git/HEAD",
            "/.env",
            "/backup.zip",
            "/phpinfo.php",
            "/server-status",
            "/wp-admin/",
            "/config.php",
        ],
    },
    # ------------------------------------------------------------------
    # 中强度（默认）：0.3 秒间隔、2 线程、30 条路径、3 秒超时
    # ------------------------------------------------------------------
    "中强度": {
        "delay": 0.3,
        "threads": 2,
        "timeout": 3.0,
        "retries": 1,
        "max_forms": 6,
        "max_fields_per_form": 5,
        "ports": [80, 443, 8080, 8443],
        "paths": [
            # —— 低强度的 10 条 ——
            "/admin/",
            "/login",
            "/robots.txt",
            "/.git/HEAD",
            "/.env",
            "/backup.zip",
            "/phpinfo.php",
            "/server-status",
            "/wp-admin/",
            "/config.php",
            # —— 追加 20 条 ——
            "/administrator/",
            "/dashboard/",
            "/uploads/",
            "/files/",
            "/backup/",
            "/db.sql",
            "/.svn/entries",
            "/web.config",
            "/console",
            "/manager/html",
            "/actuator",
            "/actuator/health",
            "/swagger-ui.html",
            "/api/swagger.json",
            "/api/",
            "/test/",
            "/debug",
            "/logs/",
            "/static/",
            "/crossdomain.xml",
        ],
    },
    # ------------------------------------------------------------------
    # 高强度（快速）：0.05 秒间隔、5 线程、60 条路径、2 秒超时
    # ------------------------------------------------------------------
    "高强度": {
        "delay": 0.05,
        "threads": 5,
        "timeout": 2.0,
        "retries": 1,
        "max_forms": 8,
        "max_fields_per_form": 5,
        "ports": [80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000, 9090],
        "paths": [
            # —— 中强度的 30 条 ——
            "/admin/",
            "/login",
            "/robots.txt",
            "/.git/HEAD",
            "/.env",
            "/backup.zip",
            "/phpinfo.php",
            "/server-status",
            "/wp-admin/",
            "/config.php",
            "/administrator/",
            "/dashboard/",
            "/uploads/",
            "/files/",
            "/backup/",
            "/db.sql",
            "/.svn/entries",
            "/web.config",
            "/console",
            "/manager/html",
            "/actuator",
            "/actuator/health",
            "/swagger-ui.html",
            "/api/swagger.json",
            "/api/",
            "/test/",
            "/debug",
            "/logs/",
            "/static/",
            "/crossdomain.xml",
            # —— 追加 30 条 ——
            "/.htaccess",
            "/.DS_Store",
            "/.git/config",
            "/sitemap.xml",
            "/admin.php",
            "/login.php",
            "/index.php.bak",
            "/config.bak",
            "/config.old",
            "/database.yml",
            "/composer.json",
            "/package.json",
            "/id_rsa",
            "/.bash_history",
            "/jenkins/",
            "/cgi-bin/",
            "/xmlrpc.php",
            "/wp-login.php",
            "/.svn/",
            "/CVS/Entries",
            "/WEB-INF/web.xml",
            "/META-INF/",
            "/trace",
            "/info.php",
            "/export",
            "/monitor",
            "/health",
            "/metrics",
            "/api/v1/users",
            "/api/v1/config",
        ],
    },
}

# 默认强度档位
DEFAULT_INTENSITY = "中强度"

# 并发线程数上限：仅用于避免误填超大数值导致本机资源耗尽，
# 不再对固定档位或自定义档位做 5 线程的安全限制。
# 如需更保守或更激进，直接修改此值即可。
THREADS_LIMIT = 200

# ---------------------------------------------------------------------------
# 自定义档位
# ---------------------------------------------------------------------------
# 界面下拉框中的第四个选项：参数由用户通过“自定义参数”对话框填写。
# 自定义配置同样存放在本模块中，扫描函数仍然只从配置读取参数。
CUSTOM_INTENSITY = "自定义"

# 自定义参数的取值范围（最小值, 最大值），用于校验用户输入，避免危险配置
CUSTOM_LIMITS = {
    "delay": (0.0, 10.0),            # 请求间隔（秒）
    "threads": (1, THREADS_LIMIT),   # 并发线程数（上限 THREADS_LIMIT）
    "timeout": (0.5, 60.0),          # 单次请求超时（秒）
    "retries": (0, 5),               # 失败重试次数
    "max_forms": (1, 50),            # 最多测试的表单数量
    "max_fields_per_form": (1, 30),  # 每个表单最多测试的字段数量
    "paths": (1, 500),               # 路径字典条数
    "ports": (1, 200),               # 端口数量
}

# 自定义档位的默认值：默认沿用“中强度”的参数，用户可在对话框中修改
DEFAULT_CUSTOM_CONFIG = {
    "delay": INTENSITY_LEVELS["中强度"]["delay"],
    "threads": INTENSITY_LEVELS["中强度"]["threads"],
    "timeout": INTENSITY_LEVELS["中强度"]["timeout"],
    "retries": INTENSITY_LEVELS["中强度"]["retries"],
    "max_forms": INTENSITY_LEVELS["中强度"]["max_forms"],
    "max_fields_per_form": INTENSITY_LEVELS["中强度"]["max_fields_per_form"],
    "ports": list(INTENSITY_LEVELS["中强度"]["ports"]),
    "paths": list(INTENSITY_LEVELS["中强度"]["paths"]),
}

# 请求使用的 User-Agent（明确标识为安全测试工具）
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "WebSecurityScanner/1.0 (authorized-security-test)"
)

# 表单检测使用的无害 payload：
#   sqli —— 单个单引号，用于观察是否出现数据库报错特征
#   xss  —— 一段不会真正执行破坏行为的脚本标签，用于观察是否被原样反射
PAYLOADS = {
    "sqli": "'",
    "xss": "<script>alert(1)</script>",
}

# 不作为漏洞测试目标的表单字段类型（提交按钮、文件上传等）
SKIP_INPUT_TYPES = {
    "submit",
    "button",
    "image",
    "reset",
    "file",
    "checkbox",
    "radio",
}

# 常见数据库错误特征（仅用于比对响应中是否“新出现”这些字符串）
SQL_ERROR_PATTERNS = (
    "you have an error in your sql syntax",
    "sqlstate",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "microsoft ole db",
    "microsoft odbc",
    "ora-00933",
    "ora-01756",
    "ora-00921",
    "pg_query",
    "pg_exec",
    "postgresql",
    "mysql_fetch",
    "mysqli",
    "warning: mysql",
    "sqlite error",
    "sqlite3.operationalerror",
    "syntax error at or near",
    "invalid query",
)

# 判断目录探测结果是否属于“敏感路径”的关键字
SENSITIVE_PATH_KEYWORDS = (
    ".git",
    ".svn",
    ".env",
    ".htaccess",
    ".bash_history",
    ".ds_store",
    "backup",
    "db.sql",
    "database",
    ".bak",
    ".old",
    "config",
    "web.config",
    "id_rsa",
    "phpinfo",
    "server-status",
    "manager",
    "actuator",
    "console",
    "debug",
    "swagger",
    "package.json",
    "composer.json",
    "cvs/entries",
    "web-inf",
    "meta-inf",
    "xmlrpc",
)


# ---------------------------------------------------------------------------
# 自定义参数的解析与校验
# ---------------------------------------------------------------------------
def _parse_int(text, label, low, high):
    """把文本解析为整数并检查范围，失败时抛出 ValueError（中文提示）。"""
    try:
        value = int(str(text).strip())
    except (TypeError, ValueError):
        raise ValueError("%s必须是整数。" % label)
    if not (low <= value <= high):
        raise ValueError("%s必须在 %s-%s 之间。" % (label, low, high))
    return value


def _parse_float(text, label, low, high):
    """把文本解析为浮点数并检查范围，失败时抛出 ValueError（中文提示）。"""
    try:
        value = float(str(text).strip())
    except (TypeError, ValueError):
        raise ValueError("%s必须是数字。" % label)
    if not (low <= value <= high):
        raise ValueError("%s必须在 %s-%s 之间。" % (label, low, high))
    return value


def parse_port_list(text):
    """
    把“80,443 8080；8443”这类文本解析为去重后的端口列表。

    支持中英文逗号、分号、空格作为分隔符；端口必须在 1-65535 之间。
    """
    normalized = (str(text or "")
                  .replace("，", ",")
                  .replace("；", ",")
                  .replace(";", ",")
                  .replace("\n", ",")
                  .replace("\r", ","))
    ports = []
    for chunk in normalized.replace(" ", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if not chunk.isdigit():
            raise ValueError("端口 %r 不是有效的数字。" % chunk)
        port = int(chunk)
        if not (1 <= port <= 65535):
            raise ValueError("端口 %s 必须在 1-65535 之间。" % port)
        if port not in ports:
            ports.append(port)
    if not ports:
        raise ValueError("端口列表不能为空，请至少填写一个端口。")
    if len(ports) > CUSTOM_LIMITS["ports"][1]:
        raise ValueError("端口数量不能超过 %s 个。"
                         % CUSTOM_LIMITS["ports"][1])
    return ports


def parse_path_list(text):
    """
    把多行文本解析为去重后的路径字典。

    规则：
      * 每行一条路径，空行与以 # 开头的注释行会被忽略；
      * 缺少开头的 / 时自动补全；
      * 条数必须在 CUSTOM_LIMITS["paths"] 范围内。
    """
    normalized = (str(text or "")
                  .replace("\r\n", "\n")
                  .replace("\r", "\n"))
    paths = []
    for line in normalized.split("\n"):
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        if not item.startswith("/"):
            item = "/" + item
        if item not in paths:
            paths.append(item)
    if not paths:
        raise ValueError("路径字典不能为空，请至少填写一条路径。")
    if len(paths) > CUSTOM_LIMITS["paths"][1]:
        raise ValueError("路径数量不能超过 %s 条。" % CUSTOM_LIMITS["paths"][1])
    return paths


def normalize_custom_config(raw):
    """
    校验并规范化用户在“自定义参数”对话框中填写的参数。

    参数：
        raw  界面原始输入组成的字典，例如
             {"delay": "0.3", "threads": "2", "timeout": "3",
              "retries": "1", "max_forms": "6", "max_fields_per_form": "5",
              "ports": "80,443", "paths": "/admin/\\n/login"}

    返回：
        (config, "")   校验通过，config 为可直接交给扫描函数的配置字典
        (None, "提示") 校验失败，提示文字可直接展示给用户
    """
    raw = raw or {}
    try:
        config = {
            "delay": _parse_float(
                raw.get("delay"), "请求间隔", *CUSTOM_LIMITS["delay"]),
            "threads": _parse_int(
                raw.get("threads"), "并发线程数", *CUSTOM_LIMITS["threads"]),
            "timeout": _parse_float(
                raw.get("timeout"), "超时时间", *CUSTOM_LIMITS["timeout"]),
            "retries": _parse_int(
                raw.get("retries"), "重试次数", *CUSTOM_LIMITS["retries"]),
            "max_forms": _parse_int(
                raw.get("max_forms"), "最多测试表单数",
                *CUSTOM_LIMITS["max_forms"]),
            "max_fields_per_form": _parse_int(
                raw.get("max_fields_per_form"), "每表单最多字段数",
                *CUSTOM_LIMITS["max_fields_per_form"]),
            "ports": parse_port_list(raw.get("ports")),
            "paths": parse_path_list(raw.get("paths")),
        }
    except ValueError as exc:
        return None, str(exc)
    return config, ""


def custom_config_to_text(config):
    """把配置字典转换成对话框可编辑的文本字典（界面回填用）。"""
    config = config or DEFAULT_CUSTOM_CONFIG
    return {
        "delay": str(config.get("delay", "")),
        "threads": str(config.get("threads", "")),
        "timeout": str(config.get("timeout", "")),
        "retries": str(config.get("retries", "")),
        "max_forms": str(config.get("max_forms", "")),
        "max_fields_per_form": str(config.get("max_fields_per_form", "")),
        "ports": ", ".join(str(port) for port in config.get("ports", [])),
        "paths": "\n".join(config.get("paths", [])),
    }


def describe_config(config):
    """返回一行参数摘要，供界面提示与日志使用。"""
    if not config:
        return ""
    return ("请求间隔 %ss · 并发 %s · 超时 %ss · 重试 %s 次 · "
            "路径字典 %s 条 · 端口 %s 个"
            % (config.get("delay"), config.get("threads"),
               config.get("timeout"), config.get("retries"),
               len(config.get("paths", [])), len(config.get("ports", []))))
