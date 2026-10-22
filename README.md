# php2shellbt

<p align="center">
  <img src="https://img.shields.io/badge/python-3.6%2B-blue?logo=python" alt="Python 3.6+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/CVE-2026--109618-critical?color=red" alt="CVE-2026-109618">
  <img src="https://img.shields.io/badge/CVE-2026--109619-high?color=orange" alt="CVE-2026-109619">
  <img src="https://img.shields.io/badge/no%20dependencies-stdlib%20only-brightgreen" alt="No external dependencies">
</p>

> **php2shellbt** is a standalone Python scanner that detects the php2shell vulnerability chain in PHP web applications — with **zero external dependencies** (pure stdlib).

---

## What is php2shell?

**php2shell** is a critical vulnerability chain that combines PHP session management weaknesses to achieve unauthenticated Remote Code Execution (RCE) without writing any file to disk:

```
upload_progress use-after-free / OOM
         │
         ▼
  Session file injection (PHP code embedded in filename field)
         │
         ▼
  Local File Inclusion (LFI) of the session file
         │
         ▼
         RCE ← PHP code in session file executed by the server
```

Two new CVEs were assigned to the root causes of this chain:

| CVE | Title | Affected PHP | Fixed in |
|-----|-------|-------------|----------|
| **CVE-2026-109618** | Session upload_progress use-after-free / OOM | 5.4.0 – 8.5.11 | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |
| **CVE-2026-109619** | `var_destroy` use-after-free (UAF) via `unserialize()` + destructor gadget | 5.4.0 – 8.5.11 | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |

---

## Vulnerability Details

### CVE-2026-109618 — Session upload_progress use-after-free / OOM

When `session.upload_progress.enabled = On` (default in PHP ≥ 5.4), an attacker can supply a crafted `PHPSESSID` cookie in a multipart POST request containing the magic key `PHP_SESSION_UPLOAD_PROGRESS`. PHP creates (or reuses) a session file at the attacker-controlled path, storing the `upload_progress` data — including the multipart filename — verbatim in the session file. If cleanup is disabled (`session.upload_progress.cleanup = Off`), the session file persists indefinitely.

**Conditions required:**
- `session.upload_progress.enabled = On` (default)
- `session.upload_progress.cleanup = Off` OR a race-condition window
- An LFI vulnerability that can include `/tmp/sess_<PHPSESSID>`

### CVE-2026-109619 — var_destroy use-after-free

A `var_destroy()` use-after-free in PHP's unserialize path allows an attacker who controls a serialized object to trigger arbitrary destructor gadgets during the free phase. Combined with a POP (Property Oriented Programming) chain, this can yield RCE without any filesystem interaction.

**Detection:** The PHP version is leaked via the `X-Powered-By: PHP/x.y.z` response header. If the version falls within the affected range, the target is potentially vulnerable.

### php2shell Handler Mismatch

When two PHP endpoints on the same application use **different `session.serialize_handler`** values (`php_serialize` on one endpoint, `php` on another), an attacker can write a malicious serialized object via the first endpoint and trigger its deserialization via the second. The deserialization error fires the object destructor, enabling POP-chain RCE.

**Detection indicators:**
- `Failed to decode session object` in response body
- `Session object destruction failed` in response body

### php2shell Session Injection + LFI Chain

This is the full end-to-end PoC chain:

1. POST multipart to any PHP endpoint with `PHP_SESSION_UPLOAD_PROGRESS` and a filename of `<?php echo 'MARKER'; ?>`
2. The PHP engine writes the filename into the session file at `/tmp/sess_<SID>`
3. GET the LFI endpoint including `/tmp/sess_<SID>` — PHP executes the code in the filename field
4. The marker echoes back, confirming full RCE is achievable by replacing `echo` with `system()`

---

## Features

- **4 detection checks** in a single script
- **Zero external dependencies** — pure Python 3.6+ stdlib
- **Colored terminal output** for fast triage
- **JSON output mode** for CI/CD integration (`--json`)
- **Configurable timeout** and all paths/endpoints via CLI flags
- **Exit code 1** if any vulnerability is confirmed (pipeline-friendly)
- **Safe** — read-only probes, no payloads that persist or cause damage

---

## Installation

No pip install needed:

```bash
git clone https://github.com/pentestershell/php2shellbt.git
cd php2shellbt
python3 php2shellbt.py --help
```

Or download the single file directly:

```bash
curl -O https://raw.githubusercontent.com/pentestershell/php2shellbt/main/php2shellbt.py
python3 php2shellbt.py --help
```

**Requirements:** Python 3.6 or later, no third-party packages.

---

## Usage

### Basic scan (checks 1 + 2 always run)

```bash
python3 php2shellbt.py https://target.com
```

### With LFI endpoint (adds check 4 — session injection chain)

```bash
python3 php2shellbt.py https://target.com \
  --lfi "/vuln.php?page=" \
  --session-path /tmp/sessions/sess_
```

### With handler-mismatch paths (adds check 3)

```bash
python3 php2shellbt.py https://target.com \
  --write-path /upload.php \
  --read-path /api/data.php
```

### Full suite — all 4 checks

```bash
python3 php2shellbt.py https://target.com --all \
  --lfi "/vuln.php?page=" \
  --session-path /tmp/sessions/sess_ \
  --write-path /upload.php \
  --read-path /api/data.php
```

### JSON output (for CI/CD or SIEM ingestion)

```bash
python3 php2shellbt.py https://target.com --json
```

Example JSON output:

```json
{
  "target": "https://target.com",
  "results": {
    "cve109619": "VULNERABLE",
    "cve109618": "NOT_FOUND",
    "handler": "SKIPPED",
    "session_lfi": "NOT_FOUND"
  }
}
```

---

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `target` | *(required)* | Base URL of the target (e.g. `https://example.com`) |
| `--all` | Off | Run all 4 checks (requires `--lfi` + `--write-path` + `--read-path`) |
| `--lfi PATH` | — | LFI parameter path, e.g. `/vuln.php?page=` |
| `--session-path PATH` | `/tmp/sessions/sess_` | PHP session file prefix on the server |
| `--write-path PATH` | `/app/upload.php` | Endpoint using `session.serialize_handler=php_serialize` |
| `--read-path PATH` | `/api/endpoint.php` | Endpoint using `session.serialize_handler=php` |
| `--timeout N` | `10` | HTTP request timeout in seconds |
| `--json` | Off | Output results as JSON instead of colored text |

---

## Detection Checks Summary

| # | Check | CVE / Type | Requires | Indicator |
|---|-------|------------|---------|-----------|
| 1 | PHP version fingerprint | CVE-2026-109619 | Nothing | `X-Powered-By: PHP/x.y.z` in affected range |
| 2 | use-after-free / OOM via upload_progress | CVE-2026-109618 | Nothing | Session startup error in response body |
| 3 | Handler mismatch deserialization | php2shell-mismatch | `--write-path` + `--read-path` | `Failed to decode session object` |
| 4 | Session injection + LFI chain | php2shell-lfi | `--lfi` + `--session-path` | Marker echoed back via LFI |

> **Note on check 2:** PHP must have `display_errors = On` for the error indicators to appear in the response body. A "clean" response does not rule out CVE-2026-109618 — it may just be hidden.

---

## Affected Versions

| PHP Branch | Vulnerable range | Fixed version |
|-----------|-----------------|--------------|
| 5.x | 5.4.0 – latest 5.x | Not patched (EOL) — Sury backported packages (e.g. 5.6.40-104+) may include the fixes; verify the package version |
| 8.2.x | 8.2.0 – 8.2.34 | **8.2.35** |
| 8.3.x | 8.3.0 – 8.3.35 | **8.3.36** |
| 8.4.x | 8.4.0 – 8.4.26 | **8.4.27** |
| 8.5.x | 8.5.0 – 8.5.11 | **8.5.12** |

---

## Remediation

1. **Upgrade PHP** to the fixed version for your branch (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later)
2. Set `session.upload_progress.enabled = Off` in `php.ini` if file upload progress is not needed
3. Set `session.upload_progress.cleanup = On` to delete session data immediately after upload
4. Set `session.use_strict_mode = On` to reject externally supplied session IDs
5. Ensure all application endpoints use the **same** `session.serialize_handler`
6. Harden LFI: validate and whitelist all file-inclusion parameters; never include user-controlled paths
7. Consider adding a **WAF rule** to block multipart requests with PHP code in filename fields

---

## Nuclei Templates

Nuclei YAML templates that inspired this tool are available at:

> https://github.com/Ademking/php2shell-nuclei-templates

To run them directly with Nuclei:

```bash
nuclei -u https://target.com -t /path/to/php2shell/
```

---

## Legal Disclaimer

> **This tool is intended for authorized security assessments only.**
>
> Use of php2shellbt against systems you do not own or do not have explicit written permission to test is **illegal** and unethical. The author assumes no liability for any misuse or damage caused by this tool. Always obtain proper authorization before running any security scan.

---

## References

- [PHP Bug #GHSA-xxxx](https://github.com/php/php-src/security/advisories) — php.net security advisory
- [CVE-2026-109618](https://cve.mitre.org) — NVD entry
- [CVE-2026-109619](https://cve.mitre.org) — NVD entry
- [php2shell-nuclei-templates](https://github.com/Ademking/php2shell-nuclei-templates) by @Ademking
- [OWASP LFI](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion) — Testing guide
- [PHP session.upload_progress](https://www.php.net/manual/en/session.upload-progress.php) — PHP documentation

---

## License

MIT © 2026 pentestershell (BTshell)
