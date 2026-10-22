# php2shellbt (PowerShell)

**Passive PHP exposure checker for CVE-2026-109618 / CVE-2026-109619 (php2shell).**

> Language: English | [Español](README_es.md)

A standalone PowerShell port of the passive check from `php2shellbt.py`. It determines
whether a web server runs a PHP version inside the affected range by reading the
`X-Powered-By` response header — with **zero attacks against the target**.

---

## Fork of the original project

This is a **PowerShell fork** of [php2shellbt](https://github.com/pentestershell/php2shellbt)
by [pentestershell (BTshell)](https://github.com/pentestershell) — a Python 3 scanner
for the php2shell vulnerability chain (CVE-2026-109618 / CVE-2026-109619). The original
`php2shellbt.py` and its `README.md` live in this same repository.

**Differences from upstream:**

- Rewritten in PowerShell (`.ps1`), tested on Windows PowerShell 5.1 and PowerShell 7+
- Interactive menu: validate a single domain or a list from a `.txt` file
- Bilingual UI: English (default) and Spanish, switchable at runtime
- **Passive-only by design**: the active checks of the original Python scanner
  (crash-probe, upload_progress probes, handler mismatch, session injection + LFI)
  were removed. See [Security validation](#security-validation--what-this-script-does-not-do)
  for the full list and rationale.
- Trusted backport sources and temporary mitigations are printed for EOL branches

The detection logic (patch table, affected ranges) is identical to the original.
Credits for the vulnerability research belong to the original authors; the Nuclei
templates that inspired the original tool are available at
[Ademking/php2shell-nuclei-templates](https://github.com/Ademking/php2shell-nuclei-templates).

---

## Security validation — what this script does NOT do

This script performs **only passive, read-only GET requests**. It sends no payloads,
never crashes the PHP engine, never exhausts server memory, and never verifies RCE.

The following checks from the original Python scanner were **deliberately excluded**
because they can affect the target software:

| Excluded check | Why it was excluded |
|---|---|
| Crash-probe (malformed multipart bodies up to 20 MiB) | Denial of service: crashes the PHP worker |
| session.upload_progress probes with crafted PHPSESSID | Intrusive engine-triggering payload |
| Handler mismatch (serialized object injection) | Intrusive deserializer-triggering payload |
| Session injection + LFI chain (`<?php ... ?>` in filenames) | RCE verification — an actual attack |

What remains is the only safe check: read `X-Powered-By`, compare the version
against the patch table.

---

## Requirements

- Windows PowerShell 5.1, or PowerShell 7+ (`pwsh`)
- No modules, no NuGet packages, no internet dependencies — single `.ps1` file

```powershell
.\php2shellbt.ps1
```

If your execution policy blocks scripts, run it once with:

```powershell
powershell -ExecutionPolicy Bypass -File .\php2shellbt.ps1
```

---

## Usage

### Interactive menu (default)

```text
====== MENU php2shellbt ======
  1) Validate a single domain
  2) Validate from a .txt file (one domain/URL per line, in this directory)
  3) Language / Idioma: English
  4) Exit
```

- **Option 1** asks for a domain or URL. Bare domains (`example.com`) are retried
  over `http://` if `https://` fails.
- **Option 2** reads a `.txt` file from the current directory (default name
  `targets.txt`). One target per line; empty lines and `#` comments are ignored.
- **Option 3** toggles the UI language between English and Spanish on the fly.

### Command-line mode (skips the menu)

```powershell
# Single target
.\php2shellbt.ps1 -Target https://example.com

# Multiple targets from a file
.\php2shellbt.ps1 -TargetsFile .\targets.txt

# Spanish output, custom timeout
.\php2shellbt.ps1 -Language es -TargetsFile .\targets.txt -TimeoutSec 30
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Target` | — | Single domain or URL to validate |
| `-TargetsFile` | — | `.txt` file with one domain/URL per line (`#` comments allowed) |
| `-Language` | `en` | UI language: `en` (English) or `es` (Spanish) |
| `-TimeoutSec` | `10` | Timeout per HTTP request in seconds |

---

## Verdicts

| Tag | Meaning |
|---|---|
| `VULNERABLE` | PHP version is in the affected range of a branch that has a patch |
| `VULNERABLE (EOL)` | PHP version is in the affected range (5.4.0 – 8.5.11) but its branch is end-of-life — no patch will ever be released for it |
| `NOT AFFECTED` | Patched release, or a branch newer than the affected ones |
| `INCONCLUSIVE` | No `X-Powered-By` header exposing a PHP version |
| `UNKNOWN` | Branch not in the known patch table |
| `ERROR` | Connection failed |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No vulnerable version confirmed |
| `1` | At least one target confirmed vulnerable (including EOL-in-range) |
| `2` | Bad invocation (e.g. both `-Target` and `-TargetsFile`, or unreadable file) |

Exit code `1` makes the script usable in CI/CD pipelines.

---

## Patch table

| Branch | Affected range | Fixed in |
|---|---|---|
| 8.2.x | 8.2.0 – 8.2.34 | **8.2.35** |
| 8.3.x | 8.3.0 – 8.3.35 | **8.3.36** |
| 8.4.x | 8.4.0 – 8.4.26 | **8.4.27** |
| 8.5.x | 8.5.0 – 8.5.11 | **8.5.12** |
| 5.4 – 8.1 | all releases | EOL — no official patch; upgrade or use a backport |

When a vulnerability is detected the script prints official links: the release
announcement on php.net, the `php-src` source tag on GitHub, the NVD entries for
both CVEs, and the PHP security advisories page.

---

## EOL branches: temporary mitigations and backports

For end-of-life branches (5.4 – 8.1) there is no official patch. The script prints:

**Temporary mitigations (NOT definitive)** — PHP core developers state the only
real fix is patching/upgrading:

- `session.upload_progress.enabled = Off` and `session.use_strict_mode = 1` in `php.ini`
- Block multipart POSTs with PHP code in filename fields (WAF / mod_rewrite / nginx rules)
- Restrict internet access to PHP systems that cannot be updated immediately

**Backport sources, ordered by trust:**

1. Distribution/LTS vendor packages (Debian LTS, Ubuntu Pro) — usually the safest option
2. [Sury packages](https://packages.sury.org/) — PHP 5.6–8.5 on Debian/Ubuntu
3. [Remi Repo](https://rpms.remirepo.net/) — PHP 5.6–8.5 on RHEL/Fedora
4. [Official php-src minimal source backports](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619) — 7.4/8.0/8.1, compile yourself
5. [Community source backports](https://github.com/vperetti/php-cve-2026-109618-109619-backports) — 5.4–7.3, unofficial; review before use

Third-party packages are unofficial: verify origin and signatures before applying.

> **Re-scan caveat:** a backported PHP keeps reporting the old version in
> `X-Powered-By`, so this checker will keep flagging it as vulnerable. Verify the
> patch with your package manager (`dpkg` / `rpm` / `apt changelog`), not by
> re-scanning.

---

## Example session

```text
==============================================================
        php2shell vulnerability checker (PowerShell)
        CVE-2026-109618  -  CVE-2026-109619
==============================================================
  Passive mode: only reads the remote PHP version (X-Powered-By).
  Sends no payloads and causes no failures on the server.
  Target : www.example.com
[*] Checking https://www.example.com ...
[*] PHP version detected: 7.3.33
[+] VULNERABLE - PHP 7.3.33 is inside the affected range (5.4.0 - 8.5.11) and
    its branch is end-of-life (EOL): no patch will ever be released for it.
[+]   Only possible definitive remediation: upgrade to a supported branch (...).
[*]   PHP supported versions: https://www.php.net/supported-versions.php
[*]   CVE-2026-109618 (NVD): https://nvd.nist.gov/vuln/detail/CVE-2026-109618
[*]   CVE-2026-109619 (NVD): https://nvd.nist.gov/vuln/detail/CVE-2026-109619
[!]   Temporary mitigations (NOT definitive): ...
[!]   Backport sources for EOL branches: ...

==================== SUMMARY ====================
  VULNERABLE (EOL)   PHP 7.3.33      https://www.example.com

  ALERT: 1 target(s) with a VULNERABLE PHP version. Upgrade PHP immediately.
  Patches: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or later of each branch).
  Official PHP releases: https://www.php.net/releases/
```

---

## How the check works

1. Sends a single `GET` request to the target.
2. Reads the `X-Powered-By` response header and extracts `PHP/x.y.z`.
3. Compares the version against the patch table and prints the verdict.

**Limitations:**

- If the server hides `X-Powered-By` (exposure of the header is commonly disabled),
  the result is `INCONCLUSIVE` — that does **not** mean the host is safe.
- The script confirms the **version** is in the affected range. Actual exploitability
  also depends on server configuration (`session.upload_progress`, LFI presence,
  serialize handlers, etc.). In an EOL or unpatched branch, upgrading is the only
  sound recommendation regardless.
- Certificate validation is disabled (mirroring the original Python scanner) to
  allow scanning hosts with self-signed certificates. This affects the whole
  PowerShell process.

---

## Legal disclaimer

> This tool performs passive, read-only version checks and is intended for
> **authorized security assessments and asset inventory only**. Scanning systems
> you do not own or have explicit permission to test may still be against the
> terms of service of those systems or local law. The authors assume no liability
> for misuse.

---

## License

MIT © 2026 pentestershell (BTshell)
