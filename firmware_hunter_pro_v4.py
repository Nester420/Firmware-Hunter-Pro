#!/usr/bin/env python3
"""
Firmware Hunter Pro v4.0
A safer offline firmware triage framework for extracted router / IoT firmware.

What it does:
- Scans extracted firmware directories safely without executing firmware binaries.
- Optionally extracts a firmware image with binwalk if binwalk is installed.
- Finds credentials, keys, certs, IPs, domains, URLs, MACs, JWTs, API keys, hashes, CVEs.
- Maps web UI files, CGI handlers, forms, scripts, endpoints, and admin-looking routes.
- Detects ELF binaries, architecture hints, BusyBox, Linux kernel, OpenSSL, Dropbear, dnsmasq, uClibc/musl/glibc.
- Scores findings with severity and confidence.
- Produces TXT, JSON, HTML, Markdown, CSV, and separate evidence files.
- Supports simple external plugins from a plugins directory.

Safe by default:
- Does not execute firmware binaries.
- Only reads files and optionally runs host tools like strings, file, binwalk, yara.

Usage:
    python3 firmware_hunter_pro.py /path/to/squashfs-root
    python3 firmware_hunter_pro.py firmware.bin --extract
    python3 firmware_hunter_pro.py /path/to/rootfs --quick
    python3 firmware_hunter_pro.py /path/to/rootfs --yara rules.yar
    python3 firmware_hunter_pro.py /path/to/rootfs --plugins plugins/
"""

import os
import re
import csv
import sys
import json
import math
import time
import html
import shutil
import hashlib
import argparse
import tempfile
import subprocess
import importlib.util
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

VERSION = "4.0"
REPORT = defaultdict(list)
REPORT_LOCK = Lock()

# =============================================================================
# CONFIG
# =============================================================================

TEXT_EXTENSIONS = {
    ".txt", ".log", ".conf", ".cfg", ".ini", ".json", ".xml", ".html", ".htm",
    ".js", ".php", ".asp", ".cgi", ".lua", ".sh", ".service", ".default",
    ".profile", ".passwd", ".shadow", ".pem", ".key", ".crt", ".pub", ".yaml",
    ".yml", ".env", ".properties", ".rc", ".rules"
}

INTERESTING_NAMES = {
    "passwd", "shadow", "group", "hosts", "resolv.conf", "inittab", "fstab",
    "rcS", "rc.local", "profile", "authorized_keys", "known_hosts", "motd",
    "issue", "services", "inetd", "inetd.conf", "udhcpd.conf", "dnsmasq.conf",
    "dropbear", "telnetd", "lighttpd.conf", "boa.conf", "httpd.conf",
    "mini_httpd.conf", "uhttpd.conf", "nginx.conf", "config.xml", "nvram",
    "default.cfg", "wpa_supplicant.conf", "os-release", "version", "release",
    "syslog.conf", "crontab"
}

EXECUTABLE_NAMES = {
    "busybox", "telnetd", "dropbear", "sshd", "httpd", "boa", "lighttpd",
    "mini_httpd", "uhttpd", "nginx", "nc", "netcat", "wget", "curl", "tftp",
    "ftpget", "ftpput", "iptables", "ip6tables", "dnsmasq", "udhcpd", "pppd",
    "openvpn", "openssl", "sqlite3", "ash", "sh"
}

SUSPICIOUS_KEYWORDS = {
    "telnetd", "dropbear", "busybox telnet", "nc -l", "netcat", "/bin/sh",
    "/bin/ash", "reverse shell", "backdoor", "wget http", "curl http", "tftp",
    "ftpget", "ftpput", "chmod 777", "0.0.0.0", "admin:admin", "root:root",
    "password", "passwd", "shadow", "debug", "test", "factory", "developer",
    "enable telnet", "remote shell", "hardcoded", "debug shell", "diagnostic",
    "support account", "superuser", "hidden", "maintenance"
}

MALWARE_IOC_KEYWORDS = {
    "mirai": ["mirai", "busybox MIRAI", "/bin/busybox", "report.%s", "scanListen"],
    "gafgyt/bashlite": ["gafgyt", "bashlite", "gayfgt", "loligang", "telnet scanner"],
    "mozi": ["mozi", "Mozi.m", "dht.transmissionbt.com", "router.bittorrent.com"],
    "xorddos": ["xorddos", "x0r", "/tmp/.x", "BB2FA36AAA9541F0"],
    "miner": ["stratum+tcp", "xmrig", "minerd", "cryptonight", "monero"],
    "generic_bot": ["CNC", "C2", "botnet", "udp flood", "syn flood", "http flood"]
}

REGEX_PATTERNS = {
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "mac_address": r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b",
    "url": r"https?://[^\s'\"<>]{4,}",
    "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|cn|ru|info|biz|us|uk|co|dev|cloud|local|lan)\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "jwt": r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
    "api_key": r"(?i)(api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client_secret)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{12,})",
    "wifi_psk": r"(?i)(passphrase|psk|wpa_pass|wifi_pass|wifi_password|wireless_key|wpakey)\s*[:=]\s*['\"]?([^\s'\";&]{8,63})",
    "possible_password": r"(?i)(password|passwd|pwd|pass|admin_pass|root_pass|web_pass|wifi_pass|secret|token)\s*[:=]\s*['\"]?([^\s'\";&]{4,})",
    "possible_username": r"(?i)(username|user|login|admin_user|root_user)\s*[:=]\s*['\"]?([^\s'\";&]{3,})",
    "mqtt_credential": r"(?i)(mqtt_(?:user|username|pass|password)|mqttUser|mqttPass)\s*[:=]\s*['\"]?([^\s'\";&]{3,})",
    "basic_auth": r"(?i)authorization:\s*basic\s+([a-zA-Z0-9+/=]{8,})",
}

PRIVATE_KEY_MARKERS = {
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----"
}

CERT_MARKERS = {"-----BEGIN CERTIFICATE-----"}

COMPONENT_PATTERNS = {
    "busybox": [
        r"BusyBox v([\w.\-]+)",
        r"busybox\s+v([\w.\-]+)"
    ],
    "linux_kernel": [
        r"Linux version ([\w.\-]+)",
        r"kernel version[:= ]+([\w.\-]+)"
    ],
    "openssl": [
        r"OpenSSL\s+([0-9][\w.\-]+[a-z]?)",
        r"openssl-([0-9][\w.\-]+)"
    ],
    "dropbear": [
        r"Dropbear sshd v?([0-9][\w.\-]+)",
        r"dropbear[_ -]?([0-9]{4}\.[0-9]{2})"
    ],
    "dnsmasq": [
        r"dnsmasq-?([0-9][\w.\-]+)",
        r"dnsmasq version ([0-9][\w.\-]+)"
    ],
    "uClibc": [
        r"uClibc-?([0-9][\w.\-]+)"
    ],
    "musl": [
        r"musl-?([0-9][\w.\-]+)"
    ],
    "glibc": [
        r"GNU C Library.*?release version ([0-9][\w.\-]+)",
        r"GLIBC_([0-9.]+)"
    ],
    "lighttpd": [
        r"lighttpd/([0-9][\w.\-]+)"
    ],
    "boa": [
        r"Boa/([0-9][\w.\-]+)"
    ],
    "uhttpd": [
        r"uhttpd[-/ ]([0-9][\w.\-]+)"
    ]
}

CVE_HINTS = {
    "busybox": {
        "note": "BusyBox is frequently old in embedded firmware. Verify exact version against NVD/vendor advisories.",
        "keywords": ["busybox", "ash", "udhcp", "telnetd"]
    },
    "openssl": {
        "note": "OpenSSL version detected. Check for old TLS/crypto CVEs and weak certificate/key usage.",
        "keywords": ["openssl", "libssl", "libcrypto"]
    },
    "dropbear": {
        "note": "Dropbear SSH detected. Check version against Dropbear security advisories.",
        "keywords": ["dropbear", "sshd"]
    },
    "dnsmasq": {
        "note": "dnsmasq detected. Check version for DNS/DHCP vulnerabilities.",
        "keywords": ["dnsmasq"]
    },
    "boa": {
        "note": "Boa web server is commonly outdated in IoT firmware.",
        "keywords": ["boa"]
    }
}

IMPORTANT_SECTIONS = [
    ("Credential Findings", "credential_findings", "credential_findings.txt"),
    ("Possible Passwords", "possible_password", "possible_passwords.txt"),
    ("Wi-Fi PSKs", "wifi_psk", "wifi_psks.txt"),
    ("Possible Usernames", "possible_username", "possible_usernames.txt"),
    ("API Keys / Secrets", "api_key", "api_keys.txt"),
    ("MQTT Credentials", "mqtt_credential", "mqtt_credentials.txt"),
    ("JWT Tokens", "jwt", "jwt_tokens.txt"),
    ("Private Keys", "private_keys", "private_keys.txt"),
    ("Certificates", "certificates", "certificates.txt"),
    ("IP Addresses", "ipv4", "ip_addresses.txt"),
    ("MAC Addresses", "mac_address", "mac_addresses.txt"),
    ("URLs", "url", "urls.txt"),
    ("Domains", "domain", "domains.txt"),
    ("Emails", "email", "emails.txt"),
    ("Component Versions", "components", "components.txt"),
    ("Version Strings", "version_strings", "version_strings.txt"),
    ("Firmware Identity", "firmware_identity", "firmware_identity.txt"),
    ("Startup Scripts", "startup_scripts", "startup_scripts.txt"),
    ("Interesting Files", "interesting_files", "interesting_files.txt"),
    ("Interesting Binaries", "interesting_binaries", "interesting_binaries.txt"),
    ("ELF Binaries", "elf_binaries", "elf_binaries.txt"),
    ("Architecture Summary", "architecture_summary", "architecture_summary.txt"),
    ("Web Files", "web_files", "web_files.txt"),
    ("Web Routes", "web_routes", "web_routes.txt"),
    ("Web Endpoints", "web_endpoints", "web_endpoints.txt"),
    ("Cron Jobs", "cron_jobs", "cron_jobs.txt"),
    ("Users / Groups", "users_groups", "users_groups.txt"),
    ("SSH Related Files", "ssh_related", "ssh_related.txt"),
    ("Suspicious Keywords", "suspicious_keywords", "suspicious_keywords.txt"),
    ("Malware IOC Matches", "malware_iocs", "malware_iocs.txt"),
    ("High Entropy Files", "high_entropy_files", "high_entropy_files.txt"),
    ("Largest Files", "largest_files", "largest_files.txt"),
    ("BusyBox Findings", "busybox", "busybox.txt"),
    ("CVE References", "cve_references", "cve_references.txt"),
    ("CVE Hints", "cve_hints", "cve_hints.txt"),
    ("YARA Matches", "yara_matches", "yara_matches.txt"),
    ("Plugin Findings", "plugin_findings", "plugin_findings.txt"),
    ("Skipped Large Files", "skipped_large_files", "skipped_large_files.txt"),
    ("Tool Warnings", "tool_warnings", "tool_warnings.txt"),
    ("Scan Errors", "scan_errors", "scan_errors.txt"),
]


# =============================================================================
# BASIC HELPERS
# =============================================================================

def add(category, data):
    """Thread-safe de-duplicated report append."""
    with REPORT_LOCK:
        if data not in REPORT[category]:
            REPORT[category].append(data)


def safe_rel(path, root):
    try:
        return str(Path(path).resolve().relative_to(Path(root).resolve()))
    except Exception:
        return str(path)


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def check_dependencies(yara_requested=False, extract_requested=False):
    dependencies = ["strings"]
    if yara_requested:
        dependencies.append("yara")
    if extract_requested:
        dependencies.append("binwalk")

    for tool in dependencies:
        if shutil.which(tool) is None:
            add("tool_warnings", {
                "tool": tool,
                "warning": f"'{tool}' was not found in PATH. Some features may be limited."
            })
            print(f"[!] Warning: '{tool}' not found. Some features may be limited.")


def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def entropy_file(path, max_bytes=1024 * 1024):
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
        return round(entropy, 4)
    except Exception:
        return None


def is_text_file(path):
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as f:
            chunk = f.read(4096)
        if not chunk:
            return False
        return chunk.count(b"\x00") / len(chunk) < 0.08
    except Exception:
        return False


def read_text(path, max_chars=None):
    try:
        text = path.read_text(errors="ignore")
        if max_chars:
            return text[:max_chars]
        return text
    except Exception:
        return ""


def is_elf(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False


def elf_info(path):
    try:
        with open(path, "rb") as f:
            header = f.read(20)

        if len(header) < 20:
            return {}

        elf_class = header[4]
        endian = header[5]
        byte_order = "little" if endian == 1 else "big" if endian == 2 else "little"
        machine = int.from_bytes(header[18:20], byte_order)

        arch_map = {
            3: "x86",
            8: "MIPS",
            20: "PowerPC",
            40: "ARM",
            62: "x86_64",
            183: "AArch64",
            243: "RISC-V"
        }

        return {
            "class": "32-bit" if elf_class == 1 else "64-bit" if elf_class == 2 else "unknown",
            "endian": "little" if endian == 1 else "big" if endian == 2 else "unknown",
            "machine": arch_map.get(machine, f"unknown-{machine}")
        }
    except Exception:
        return {}


def run_strings(path, limit=1200):
    try:
        result = subprocess.run(
            ["strings", str(path)],
            capture_output=True,
            text=True,
            timeout=20,
            errors="ignore"
        )
        return result.stdout.splitlines()[:limit]
    except Exception:
        return []


def run_file_cmd(path):
    if shutil.which("file") is None:
        return None
    try:
        result = subprocess.run(
            ["file", "-b", str(path)],
            capture_output=True,
            text=True,
            timeout=5,
            errors="ignore"
        )
        return result.stdout.strip()
    except Exception:
        return None


# =============================================================================
# EXTRACTION
# =============================================================================

def extract_with_binwalk(firmware_image, output_base):
    firmware_image = Path(firmware_image).resolve()
    extract_dir = Path(output_base).resolve() / f"binwalk_extract_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
    extract_dir.mkdir(parents=True, exist_ok=True)

    if shutil.which("binwalk") is None:
        raise RuntimeError("binwalk not found. Install it or scan an already extracted rootfs directory.")

    print(f"[+] Extracting with binwalk into: {extract_dir}")
    try:
        subprocess.run(
            ["binwalk", "-Me", str(firmware_image), "--directory", str(extract_dir)],
            check=False,
            timeout=1800
        )
    except subprocess.TimeoutExpired:
        add("tool_warnings", {"tool": "binwalk", "warning": "binwalk extraction timed out"})
    except Exception as e:
        add("tool_warnings", {"tool": "binwalk", "warning": f"binwalk extraction failed: {e}"})

    candidates = find_rootfs_candidates(extract_dir)
    if candidates:
        print("[+] Possible rootfs candidates:")
        for idx, cand in enumerate(candidates[:10], 1):
            print(f"    {idx}. {cand}")
        return candidates[0]

    print("[!] No obvious rootfs found. Scanning extraction directory instead.")
    return extract_dir


def find_rootfs_candidates(base_dir):
    base_dir = Path(base_dir)
    candidates = []

    for dirpath, dirnames, filenames in os.walk(base_dir):
        d = Path(dirpath)
        names = set(filenames) | set(dirnames)
        score = 0

        if "etc" in names:
            score += 3
        if "bin" in names:
            score += 2
        if "sbin" in names:
            score += 2
        if "www" in names or "web" in names or "htdocs" in names:
            score += 2
        if "passwd" in names or "shadow" in names:
            score += 2
        if "init.d" in names:
            score += 2

        if score >= 5:
            candidates.append((score, d))

    candidates.sort(key=lambda x: x[0], reverse=True)
    return [c[1] for c in candidates]


# =============================================================================
# SCANNERS
# =============================================================================

def extract_version_strings(text):
    patterns = [
        r"(?i)(version|build|release|fw_ver|firmware|software|sw_ver|hardware|hw_ver|model|vendor|product)\s*[:=]\s*['\"]?([\w.\-/ ]{3,80})",
        r"(?i)(busybox\s+v\d{1,3}\.\d{1,3}(?:\.\d{1,5})?)",
        r"(?i)(linux\s+version\s+[\w.\-]+)",
        r"\bV(\d{1,3}\.\d{1,3}\.\d{1,5})\b",
        r"\b(\d{4}-\d{2}-\d{2})\b",
    ]

    versions = set()

    for pattern in patterns:
        for match in re.findall(pattern, text):
            if isinstance(match, tuple):
                value = match[-1]
            else:
                value = match
            value = " ".join(value.strip().split())
            if 3 <= len(value) <= 120:
                versions.add(value)

    return sorted(versions)[:40]


def detect_components(text, rel_path):
    for component, patterns in COMPONENT_PATTERNS.items():
        for pattern in patterns:
            for match in re.findall(pattern, text, re.I):
                version = match[-1] if isinstance(match, tuple) else match
                version = str(version).strip()
                if version:
                    add("components", {
                        "component": component,
                        "version": version,
                        "file": rel_path
                    })
                    if component in CVE_HINTS:
                        add("cve_hints", {
                            "component": component,
                            "version": version,
                            "file": rel_path,
                            "note": CVE_HINTS[component]["note"]
                        })


def detect_malware_iocs(text, rel_path):
    low = text.lower()
    for family, indicators in MALWARE_IOC_KEYWORDS.items():
        hits = []
        for indicator in indicators:
            if indicator.lower() in low:
                hits.append(indicator)
        if hits:
            add("malware_iocs", {
                "family_or_category": family,
                "file": rel_path,
                "indicators": sorted(set(hits)),
                "confidence": "medium" if len(hits) == 1 else "high"
            })


def scan_text_content(path, content, rel_path):
    for name, pattern in REGEX_PATTERNS.items():
        for match in re.findall(pattern, content):
            if isinstance(match, tuple):
                finding = {"file": rel_path, "key": match[0], "value": match[1]}
                value_for_validation = match[1]
            else:
                finding = {"file": rel_path, "value": match}
                value_for_validation = match

            if name == "ipv4":
                parts = value_for_validation.split(".")
                if not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    continue

            add(name, finding)

            if name in {"possible_password", "wifi_psk", "api_key", "mqtt_credential"}:
                add_credential_finding(name, finding)

    for marker in PRIVATE_KEY_MARKERS:
        if marker in content:
            add("private_keys", {"file": rel_path, "marker": marker})
            add("credential_findings", {
                "file": rel_path,
                "type": "private_key",
                "value": marker,
                "confidence": "high",
                "severity": "critical",
                "reason": "Private key material marker found"
            })

    for marker in CERT_MARKERS:
        if marker in content:
            add("certificates", {"file": rel_path, "marker": marker})

    lowered = content.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in lowered:
            add("suspicious_keywords", {"file": rel_path, "keyword": keyword})

    versions = extract_version_strings(content)
    if versions:
        add("version_strings", {"file": rel_path, "versions": versions})

    detect_components(content, rel_path)
    detect_malware_iocs(content, rel_path)


def add_credential_finding(kind, finding):
    value = str(finding.get("value", ""))
    key = str(finding.get("key", ""))
    file = finding.get("file", "")

    confidence = "medium"
    severity = "medium"
    reasons = []

    if kind in {"api_key", "wifi_psk"}:
        confidence = "high"
        severity = "high"
        reasons.append(f"{kind} pattern matched")

    if key.lower() in {"password", "passwd", "pwd", "admin_pass", "root_pass", "secret", "token"}:
        confidence = "high"
        severity = "high"
        reasons.append("credential-like key name")

    if value.lower() in {"admin", "root", "password", "123456", "12345678", "admin123", "root123"}:
        confidence = "high"
        severity = "high"
        reasons.append("common/default credential value")

    if any(x in file.lower() for x in ["shadow", "passwd", "default", "config", "nvram", "wpa"]):
        reasons.append("sensitive config path")
        if confidence == "medium":
            confidence = "high"

    add("credential_findings", {
        "file": file,
        "type": kind,
        "key": key,
        "value": value,
        "confidence": confidence,
        "severity": severity,
        "reason": "; ".join(reasons) if reasons else "credential-like pattern matched"
    })


def classify_path(path, root, size, rel_path):
    lower = str(path).lower()
    name = path.name.lower()

    info = {"file": rel_path, "sha256": sha256_file(path), "size": size}

    if name in INTERESTING_NAMES:
        add("interesting_files", info)

    if any(p in lower for p in ["/etc/init.d", "/etc/rc", "/etc/inittab", "/etc/services", "/lib/systemd"]):
        add("startup_scripts", info)

    if any(p in lower for p in ["/www", "/web", "/htdocs", "/cgi-bin", "/var/www"]):
        add("web_files", info)

    if any(x in name for x in ["config", ".conf", ".cfg", ".ini", ".json", ".xml", ".yaml", ".yml"]):
        add("config_files", info)

    if "cron" in lower or "crontab" in lower:
        add("cron_jobs", info)

    if name in {"passwd", "shadow", "group"}:
        add("users_groups", info)

    if any(x in lower for x in ["ssh", "dropbear", "authorized_keys", "host_key"]):
        add("ssh_related", info)

    if name in EXECUTABLE_NAMES:
        add("interesting_binaries", {**info, "reason": "Common embedded Linux service or utility"})


def scan_busybox(path, text, rel_path):
    if "busybox" not in str(path).lower() and "busybox" not in text.lower():
        return

    banner = re.search(r"BusyBox v[\w.\-]+", text)
    applet_hits = []
    applet_keywords = ["telnet", "wget", "tftp", "httpd", "ash", "sh", "nc", "ftpget", "ftpput"]

    for line in text.splitlines():
        low = line.lower()
        if any(x in low for x in applet_keywords) and len(line.strip()) < 250:
            applet_hits.append(line.strip())

    risky_applets = []
    for app in applet_keywords:
        if app in text.lower():
            risky_applets.append(app)

    add("busybox", {
        "file": rel_path,
        "banner": banner.group(0) if banner else None,
        "risky_applet_hints": sorted(set(risky_applets)),
        "possible_applets_or_strings": sorted(set(applet_hits))[:100]
    })


def scan_web_endpoints(path, content, rel_path):
    lower_path = str(path).lower()

    if not any(x in lower_path for x in ["/www", "/web", "/htdocs", "/cgi-bin", ".html", ".js", ".php", ".cgi", ".asp"]):
        return

    endpoints = re.findall(r"[\"'](/[^\"'\s<>]{2,})[\"']", content)
    forms = re.findall(r"(?i)<form[^>]+action=[\"']?([^\"'>\s]+)", content)
    scripts = re.findall(r"(?i)<script[^>]+src=[\"']?([^\"'>\s]+)", content)
    ajax = re.findall(r"(?i)(?:url|href|src)\s*[:=]\s*[\"']([^\"']+)[\"']", content)
    cgi = re.findall(r"[\w./-]+\.cgi(?:\?[^\"'\s<>]*)?", content)

    admin_hits = []
    for route in set(endpoints + forms + scripts + ajax + cgi):
        if any(k in route.lower() for k in ["admin", "login", "password", "upgrade", "firmware", "reboot", "debug", "shell", "system", "config"]):
            admin_hits.append(route)

    if endpoints or forms or scripts or ajax or cgi:
        data = {
            "file": rel_path,
            "endpoints": sorted(set(endpoints))[:150],
            "forms": sorted(set(forms))[:80],
            "scripts": sorted(set(scripts))[:80],
            "ajax_or_refs": sorted(set(ajax))[:120],
            "cgi_refs": sorted(set(cgi))[:120],
            "admin_like_routes": sorted(set(admin_hits))[:120]
        }
        add("web_endpoints", data)

        for route in sorted(set(endpoints + forms + scripts + ajax + cgi + admin_hits)):
            if len(route) < 300:
                add("web_routes", {
                    "route": route,
                    "file": rel_path,
                    "admin_like": route in admin_hits
                })


def scan_possible_cves(content, rel_path):
    for cve in re.findall(r"CVE-\d{4}-\d{4,7}", content, re.I):
        add("cve_references", {"file": rel_path, "cve": cve.upper()})


def yara_scan_file(path, rel_path, yara_rule_path):
    if not yara_rule_path:
        return

    try:
        result = subprocess.run(
            ["yara", "-r", str(yara_rule_path), str(path)],
            capture_output=True,
            text=True,
            timeout=25
        )

        if result.stdout.strip():
            add("yara_matches", {
                "file": rel_path,
                "matches": result.stdout.strip().splitlines()
            })

    except FileNotFoundError:
        add("tool_warnings", {"tool": "yara", "warning": "YARA is not installed or not in PATH"})
    except Exception as e:
        add("scan_errors", {"file": rel_path, "error": f"YARA scan failed: {e}"})


def scan_file(path, root, yara_rules=None, quick=False):
    try:
        if not path.is_file():
            return

        size = path.stat().st_size
        rel_path = safe_rel(path, root)

        classify_path(path, root, size, rel_path)

        if quick and size > 10_000_000:
            add("skipped_large_files", {
                "file": rel_path,
                "size": size,
                "reason": "Skipped because --quick mode is enabled"
            })
            return

        ent = entropy_file(path)
        if ent is not None and ent >= 7.5 and size > 1024:
            add("high_entropy_files", {
                "file": rel_path,
                "entropy": ent,
                "size": size,
                "sha256": sha256_file(path),
                "note": "May indicate compression, encryption, packed data, or a binary blob"
            })

        if is_elf(path):
            info = elf_info(path)
            file_desc = run_file_cmd(path)
            add("elf_binaries", {
                "file": rel_path,
                "sha256": sha256_file(path),
                "size": size,
                "elf": info,
                "file_cmd": file_desc
            })

            strings_text = "\n".join(run_strings(path))
            scan_text_content(path, strings_text, rel_path)
            scan_busybox(path, strings_text, rel_path)
            scan_possible_cves(strings_text, rel_path)

        if is_text_file(path):
            content = read_text(path)
            scan_text_content(path, content, rel_path)
            scan_web_endpoints(path, content, rel_path)
            scan_possible_cves(content, rel_path)
            scan_busybox(path, content, rel_path)

        if yara_rules:
            yara_scan_file(path, rel_path, yara_rules)

    except Exception as e:
        add("scan_errors", {"file": str(path), "error": str(e)})


# =============================================================================
# POST PROCESSING
# =============================================================================

def detect_firmware_identity(root):
    identity_files = [
        "etc/os-release", "etc/openwrt_release", "etc/openwrt_version",
        "etc/version", "etc/banner", "etc/issue", "version", "release"
    ]

    for rel in identity_files:
        path = Path(root) / rel
        if path.exists() and path.is_file():
            text = read_text(path, max_chars=5000)
            if text:
                add("firmware_identity", {
                    "file": rel,
                    "content_preview": text[:1000]
                })

    # Heuristic identity from config/version strings
    vendor_model_keywords = ["model", "vendor", "product", "device", "board", "firmware", "version"]
    for item in REPORT.get("version_strings", [])[:200]:
        versions = item.get("versions", [])
        hits = [v for v in versions if any(k in v.lower() for k in vendor_model_keywords)]
        if hits:
            add("firmware_identity", {
                "file": item.get("file"),
                "identity_hints": hits[:20]
            })


def summarize_architecture():
    machines = Counter()
    endians = Counter()
    classes = Counter()

    for item in REPORT.get("elf_binaries", []):
        elf = item.get("elf", {})
        if elf.get("machine"):
            machines[elf["machine"]] += 1
        if elf.get("endian"):
            endians[elf["endian"]] += 1
        if elf.get("class"):
            classes[elf["class"]] += 1

    if machines or endians or classes:
        add("architecture_summary", {
            "machines": dict(machines.most_common()),
            "endian": dict(endians.most_common()),
            "class": dict(classes.most_common())
        })


def summarize_largest_files(root, limit=30):
    files = []
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            p = Path(dirpath) / filename
            try:
                if p.is_file():
                    files.append((p.stat().st_size, safe_rel(p, root), sha256_file(p)))
            except Exception:
                pass

    for size, rel, digest in sorted(files, reverse=True)[:limit]:
        add("largest_files", {"file": rel, "size": size, "sha256": digest})


def run_plugins(plugin_dir, root):
    if not plugin_dir:
        return

    plugin_dir = Path(plugin_dir)
    if not plugin_dir.exists():
        add("tool_warnings", {"tool": "plugins", "warning": f"Plugin directory not found: {plugin_dir}"})
        return

    for plugin_file in plugin_dir.glob("*.py"):
        try:
            spec = importlib.util.spec_from_file_location(plugin_file.stem, plugin_file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            if hasattr(module, "scan"):
                result = module.scan(str(root))
                add("plugin_findings", {
                    "plugin": plugin_file.name,
                    "result": result
                })
            else:
                add("tool_warnings", {
                    "tool": "plugins",
                    "warning": f"{plugin_file.name} has no scan(root) function"
                })
        except Exception as e:
            add("scan_errors", {
                "file": str(plugin_file),
                "error": f"Plugin failed: {e}"
            })


def score_findings():
    weights = {
        "private_keys": 35,
        "credential_findings": 20,
        "possible_password": 15,
        "wifi_psk": 15,
        "api_key": 15,
        "jwt": 15,
        "users_groups": 12,
        "yara_matches": 35,
        "malware_iocs": 30,
        "interesting_binaries": 8,
        "suspicious_keywords": 6,
        "web_routes": 5,
        "web_endpoints": 5,
        "ssh_related": 5,
        "startup_scripts": 5,
        "cve_references": 5,
        "cve_hints": 3,
    }

    score = 0
    reasons = []

    for category, weight in weights.items():
        count = len(REPORT.get(category, []))
        if count:
            added = min(count * weight, weight * 6)
            score += added
            reasons.append(f"{category}: {count} finding(s), +{added}")

    critical = any(x.get("severity") == "critical" for x in REPORT.get("credential_findings", []) if isinstance(x, dict))
    malware = len(REPORT.get("malware_iocs", [])) > 0

    if score >= 180 or critical or malware:
        level = "CRITICAL" if critical or malware else "HIGH"
    elif score >= 100:
        level = "HIGH"
    elif score >= 50:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "NONE"

    REPORT["risk_summary"] = [{
        "score": score,
        "level": level,
        "reasons": reasons,
        "notes": [
            "Risk score is a triage aid, not proof of compromise.",
            "Manually validate credentials, CVEs, and malware indicators."
        ]
    }]


# =============================================================================
# REPORTING
# =============================================================================

def write_list_file(output_dir, filename, title, items):
    path = output_dir / filename

    with open(path, "w", encoding="utf-8") as f:
        f.write(title + "\n")
        f.write("=" * 100 + "\n\n")

        if not items:
            f.write("No findings.\n")
            return path

        for item in items:
            if isinstance(item, dict):
                for k, v in item.items():
                    f.write(f"{k}: {v}\n")
                f.write("-" * 100 + "\n")
            else:
                f.write(str(item) + "\n")

    return path


def write_csv(output_dir):
    csv_file = output_dir / "findings.csv"
    rows = []

    for title, key, _filename in IMPORTANT_SECTIONS:
        for item in REPORT.get(key, []):
            if isinstance(item, dict):
                rows.append({
                    "category": key,
                    "title": title,
                    "file": item.get("file", ""),
                    "value": item.get("value", item.get("route", item.get("component", ""))),
                    "severity": item.get("severity", ""),
                    "confidence": item.get("confidence", ""),
                    "details": json.dumps(item, ensure_ascii=False)
                })
            else:
                rows.append({
                    "category": key,
                    "title": title,
                    "file": "",
                    "value": str(item),
                    "severity": "",
                    "confidence": "",
                    "details": str(item)
                })

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["category", "title", "file", "value", "severity", "confidence", "details"])
        writer.writeheader()
        writer.writerows(rows)

    return csv_file


def write_markdown(output_dir):
    md_file = output_dir / "firmware_report.md"
    risk = REPORT.get("risk_summary", [{}])[0]
    totals = REPORT.get("scan_totals", [{}])[0]
    meta = REPORT.get("scan_metadata", [{}])[0]

    with open(md_file, "w", encoding="utf-8") as f:
        f.write(f"# Firmware Hunter Pro v{VERSION} Report\n\n")
        f.write("## Scan Info\n\n")
        f.write(f"- Firmware root: `{meta.get('root', 'Unknown')}`\n")
        f.write(f"- Started: `{meta.get('started', 'Unknown')}`\n")
        f.write(f"- Finished: `{meta.get('finished', 'Unknown')}`\n")
        f.write(f"- Total files: `{totals.get('total_files', 0)}`\n")
        f.write(f"- Total size: `{totals.get('total_size_bytes', 0)}` bytes\n")
        f.write(f"- Quick mode: `{meta.get('quick_mode', False)}`\n\n")

        f.write("## Risk Summary\n\n")
        f.write(f"- Level: **{risk.get('level', 'UNKNOWN')}**\n")
        f.write(f"- Score: **{risk.get('score', 0)}**\n\n")

        f.write("## Findings Overview\n\n")
        f.write("| Finding | Count |\n|---|---:|\n")
        for title, key, _ in IMPORTANT_SECTIONS:
            count = len(REPORT.get(key, []))
            if count:
                f.write(f"| {title} | {count} |\n")

        f.write("\n## Recommended Next Steps\n\n")
        for step in recommended_steps():
            f.write(f"- {step}\n")

    return md_file


def write_html_report(output_dir):
    html_file = output_dir / "firmware_report.html"
    risk = REPORT.get("risk_summary", [{}])[0]
    totals = REPORT.get("scan_totals", [{}])[0]
    meta = REPORT.get("scan_metadata", [{}])[0]

    severity_color = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#22c55e",
        "NONE": "#94a3b8"
    }.get(risk.get("level", "UNKNOWN"), "#94a3b8")

    with open(html_file, "w", encoding="utf-8") as f:
        f.write(f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Firmware Hunter Pro Report</title>
<style>
body {{ font-family: Arial, sans-serif; background: #0f172a; color: #e5e7eb; margin: 0; }}
header {{ background: #020617; padding: 24px 32px; border-bottom: 1px solid #334155; }}
main {{ padding: 24px 32px; }}
h1 {{ margin: 0; color: #7dd3fc; }}
h2 {{ color: #bfdbfe; margin-top: 28px; }}
.card {{ background: #111827; border: 1px solid #334155; border-radius: 14px; padding: 18px; margin-bottom: 18px; box-shadow: 0 10px 24px rgba(0,0,0,.25); }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; }}
.metric {{ background: #1e293b; border-radius: 12px; padding: 14px; border: 1px solid #334155; }}
.metric b {{ display: block; color: #93c5fd; margin-bottom: 8px; }}
.badge {{ display: inline-block; padding: 6px 12px; border-radius: 999px; background: {severity_color}; color: #111827; font-weight: bold; }}
pre {{ background: #020617; color: #d1d5db; padding: 14px; border-radius: 10px; overflow-x: auto; }}
details {{ margin: 12px 0; background: #111827; border: 1px solid #334155; border-radius: 10px; padding: 12px; }}
summary {{ cursor: pointer; font-weight: bold; color: #93c5fd; }}
.count {{ color: #facc15; font-weight: bold; }}
input {{ width: 100%; padding: 12px; border-radius: 10px; border: 1px solid #334155; background: #020617; color: #e5e7eb; margin: 12px 0; }}
.small {{ color: #94a3b8; font-size: 13px; }}
a {{ color: #93c5fd; }}
</style>
<script>
function filterFindings() {{
  var input = document.getElementById("search").value.toLowerCase();
  var blocks = document.getElementsByTagName("details");
  for (var i = 0; i < blocks.length; i++) {{
    var text = blocks[i].innerText.toLowerCase();
    blocks[i].style.display = text.includes(input) ? "" : "none";
  }}
}}
</script>
</head>
<body>
<header>
<h1>Firmware Hunter Pro v{VERSION}</h1>
<p class="small">Offline firmware triage report</p>
</header>
<main>
<div class="grid">
<div class="metric"><b>Risk</b><span class="badge">{html.escape(str(risk.get('level', 'UNKNOWN')))}</span></div>
<div class="metric"><b>Risk Score</b>{html.escape(str(risk.get('score', 0)))}</div>
<div class="metric"><b>Total Files</b>{html.escape(str(totals.get('total_files', 0)))}</div>
<div class="metric"><b>Total Size</b>{html.escape(str(totals.get('total_size_bytes', 0)))} bytes</div>
</div>

<div class="card">
<h2>Scan Info</h2>
<p><b>Firmware Root:</b> {html.escape(str(meta.get('root', 'Unknown')))}</p>
<p><b>Started:</b> {html.escape(str(meta.get('started', 'Unknown')))}</p>
<p><b>Finished:</b> {html.escape(str(meta.get('finished', 'Unknown')))}</p>
<p><b>Quick Mode:</b> {html.escape(str(meta.get('quick_mode', False)))}</p>
<p><b>Worker Jobs:</b> {html.escape(str(meta.get('jobs', 'Unknown')))}</p>
</div>

<div class="card">
<h2>Findings Overview</h2>
""")

        for title, key, filename in IMPORTANT_SECTIONS:
            count = len(REPORT.get(key, []))
            if count:
                f.write(f"<p><b>{html.escape(title)}</b>: <span class='count'>{count}</span> — {html.escape(filename)}</p>\n")

        f.write("""</div>
<div class="card">
<h2>Recommended Next Steps</h2>
<ul>
""")
        for step in recommended_steps():
            f.write(f"<li>{html.escape(step)}</li>\n")

        f.write("""</ul>
</div>

<h2>Detailed Findings</h2>
<input id="search" onkeyup="filterFindings()" placeholder="Search findings...">
""")

        for title, key, _filename in IMPORTANT_SECTIONS:
            items = REPORT.get(key, [])
            if not items:
                continue
            f.write(f"<details><summary>{html.escape(title)} ({len(items)})</summary>\n")
            f.write("<pre>")
            f.write(html.escape(json.dumps(items, indent=2, ensure_ascii=False)))
            f.write("</pre></details>\n")

        f.write("</main></body></html>")

    return html_file


def recommended_steps():
    return [
        "Review credential_findings.txt, possible_passwords.txt, and wifi_psks.txt for hardcoded credentials.",
        "Review startup_scripts.txt to understand what starts at boot.",
        "Review web_routes.txt and web_endpoints.txt for login panels, CGI handlers, firmware update routes, and debug routes.",
        "Review interesting_binaries.txt for telnet, dropbear, busybox, wget, tftp, netcat, and web servers.",
        "Review private_keys.txt and certificates.txt for exposed secrets or reused keys.",
        "Review components.txt and cve_hints.txt, then verify versions against authoritative vulnerability databases.",
        "Review malware_iocs.txt and yara_matches.txt, then manually validate before making conclusions.",
        "Use full_report.json or findings.csv for automation, diffing, or importing into other tools."
    ]


def write_reports(base_output):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = Path(base_output) / f"scan_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    json_file = output_dir / "full_report.json"
    main_report = output_dir / "firmware_report.txt"
    summary_file = output_dir / "summary.txt"

    normal_report = {k: v for k, v in REPORT.items()}

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(normal_report, f, indent=4, ensure_ascii=False)

    risk = REPORT.get("risk_summary", [{}])[0]
    totals = REPORT.get("scan_totals", [{}])[0]
    meta = REPORT.get("scan_metadata", [{}])[0]

    for title, key, filename in IMPORTANT_SECTIONS:
        items = REPORT.get(key, [])
        if items:
            write_list_file(output_dir, filename, title, items)

    csv_file = write_csv(output_dir)
    md_file = write_markdown(output_dir)
    html_file = write_html_report(output_dir)

    with open(summary_file, "w", encoding="utf-8") as f:
        f.write("Firmware Hunter Pro Summary\n")
        f.write("=" * 100 + "\n\n")
        f.write(f"Scan Time:     {timestamp}\n")
        f.write(f"Firmware Root: {meta.get('root', 'Unknown')}\n")
        f.write(f"Quick Mode:    {meta.get('quick_mode', False)}\n")
        f.write(f"Jobs:          {meta.get('jobs', 'Unknown')}\n")
        f.write(f"Total Files:   {totals.get('total_files', 0)}\n")
        f.write(f"Total Size:    {totals.get('total_size_bytes', 0)} bytes\n\n")

        f.write("Risk Summary\n")
        f.write("-" * 100 + "\n")
        f.write(f"Risk Level:    {risk.get('level', 'UNKNOWN')}\n")
        f.write(f"Risk Score:    {risk.get('score', 0)}\n\n")

        f.write("Finding Counts\n")
        f.write("-" * 100 + "\n")
        for title, key, _ in IMPORTANT_SECTIONS:
            count = len(REPORT.get(key, []))
            if count:
                f.write(f"{title:<35} {count}\n")

    with open(main_report, "w", encoding="utf-8") as f:
        f.write("Firmware Hunter Pro Report\n")
        f.write("=" * 100 + "\n")
        f.write("Offline firmware triage report\n")
        f.write("=" * 100 + "\n\n")

        f.write("[SCAN INFO]\n")
        f.write(f"Firmware Root : {meta.get('root', 'Unknown')}\n")
        f.write(f"Started       : {meta.get('started', 'Unknown')}\n")
        f.write(f"Finished      : {meta.get('finished', 'Unknown')}\n")
        f.write(f"Quick Mode    : {meta.get('quick_mode', False)}\n")
        f.write(f"Worker Jobs   : {meta.get('jobs', 'Unknown')}\n")
        f.write(f"Total Files   : {totals.get('total_files', 0)}\n")
        f.write(f"Total Size    : {totals.get('total_size_bytes', 0)} bytes\n\n")

        f.write("[RISK SUMMARY]\n")
        f.write(f"Level         : {risk.get('level', 'UNKNOWN')}\n")
        f.write(f"Score         : {risk.get('score', 0)}\n\n")

        if risk.get("reasons"):
            f.write("Reasons:\n")
            for reason in risk.get("reasons", []):
                f.write(f"  - {reason}\n")
            f.write("\n")

        f.write("[FINDINGS OVERVIEW]\n")
        for title, key, filename in IMPORTANT_SECTIONS:
            count = len(REPORT.get(key, []))
            if count:
                f.write(f"[+] {title:<35} {count:<5} -> {filename}\n")
            else:
                f.write(f"[-] {title:<35} 0\n")

        f.write("\n[RECOMMENDED NEXT STEPS]\n")
        f.write("-" * 100 + "\n")
        for idx, step in enumerate(recommended_steps(), 1):
            f.write(f"{idx}. {step}\n")

        f.write("\n[GENERATED FILES]\n")
        for file in sorted(output_dir.iterdir()):
            f.write(f"- {file.name}\n")

    print()
    print("=" * 100)
    print(" Firmware Hunter Pro Scan Complete")
    print("=" * 100)
    print(f" Output Folder : {output_dir}")
    print(f" Main Report   : {main_report}")
    print(f" Summary       : {summary_file}")
    print(f" HTML Report   : {html_file}")
    print(f" Markdown      : {md_file}")
    print(f" CSV Findings  : {csv_file}")
    print(f" JSON Report   : {json_file}")
    print("=" * 100)


# =============================================================================
# MAIN SCAN
# =============================================================================

def scan_firmware(root, yara_rules=None, quick=False, jobs=8, plugins=None):
    root = Path(root).resolve()

    if not root.exists():
        raise FileNotFoundError(f"Firmware path does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Firmware path should be an extracted directory/rootfs: {root}")

    files = []
    total_size = 0

    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            path = Path(dirpath) / filename
            if path.is_file():
                files.append(path)
                try:
                    total_size += path.stat().st_size
                except Exception:
                    pass

    REPORT["scan_metadata"] = [{
        "tool": "Firmware Hunter Pro",
        "version": VERSION,
        "root": str(root),
        "started": now_iso(),
        "quick_mode": quick,
        "jobs": jobs,
        "yara_rules": str(yara_rules) if yara_rules else None,
        "plugins": str(plugins) if plugins else None
    }]

    print(f"[+] Files discovered: {len(files)}")
    print(f"[+] Total size: {total_size} bytes")
    print(f"[+] Worker threads: {jobs}")

    completed = 0
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=max(1, jobs)) as executor:
        futures = [executor.submit(scan_file, f, root, yara_rules, quick) for f in files]

        for future in as_completed(futures):
            completed += 1
            try:
                future.result()
            except Exception as e:
                add("scan_errors", {"file": "unknown", "error": str(e)})

            if completed % 500 == 0:
                elapsed = max(time.time() - start_time, 1)
                rate = completed / elapsed
                print(f"[+] Progress: {completed}/{len(files)} files scanned ({rate:.1f} files/sec)")

    detect_firmware_identity(root)
    summarize_architecture()
    summarize_largest_files(root)
    run_plugins(plugins, root)
    score_findings()

    REPORT["scan_totals"] = [{
        "total_files": len(files),
        "total_size_bytes": total_size,
        "elapsed_seconds": round(time.time() - start_time, 2)
    }]

    REPORT["scan_metadata"][0]["finished"] = now_iso()


def main():
    parser = argparse.ArgumentParser(
        description="Firmware Hunter Pro v4.0 - advanced offline firmware triage scanner"
    )

    parser.add_argument("target", help="Path to extracted firmware/rootfs directory, or firmware image with --extract")
    parser.add_argument("-o", "--output", default="firmware_hunter_output", help="Base output directory")
    parser.add_argument("--extract", action="store_true", help="Use binwalk to extract target first, then scan extraction")
    parser.add_argument("--yara", help="Optional path to YARA rule file or directory")
    parser.add_argument("--quick", action="store_true", help="Quick mode: skip files larger than 10 MB")
    parser.add_argument("-j", "--jobs", type=int, default=8, help="Number of worker threads, default: 8")
    parser.add_argument("--plugins", help="Optional plugins directory. Each plugin should expose scan(root).")

    args = parser.parse_args()

    print(f"[+] Firmware Hunter Pro v{VERSION}")
    print("[+] Safe mode: this tool does not execute firmware binaries.")

    check_dependencies(yara_requested=bool(args.yara), extract_requested=args.extract)

    target = Path(args.target).resolve()

    if args.extract:
        scan_root = extract_with_binwalk(target, args.output)
    else:
        scan_root = target

    print(f"[+] Scanning: {scan_root}")

    scan_firmware(
        scan_root,
        yara_rules=args.yara,
        quick=args.quick,
        jobs=args.jobs,
        plugins=args.plugins
    )

    write_reports(args.output)


if __name__ == "__main__":
    main()
