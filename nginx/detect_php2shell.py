#!/usr/bin/env python3
"""
detect_php2shell.py
--------------------
Automatisierte Erkennung, Klassifikation und Extraktion von Angriffsversuchen
auf die PHP_SESSION_UPLOAD_PROGRESS / php2shell Schwachstelle (LFI-to-RCE)
und React2Shell (CVE-2025-55182).

Funktionen:
- Regelbasierte Auswertung (R1 - R11) und Einstufung in Tiers (T0 - T5)
- Extraktion von Payloads aus multipart/form-data Bodies ($request_body)
- Suche nach Scanner-Signaturen (php2s, php2shell, Assetnote) und Boundaries
- Erkennung von LFI-Probes (/tmp/sess_*, php://filter, index.php?file=...)
- Live-Monitoring-Modus (--live) oder Datei-/Archiv-Scan (--file / --all)
"""

import sys
import os
import re
import json
import gzip
import time
import argparse
from datetime import datetime

# ANSI-Farben für Terminal-Ausgabe
C_RESET  = "\033[0m"
C_BOLD   = "\033[1m"
C_RED    = "\033[91m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE   = "\033[94m"
C_MAGENTA= "\033[95m"
C_CYAN   = "\033[96m"

# Erkennungsmuster
SCANNER_UAS = [
    re.compile(r"php2s(?:hell)?", re.IGNORECASE),
    re.compile(r"assetnote", re.IGNORECASE),
    re.compile(r"react2shell", re.IGNORECASE)
]

LFI_PATTERNS = [
    re.compile(r"(\/tmp\/sess_[a-zA-Z0-9_-]+)", re.IGNORECASE),
    re.compile(r"(php:\/\/(?:filter|input|data))", re.IGNORECASE),
    re.compile(r"((?:\.\.\/|\.\.\\)+)", re.IGNORECASE),
    re.compile(r"(\/etc\/passwd)", re.IGNORECASE)
]

P2S_STRING = "PHP_SESSION_UPLOAD_PROGRESS"

def parse_log_line(line):
    """Parst eine JSON-Logzeile."""
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        # Fallback für nicht-JSON oder abgeschnittene Zeilen
        return None

def analyze_entry(entry):
    """
    Analysiert ein einzelnes Log-Event anhand der Phasen & Regeln R1-R11.
    Gibt (matches, tier, summary, payload_info) zurück.
    """
    matches = []
    
    src_ip = entry.get("src_ip", "-")
    ts = entry.get("ts", "-")
    method = entry.get("method", "-")
    uri = entry.get("uri", "-")
    status = entry.get("status", 0)
    req_len = int(entry.get("request_length") or 0)
    user_agent = entry.get("user_agent", "")
    content_type = entry.get("content_type", "")
    body = entry.get("request_body", "")
    transfer_encoding = entry.get("transfer_encoding", "")
    cookie = entry.get("cookie", "") or entry.get("cookie_phpsessid", "")

    # R1: POST, Multipart, Request-Länge > 500 Bytes
    is_multipart = "multipart/form-data" in content_type.lower()
    if method == "POST" and is_multipart and req_len > 500:
        matches.append(("R1", "POST Multipart über 500 Bytes"))

    # R2: POST, Multipart, Status 502 / 500
    if method == "POST" and is_multipart and status in [500, 502]:
        matches.append(("R2", f"POST Multipart mit Status {status}"))

    # R3: Multipart mit Chunked Transfer-Encoding oder auf Nicht-Upload-Endpunkte (/ oder /index.php)
    if is_multipart and "chunked" in transfer_encoding.lower():
        matches.append(("R3", "Multipart mit Transfer-Encoding: chunked"))
    if is_multipart and uri in ["/", "/index.php"]:
        matches.append(("R3", f"Multipart auf Nicht-Upload Endpunkt '{uri}'"))

    # R8: Body enthält PHP_SESSION_UPLOAD_PROGRESS (Kernindikator php2shell)
    has_p2s = (P2S_STRING in body) or (P2S_STRING in uri)
    if has_p2s:
        matches.append(("R8", f"Exploit-String {P2S_STRING} gefunden!"))

    # R9: Viele Formularteile / Datei-Uploads
    if is_multipart and body:
        file_parts = len(re.findall(r'Content-Disposition:\s*form-data', body, re.IGNORECASE))
        empty_files = len(re.findall(r'filename=["\']["\']', body, re.IGNORECASE))
        if file_parts >= 3 or empty_files >= 2:
            matches.append(("R9", f"Multipart-Payload mit {file_parts} Parts / {empty_files} leeren Filenames"))

    # R11: Scanner User-Agent oder Boundary
    for ua_pat in SCANNER_UAS:
        if ua_pat.search(user_agent):
            matches.append(("R11", f"Scanner-UA erkannt: '{user_agent}'"))
            break
    if "p2s" in content_type.lower() or "php2s" in content_type.lower():
        matches.append(("R11", "Boundary enthält 'p2s' / 'php2s'"))
    if "WebKitFormBoundaryx8jO2oVc6SWP3Sad" in content_type:
        matches.append(("R11", "React2Shell PoC Boundary (CVE-2025-55182)"))

    # LFI-Probe Erkennung
    for lfi_pat in LFI_PATTERNS:
        lfi_match = lfi_pat.search(uri)
        if lfi_match:
            matches.append(("LFI", f"LFI-Vektor in URI: '{lfi_match.group(1)}'"))
            break

    # Tier-Einstufung
    tier = "T0"
    if has_p2s:
        tier = "T2 (ARMED / EXPLOIT)"
    elif any(r[0] in ["R8", "R9"] for r in matches):
        tier = "T2 (ARMED)"
    elif any(r[0] in ["R1", "R3", "LFI"] for r in matches):
        tier = "T1 (PROBE)"
    elif any(r[0] == "R11" for r in matches):
        tier = "T0 (RECON SCAN)"

    # Payload-Extraktion
    payload_info = extract_payload(body) if body else None

    return matches, tier, payload_info

def extract_payload(body):
    """Extrahiert Formularfelder, Dateinamen und Codefragmente aus dem Body."""
    info = {"fields": {}, "files": [], "code_snippets": []}
    
    # Form-data fields
    field_matches = re.findall(
        r'Content-Disposition:\s*form-data;\s*name="([^"]+)"(?:\s*;\s*filename="([^"]*)")?(?:[^\r\n]*\r?\n[^\r\n]*)*\r?\n\r?\n(.*?)(?=\r?\n---|\Z)',
        body,
        re.DOTALL
    )
    for name, filename, val in field_matches:
        if filename:
            info["files"].append({"field": name, "filename": filename, "preview": val[:120].strip()})
        else:
            info["fields"][name] = val.strip()[:150]

    # PHP Code detection
    php_codes = re.findall(r'(<\?php.*?\?>|eval\(|system\(|passthru\(|shell_exec\(|base64_decode\()', body, re.IGNORECASE | re.DOTALL)
    if php_codes:
        info["code_snippets"] = [c.strip()[:120] for c in php_codes[:3]]

    return info

def print_finding(entry, matches, tier, payload_info):
    """Gibt einen formatierten Fund auf dem Terminal aus."""
    color = C_YELLOW if "T1" in tier else (C_RED if "T2" in tier else C_CYAN)
    
    print(f"\n{color}{C_BOLD}{'='*80}{C_RESET}")
    print(f"{color}{C_BOLD}[{tier}] {entry.get('ts')} | IP: {entry.get('src_ip')} -> Port {entry.get('dst_port')}{C_RESET}")
    print(f"  {C_BOLD}Request:{C_RESET} {entry.get('method')} {entry.get('uri')} (HTTP {entry.get('status')}) | Länge: {entry.get('request_length')} B")
    print(f"  {C_BOLD}User-Agent:{C_RESET} {entry.get('user_agent') or '(leer)'}")
    if entry.get("content_type"):
        print(f"  {C_BOLD}Content-Type:{C_RESET} {entry.get('content_type')}")
    if entry.get("cookie") or entry.get("cookie_phpsessid"):
        print(f"  {C_BOLD}Cookies:{C_RESET} {entry.get('cookie') or entry.get('cookie_phpsessid')}")
    
    print(f"  {C_BOLD}Regel-Treffer:{C_RESET}")
    for rule_id, desc in matches:
        print(f"    - [{C_MAGENTA}{rule_id}{C_RESET}] {desc}")

    if payload_info:
        print(f"  {C_GREEN}{C_BOLD}Extrahiertes Body-Payload:{C_RESET}")
        if payload_info["fields"]:
            print(f"    • Form-Felder: {json.dumps(payload_info['fields'], ensure_ascii=False)}")
        for f in payload_info["files"]:
            print(f"    • Datei: field={f['field']}, filename='{f['filename']}', data={repr(f['preview'])}")
        if payload_info["code_snippets"]:
            print(f"    • {C_RED}{C_BOLD}Erkannter Code:{C_RESET} {payload_info['code_snippets']}")
    print(f"{color}{'='*80}{C_RESET}")

def scan_file(filepath):
    """Durchsucht eine Logdatei (egal ob Plaintext oder .gz)."""
    opener = gzip.open if filepath.endswith(".gz") else open
    count = 0
    hits = 0
    try:
        with opener(filepath, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                count += 1
                entry = parse_log_line(line)
                if not entry:
                    continue
                matches, tier, payload = analyze_entry(entry)
                if tier != "T0":
                    hits += 1
                    print_finding(entry, matches, tier, payload)
    except Exception as e:
        print(f"Fehler beim Lesen von {filepath}: {e}", file=sys.stderr)
    return count, hits

def live_monitor(log_path):
    """Verfolgt honeypot.log live (wie tail -f)."""
    print(f"{C_GREEN}{C_BOLD}[*] Starte php2shell Live-Monitor auf: {log_path}{C_RESET}")
    print(f"[*] Drücke Ctrl+C zum Beenden.\n")
    
    if not os.path.exists(log_path):
        print(f"{C_RED}[!] Datei {log_path} existiert nicht!{C_RESET}")
        return

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        # Zum Ende der Datei springen
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            entry = parse_log_line(line)
            if not entry:
                continue
            matches, tier, payload = analyze_entry(entry)
            if tier != "T0":
                print_finding(entry, matches, tier, payload)

def main():
    parser = argparse.ArgumentParser(description="php2shell / CVE-2025-55182 Honeypot Detector")
    parser.add_argument("--file", "-f", help="Zu analysierende Logdatei (.log oder .gz)")
    parser.add_argument("--live", "-l", action="store_true", help="Live-Monitoring auf aktuellem honeypot.log")
    parser.add_argument("--path", "-p", default="/home/honeypot/nginx-docker/logs/honeypot.log", help="Pfad zum aktiven honeypot.log")
    parser.add_argument("--dir", "-d", help="Verzeichnis mit Logdateien (rekursiv scannen)")
    
    args = parser.parse_args()

    if args.live:
        live_monitor(args.path)
    elif args.file:
        c, h = scan_file(args.file)
        print(f"\n[Fertig] {c} Zeilen geprüft, {h} auffällige Events gefunden.")
    elif args.dir:
        total_c, total_h = 0, 0
        for root, _, files in os.walk(args.dir):
            for file in sorted(files):
                if file.endswith(".log") or file.endswith(".log.gz"):
                    p = os.path.join(root, file)
                    c, h = scan_file(p)
                    total_c += c
                    total_h += h
        print(f"\n[Gesamt] {total_c} Zeilen in allen Dateien geprüft, {total_h} Treffer gefunden.")
    else:
        # Standard: Aktives Log scannen
        default_log = args.path if os.path.exists(args.path) else "honeypot.log"
        if os.path.exists(default_log):
            c, h = scan_file(default_log)
            print(f"\n[Fertig] {c} Zeilen geprüft, {h} auffällige Events gefunden.")
        else:
            parser.print_help()

if __name__ == "__main__":
    main()
