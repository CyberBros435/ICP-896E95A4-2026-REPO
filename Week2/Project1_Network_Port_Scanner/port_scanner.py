#!/usr/bin/env python3
"""
Network Port Scanner
InternCareerPath - Cyber Security Internship | Project 1 (Beginner)

Features : TCP connect scan, UDP scan, multithreading, banner grabbing,
           service detection, JSON + HTML reports.
Python   : 3.13 (standard library only, no pip install needed)

ETHICS   : Scan only systems you own or have written permission to test.
           Safe practice targets: 127.0.0.1, your own lab VM, scanme.nmap.org
"""
import argparse
import concurrent.futures as cf
import json
import socket
import sys
import time
from datetime import datetime
from html import escape
from pathlib import Path

REPORT_DIR = Path(__file__).resolve().parent / "report"

COMMON_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "microsoft-ds", 465: "smtps", 514: "syslog",
    587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 27017: "mongodb",
}
HTTP_PORTS = {80, 8000, 8080, 8888, 8443, 443}
DNS_QUERY = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x07example\x03com\x00\x00\x01\x00\x01")
UDP_PROBES = {53: DNS_QUERY}


# ----------------------------------------------------------------- helpers
def parse_ports(spec: str) -> list[int]:
    """'22,80,100-200' -> sorted list of ports."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
            if a > b:
                a, b = b, a
            ports.update(range(a, b + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def detect_service(port: int, proto: str, banner: str) -> str:
    """Banner-based detection first, then port-number lookup."""
    b = banner.upper()
    if b.startswith("SSH-"):
        return "ssh"
    if b.startswith("HTTP/"):
        return "http"
    if b.startswith("220") and "FTP" in b:
        return "ftp"
    if b.startswith("220") and "SMTP" in b:
        return "smtp"
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"


def grab_banner(sock: socket.socket, port: int) -> str:
    """Read whatever the service says first (or poke HTTP) - best effort."""
    try:
        sock.settimeout(1.5)
        if port in HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
        text = sock.recv(1024).decode("utf-8", "replace").strip()
        if not text:
            return ""
        lines = text.splitlines()
        banner = lines[0].strip()
        server = [ln.strip() for ln in lines if ln.lower().startswith("server:")]
        if server:
            banner += " | " + server[0]
        return banner[:120]
    except OSError:
        return ""


# ------------------------------------------------------------------- scans
def scan_tcp(ip: str, port: int, timeout: float, banners: bool):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            banner = grab_banner(s, port) if banners else ""
            return {"port": port, "protocol": "tcp", "state": "open",
                    "service": detect_service(port, "tcp", banner),
                    "banner": banner}
    except OSError:
        return None


def scan_udp(ip: str, port: int, timeout: float, banners: bool):
    """Reply = open | ICMP unreachable = closed | silence = open|filtered."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.send(UDP_PROBES.get(port, b"\x00"))
            try:
                data = s.recv(1024)
                banner = data[:40].hex() if banners and data else ""
                return {"port": port, "protocol": "udp", "state": "open",
                        "service": detect_service(port, "udp", ""),
                        "banner": banner}
            except socket.timeout:
                return {"port": port, "protocol": "udp",
                        "state": "open|filtered",
                        "service": detect_service(port, "udp", ""),
                        "banner": ""}
            except (ConnectionResetError, ConnectionRefusedError):
                return None
    except OSError:
        return None


def run_scan(target, ports, mode, threads, timeout, banners):
    ip = socket.gethostbyname(target)
    jobs = []
    if mode in ("tcp", "both"):
        jobs += [(scan_tcp, p) for p in ports]
    if mode in ("udp", "both"):
        jobs += [(scan_udp, p) for p in ports]

    print(f"\n[*] Target : {target} ({ip})")
    print(f"[*] Mode   : {mode.upper()} | Ports: {len(ports)} | "
          f"Threads: {threads} | Timeout: {timeout}s")
    print(f"[*] Started: {datetime.now():%Y-%m-%d %H:%M:%S}\n")
    print(f"{'PORT':<12}{'STATE':<15}{'SERVICE':<15}BANNER")
    print("-" * 70)

    results, start = [], time.time()
    ex = cf.ThreadPoolExecutor(max_workers=threads)
    try:
        futures = [ex.submit(fn, ip, p, timeout, banners) for fn, p in jobs]
        for f in cf.as_completed(futures):
            r = f.result()
            if r:
                results.append(r)
                print(f"{str(r['port']) + '/' + r['protocol']:<12}"
                      f"{r['state']:<15}{r['service']:<15}{r['banner']}")
    except KeyboardInterrupt:
        print("\n[!] Interrupted - saving partial results.")
        ex.shutdown(wait=False, cancel_futures=True)
    else:
        ex.shutdown()

    results.sort(key=lambda r: (r["port"], r["protocol"]))
    duration = round(time.time() - start, 2)
    return {
        "target": target, "ip": ip, "mode": mode,
        "ports_scanned": len(ports),
        "scan_time": datetime.now().isoformat(timespec="seconds"),
        "duration_seconds": duration,
        "open_count": sum(r["state"] == "open" for r in results),
        "results": results,
    }


# ----------------------------------------------------------------- reports
def save_reports(data: dict) -> list[Path]:
    REPORT_DIR.mkdir(exist_ok=True)
    safe = data["target"].replace(".", "_").replace(":", "_")
    base = f"scan_{safe}_{datetime.now():%Y%m%d_%H%M%S}"
    json_path = REPORT_DIR / f"{base}.json"
    html_path = REPORT_DIR / f"{base}.html"

    json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    rows = "".join(
        "<tr><td>{}/{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            r["port"], r["protocol"], escape(r["state"]),
            escape(r["service"]), escape(r["banner"]))
        for r in data["results"]
    ) or "<tr><td colspan='4'>No open ports found</td></tr>"
    html = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>Port Scan Report</title><style>"
        "body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;color:#222}"
        "table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #ccc;padding:8px;text-align:left}"
        "th{background:#1f2937;color:#fff}tr:nth-child(even){background:#f3f4f6}"
        "</style></head><body><h1>Port Scan Report</h1>"
        f"<p><b>Target:</b> {escape(data['target'])} ({data['ip']})<br>"
        f"<b>Mode:</b> {data['mode'].upper()} | "
        f"<b>Ports scanned:</b> {data['ports_scanned']} | "
        f"<b>Open:</b> {data['open_count']}<br>"
        f"<b>Time:</b> {data['scan_time']} | "
        f"<b>Duration:</b> {data['duration_seconds']}s</p>"
        "<table><tr><th>Port</th><th>State</th><th>Service</th>"
        f"<th>Banner</th></tr>{rows}</table></body></html>"
    )
    html_path.write_text(html, encoding="utf-8")
    return [json_path, html_path]


# --------------------------------------------------------------------- CLI
def confirm_authorization() -> bool:
    ans = input("[?] Do you own this target or have written permission "
                "to scan it? (y/N): ").strip().lower()
    return ans in ("y", "yes")


def interactive_args():
    print("=" * 60)
    print(" Network Port Scanner - ICP Cyber Security Internship")
    print("=" * 60)
    target = input("Target (IP/hostname) [127.0.0.1]: ").strip() or "127.0.0.1"
    ports = input("Ports [1-1024]: ").strip() or "1-1024"
    mode = input("Mode tcp/udp/both [tcp]: ").strip().lower() or "tcp"
    return argparse.Namespace(target=target, ports=ports, mode=mode,
                              threads=100, timeout=1.0, no_banner=False,
                              yes=False, no_save=False)


def get_args():
    if len(sys.argv) == 1:
        return interactive_args()
    p = argparse.ArgumentParser(
        description="Multithreaded TCP/UDP port scanner with banner grabbing.",
        epilog="Example: python port_scanner.py 127.0.0.1 -p 1-1024 -m tcp")
    p.add_argument("target", help="IP address or hostname")
    p.add_argument("-p", "--ports", default="1-1024",
                   help="e.g. 80 | 22,80,443 | 1-1024 (default 1-1024)")
    p.add_argument("-m", "--mode", choices=["tcp", "udp", "both"],
                   default="tcp")
    p.add_argument("-t", "--threads", type=int, default=100)
    p.add_argument("--timeout", type=float, default=1.0,
                   help="seconds per port (default 1.0)")
    p.add_argument("--no-banner", action="store_true",
                   help="skip banner grabbing")
    p.add_argument("--no-save", action="store_true",
                   help="do not write JSON/HTML reports")
    p.add_argument("-y", "--yes", action="store_true",
                   help="skip the authorization prompt")
    return p.parse_args()


def main() -> int:
    args = get_args()
    if args.mode not in ("tcp", "udp", "both"):
        print("[!] Mode must be tcp, udp or both.")
        return 1
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[!] Invalid ports: {e}")
        return 1
    if not args.yes and not confirm_authorization():
        print("[!] Aborted. Only scan authorized targets.")
        return 1
    try:
        data = run_scan(args.target, ports, args.mode,
                        max(1, args.threads), args.timeout,
                        not args.no_banner)
    except socket.gaierror:
        print(f"[!] Cannot resolve host: {args.target}")
        return 1

    print("-" * 70)
    print(f"[+] Done in {data['duration_seconds']}s | "
          f"{data['open_count']} open port(s) of {data['ports_scanned']} "
          f"scanned")
    if not args.no_save:
        for path in save_reports(data):
            print(f"[+] Saved: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
