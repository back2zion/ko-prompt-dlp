#!/usr/bin/env python3
"""Exposure check for assets you own or are authorised to audit.

Checks, per host in the scope file:
  * risky TCP ports that are reachable (RDP, SMB, Telnet, databases, admin consoles ...)
  * HTTP Basic-auth endpoints that accept a vendor default password

It refuses to run without --confirm-authorized, refuses networks larger than /24 and
public addresses (unless --allow-public), and sends at most one request per second to
any one host for the credential check.
"""
from __future__ import annotations

import argparse
import base64
import http.client
import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

RISKY_PORTS = {
    21: ("FTP", "medium"), 23: ("Telnet", "high"), 135: ("MS-RPC", "medium"),
    139: ("NetBIOS", "medium"), 445: ("SMB", "high"), 1433: ("MSSQL", "high"),
    1521: ("Oracle DB", "high"), 3306: ("MySQL", "high"), 3389: ("RDP", "high"),
    5432: ("PostgreSQL", "high"), 5900: ("VNC", "high"), 6379: ("Redis", "high"),
    7001: ("WebLogic admin", "high"), 8080: ("HTTP alt/admin", "low"),
    9200: ("Elasticsearch", "high"), 27017: ("MongoDB", "high"),
}
WEB_PORTS = (80, 8080, 8000, 8888)
DEFAULT_CREDS = [("admin", "admin"), ("admin", "password"), ("admin", "1234"),
                 ("admin", ""), ("root", "root"), ("user", "user")]
MAX_HOSTS = 256


def expand_scope(lines: list[str], allow_public: bool = False) -> list[str]:
    hosts: list[str] = []
    for raw in lines:
        line = raw.split("#")[0].strip()
        if not line:
            continue
        net = ipaddress.ip_network(line, strict=False)
        if net.num_addresses > MAX_HOSTS:
            raise ValueError(f"{line}: scope larger than /24 is not allowed")
        if not allow_public and not (net.is_private or net.is_loopback):
            raise ValueError(f"{line}: public address; pass --allow-public if you own it")
        hosts += [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]
    if len(hosts) > MAX_HOSTS:
        raise ValueError("scope has more than 256 hosts")
    return list(dict.fromkeys(hosts))


def port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def basic_auth_status(host: str, port: int, creds: tuple[str, str] | None, timeout: float):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    headers = {}
    if creds:
        headers["Authorization"] = "Basic " + base64.b64encode(
            f"{creds[0]}:{creds[1]}".encode()).decode()
    try:
        conn.request("GET", "/", headers=headers)
        r = conn.getresponse()
        return r.status, r.getheader("WWW-Authenticate")
    except (OSError, http.client.HTTPException):
        return None, None
    finally:
        conn.close()


def check_host(host: str, timeout: float = 1.0, ports: dict | None = None,
               web_ports: tuple = WEB_PORTS, delay: float = 1.0,
               creds_list: list = DEFAULT_CREDS) -> list[dict]:
    findings = []
    open_ports = []
    for port, (name, sev) in (ports or RISKY_PORTS).items():
        if port_open(host, port, timeout):
            open_ports.append(port)
            findings.append({"host": host, "port": port, "severity": sev,
                             "issue": f"{name} port reachable",
                             "fix": "Restrict to a management network / VPN or close the port."})
    for port in web_ports:
        if port not in open_ports and not port_open(host, port, timeout):
            continue
        status, www = basic_auth_status(host, port, None, timeout)
        if status != 401 or not www or not www.lower().startswith("basic"):
            continue
        for user, pw in creds_list:
            time.sleep(delay)
            status, _ = basic_auth_status(host, port, (user, pw), timeout)
            if status is not None and status < 400:
                findings.append({"host": host, "port": port, "severity": "critical",
                                 "issue": f"default credentials accepted ({user}/{'<empty>' if not pw else pw})",
                                 "fix": "Change the password now and restrict access to the console."})
                break
    return findings


def run(hosts: list[str], workers: int = 16, **kw) -> list[dict]:
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = ex.map(lambda h: check_host(h, **kw), hosts)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted((f for r in results for f in r), key=lambda f: (order[f["severity"]], f["host"], f["port"]))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scope", required=True, help="file with one IP/CIDR per line (max /24 each)")
    ap.add_argument("--confirm-authorized", action="store_true",
                    help="confirm you own these assets or have written authorisation to test them")
    ap.add_argument("--allow-public", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if not args.confirm_authorized:
        print("Refusing to run: pass --confirm-authorized after verifying you may test these assets.",
              file=sys.stderr)
        return 2
    try:
        hosts = expand_scope(open(args.scope).read().splitlines(), args.allow_public)
    except ValueError as e:
        print(f"scope error: {e}", file=sys.stderr)
        return 2
    findings = run(hosts)
    if args.json:
        print(json.dumps(findings, ensure_ascii=False, indent=2))
    else:
        print(f"{len(hosts)} hosts checked, {len(findings)} findings")
        for f in findings:
            print(f"[{f['severity'].upper():8}] {f['host']}:{f['port']}  {f['issue']}\n           -> {f['fix']}")
    return 1 if any(f["severity"] in ("critical", "high") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
