#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BRUTUS Main Runner - standalone local security-audit wardog for NOVA.

Brutus is NOVA's trained hunting dog ("cerberus"): point it at an EXPLICIT,
authorized scope and it performs a real local self-audit scan, then writes its
findings back into NOVA's palace (NOVA.db) where she can read them.

This is a self-audit instrument, NOT an offensive engine. It does a real local
TCP service scan + hygiene audit against an authorized allowlist scope and
references a published weak-password list for reporting. It does NOT crack
passwords or reverse hashes.

Modes
-----
  --real   (DEFAULT) Real local scan/probe of an explicit authorized scope.
           Requires (1) an acknowledged legal/authorization gate and (2) a
           scope: --scope <host|CIDR> (repeatable) and/or a brutus_scope.txt
           file. With no acknowledgment or no scope it REFUSES.
  --demo   Opt-in safe, sandboxed, simulated run. Non-destructive, touches
           no network and does not write to NOVA.db by default.

Usage
-----
  python brutus_runner.py                         # real hunt (interactive ack prompt)
  python brutus_runner.py --scope 127.0.0.1
  python brutus_runner.py --real --ack --scope 192.168.1.0/24   # headless-safe
  python brutus_runner.py --demo                  # safe simulated sandbox
  python brutus_runner.py --real --ack --no-nova  # real scan, skip NOVA.db write

Author: Grok Bot (NOVA integration lane)  |  Original demo: Aurelius Nova
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import socket
import sys
from datetime import datetime, timezone

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
SCOPE_FILE = os.path.join(PROJECT_DIR, "brutus_scope.txt")
REPORT_PATH = os.path.join(PROJECT_DIR, "report.html")
RESULTS_JSON = os.path.join(PROJECT_DIR, "brutus_last_hunt.json")

LEGAL_WARNING = """\
======================================================================
  BRUTUS - LEGAL / AUTHORIZATION NOTICE  (read before any real scan)
======================================================================
  Only scan systems you OWN or networks you are EXPLICITLY AUTHORIZED
  to audit. You are solely responsible for all activity performed with
  this tool. Unauthorized scanning may be illegal.

  Brutus is a DEFENSIVE self-audit instrument: it finds exposure so it
  can be fixed. It does not crack passwords, reverse hashes, or exploit.
======================================================================"""

# Ports Brutus probes in a real local scan (host -> service name).
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}
DEFAULT_PORTS = sorted(PORT_SERVICES)

_HIGH_RISK = {"Telnet", "FTP", "SMB", "RDP", "VNC", "NetBIOS", "MSRPC"}
_MED_RISK = {"SSH", "HTTP", "HTTP-Alt", "SMTP", "DNS", "MySQL", "PostgreSQL",
             "Oracle", "MSSQL", "POP3", "IMAP"}


def _risk_for(service: str) -> str:
    if service in _HIGH_RISK:
        return "HIGH"
    if service in _MED_RISK:
        return "MEDIUM"
    return "LOW"


def _zulu() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Legal / authorization gate  (the hard boundary, with the allowlist)
# ---------------------------------------------------------------------------
def authorization_gate(acknowledged: bool, interactive: bool | None = None,
                       scope_file_present: bool | None = None) -> bool:
    """Display the legal notice and require acknowledgment before a real scan.

    - Interactive (a human at a TTY): require a typed positive acknowledgment,
      unless --ack was already supplied.
    - Headless (NOVA dispatch / no TTY): require BOTH an explicit acknowledged
      flag AND the allowlist scope file to be present. Refuse otherwise.
    """
    print(LEGAL_WARNING)
    if interactive is None:
        try:
            interactive = sys.stdin.isatty()
        except Exception:
            interactive = False
    if scope_file_present is None:
        scope_file_present = os.path.isfile(SCOPE_FILE)

    if not interactive:
        if not scope_file_present:
            print("\nREFUSED (headless): allowlist scope file is missing.")
            print(f"  Expected: {SCOPE_FILE}")
            return False
        if not acknowledged:
            print("\nREFUSED (headless): authorization not acknowledged.")
            print("  Re-run with --ack (and an authorized scope) to confirm you are")
            print("  authorized to audit the listed targets.")
            return False
        print("\n[auth] Headless acknowledgment accepted (--ack) + scope file present.")
        return True

    # Interactive path
    if acknowledged:
        print("\n[auth] Authorization acknowledged via --ack.")
        return True
    try:
        resp = input("\nType 'I AGREE' to acknowledge and proceed (anything else aborts): ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nREFUSED: no acknowledgment given.")
        return False
    if resp.upper() == "I AGREE":
        print("[auth] Authorization acknowledged.")
        return True
    print("REFUSED: acknowledgment not given. Aborting.")
    return False


# ---------------------------------------------------------------------------
# Stage 1 - Rainbow table (published weak-password reference, both modes)
# ---------------------------------------------------------------------------
def load_rainbow_table():
    """Load the published weak-password reference (for reporting only).

    Prefers the richer rainbow_table.py module (37+ entries). Falls back to a
    small built-in set if that module is unavailable. This is a reference list
    of commonly-breached passwords - NOT a cracker and not a hash-reversal
    table. The data files proper are maintained in the password/rainbow lane.
    """
    try:
        sys.path.insert(0, PROJECT_DIR)
        import rainbow_table as rt  # type: ignore
        passwords = {}
        for pw, prevalence, _year in rt.RAINBOW_TABLE:
            likelihood = min(99, int(round(prevalence * 3)))
            breach_count = int(prevalence * 1_000_000)
            passwords[pw] = {"breach_count": breach_count, "likelihood": likelihood}
        if passwords:
            return {"passwords": passwords, "source": "rainbow_table.py"}
    except Exception:
        pass

    return {
        "passwords": {
            "password": {"breach_count": 24000000, "likelihood": 95},
            "123456": {"breach_count": 20181715, "likelihood": 92},
            "qwerty": {"breach_count": 8942869, "likelihood": 88},
            "admin": {"breach_count": 14200000, "likelihood": 85},
            "1234": {"breach_count": 8500000, "likelihood": 78},
            "password1": {"breach_count": 6200000, "likelihood": 72},
            "letmein": {"breach_count": 4100000, "likelihood": 65},
            "welcome": {"breach_count": 3800000, "likelihood": 62},
            "12345": {"breach_count": 3200000, "likelihood": 58},
        },
        "source": "builtin-fallback",
    }


def analyze_user_accounts(rainbow_table):
    """Stage 2 - weak-credential reference matrix (illustrative dataset).

    This compares a small illustrative set of example accounts against the
    published weak-password reference. No live credentials are tested and no
    cracking is performed.
    """
    test_users = [
        {"username": "admin", "password": "1234", "user_type": "Default system admin"},
        {"username": "test", "password": "password", "user_type": "Test account"},
        {"username": "root", "password": "qwerty", "user_type": "Super user"},
        {"username": "guest", "password": "admin", "user_type": "Guest account"},
    ]
    results = []
    for user in test_users:
        username = user["username"]
        password = user["password"]
        if password in rainbow_table["passwords"]:
            breach_info = rainbow_table["passwords"][password]
            risk_score = ((breach_info["likelihood"] + 50) / 100 * 30) + (65 if username == "admin" else 40)
            results.append({
                "username": username,
                "password": password,
                "user_type": user["user_type"],
                "breach_count": breach_info["breach_count"],
                "likelihood_score": breach_info["likelihood"],
                "risk_level": "CRITICAL" if risk_score > 90 else "HIGH" if risk_score > 75 else "MEDIUM" if risk_score > 50 else "LOW",
                "combined_risk_score": round(risk_score, 1),
            })
    return results


# ---------------------------------------------------------------------------
# Stage 3 - Service scanning
# ---------------------------------------------------------------------------
def run_service_scanner_demo():
    """Simulated service findings for --demo (no network touched)."""
    return [
        {"port": 80, "service": "HTTP", "state": "OPEN", "vulnerability_risk": "MEDIUM"},
        {"port": 443, "service": "HTTPS", "state": "OPEN", "vulnerability_risk": "LOW"},
        {"port": 22, "service": "SSH", "state": "OPEN", "vulnerability_risk": "MEDIUM"},
        {"port": 3389, "service": "RDP", "state": "OPEN", "vulnerability_risk": "HIGH"},
        {"port": 445, "service": "SMB", "state": "OPEN", "vulnerability_risk": "HIGH"},
    ]


# ---------------------------------------------------------------------------
# Scope handling (the allowlist leash that keeps her well-mannered)
# ---------------------------------------------------------------------------
def read_scope_file(path=SCOPE_FILE):
    entries = []
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    entries.append(line)
    return entries


def gather_scope(cli_scope):
    """Combine --scope args (repeatable / comma-separated) with brutus_scope.txt."""
    entries = []
    for raw in (cli_scope or []):
        entries.extend(p.strip() for p in raw.split(",") if p.strip())
    entries.extend(read_scope_file())
    seen, out = set(), []
    for e in entries:
        if e.lower() not in seen:
            seen.add(e.lower())
            out.append(e)
    return out


def expand_scope(entries, max_hosts=1024):
    """Turn scope entries (hosts / IPs / CIDRs) into a concrete host list."""
    hosts, notes = [], []
    for e in entries:
        low = e.lower()
        if low in ("localhost",):
            hosts.append("127.0.0.1")
            continue
        try:
            net = ipaddress.ip_network(e, strict=False)
            if net.num_addresses <= 1:
                hosts.append(str(net.network_address))
            else:
                addrs = [str(a) for a in net.hosts()]
                if len(addrs) > max_hosts:
                    notes.append(f"scope {e} has {len(addrs)} hosts; capped at {max_hosts}")
                    addrs = addrs[:max_hosts]
                hosts.extend(addrs)
        except ValueError:
            hosts.append(e)
    seen, out = set(), []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out, notes


def scan_host(host, ports, timeout=0.5, max_workers=64):
    """Real TCP connect scan of one host. Returns open-port findings."""
    def probe(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            return port if s.connect_ex((host, port)) == 0 else None
        except OSError:
            return None
        finally:
            s.close()

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for res in ex.map(probe, ports):
            if res is not None:
                open_ports.append(res)
    open_ports.sort()
    out = []
    for p in open_ports:
        svc = PORT_SERVICES.get(p, "Unknown")
        out.append({"port": p, "service": svc, "state": "OPEN", "vulnerability_risk": _risk_for(svc)})
    return out


def run_real_hunt(scope_entries, ports=None, timeout=0.5):
    hosts, notes = expand_scope(scope_entries)
    ports = ports or list(DEFAULT_PORTS)
    host_results, flat = [], []
    for h in hosts:
        found = scan_host(h, ports, timeout=timeout)
        host_results.append({"host": h, "open_ports": found})
        for f in found:
            flat.append({**f, "host": h})
        label = f"{len(found)} open" if found else "no open ports"
        print(f"      [scan] {h}: {label}")
    return hosts, host_results, flat, notes


# ---------------------------------------------------------------------------
# HTML report (unchanged structure; fed real or demo findings)
# ---------------------------------------------------------------------------
def generate_html_report(rainbow_data, user_results, service_findings, mode="real", scope=None):
    report_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scope = scope or []

    password_html = ""
    for password, info in rainbow_data["passwords"].items():
        color = "#dc3545" if info["likelihood"] >= 80 else "#fd7e14" if info["likelihood"] >= 60 else "#ffc107"
        password_html += f'''
    <tr>
      <td><strong>{password}</strong></td>
      <td style="text-align:right;">{info['breach_count']:,}</td>
      <td style="color:{color}; font-weight:bold;">{info['likelihood']}%</td>
    </tr>'''

    user_html = ""
    for user in user_results:
        color_map = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107", "LOW": "#28a745"}
        risk_color = color_map.get(user["risk_level"], "#6c757d")
        user_html += f'''
    <tr>
      <td><strong>{user['username']}</strong></td>
      <td style="text-align:right;">{user['combined_risk_score']}%</td>
      <td style="color:{risk_color}; font-weight:bold;">{user['risk_level']}</td>
    </tr>'''

    service_html = ""
    for service in service_findings:
        color_map = {"LOW": "#28a745", "MEDIUM": "#ffc107", "HIGH": "#fd7e14", "CRITICAL": "#dc3545"}
        risk_color = color_map.get(service["vulnerability_risk"], "#6c757d")
        host_cell = f"<td><code>{service.get('host','-')}</code></td>"
        service_html += f'''
    <tr>
      {host_cell}
      <td><strong>{service['port']}</strong></td>
      <td><code>{service['service']}</code></td>
      <td style="color:{risk_color}; font-weight:bold;">{service['vulnerability_risk']}</td>
    </tr>'''

    mode_badge = "REAL LOCAL SCAN" if mode == "real" else "DEMO / SIMULATED"
    scope_txt = ", ".join(scope) if scope else "(simulated - no live targets)"

    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Brutus Security Audit Report</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); padding: 20px; }}
.container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); overflow: hidden; }}
.header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; }}
.header h1 {{ font-size: 2.5em; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }}
.timestamp {{ opacity: 0.9; font-size: 1.05em; }}
.section {{ padding: 30px; border-bottom: 1px solid #eee; }}
.section-title {{ color: #667eea; font-size: 1.8em; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 3px solid #667eea; }}
.summary-box {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; text-align: center; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
th {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; font-weight: 600; }}
tr:hover {{ background-color: #f8f9fa; }}
.footer {{ background: #343a40; color: white; text-align: center; padding: 20px; font-size: 0.9em; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>BRUTUS SECURITY AUDIT REPORT</h1>
    <p class="timestamp">Generated: {report_timestamp} &middot; Mode: {mode_badge}</p>
    <p class="timestamp">Scope: {scope_txt}</p>
  </div>

  <div class="section">
    <h2 class="section-title">EXECUTIVE SUMMARY</h2>
    <div class="summary-box">
      <h2>COMPREHENSIVE SECURITY ASSESSMENT</h2>
      <p>Passwords referenced: {len(rainbow_data['passwords'])} &middot; Accounts reviewed: {len(user_results)} &middot; Open services found: {len(service_findings)}</p>
    </div>
  </div>

  <div class="section">
    <h2 class="section-title">PASSWORD BREACH REFERENCE (published weak-password list)</h2>
    <table>
      <thead><tr><th>Password</th><th style="text-align:right;">Breach Instances</th><th>Likelihood of Use</th></tr></thead>
      <tbody>{password_html}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2 class="section-title">USER ACCOUNT RISK REFERENCE</h2>
    <table>
      <thead><tr><th>Username</th><th style="text-align:right;">Combined Risk</th><th>Risk Level</th></tr></thead>
      <tbody>{user_html}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2 class="section-title">SERVICE / PORT SCAN RESULTS ({mode_badge})</h2>
    <table>
      <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Risk Level</th></tr></thead>
      <tbody>{service_html}
      </tbody>
    </table>
  </div>
</div>
<div class="footer">
  <p><strong>DEFENSIVE / AUTHORIZED-USE TOOL ONLY</strong> - scan only hosts you own or are authorized to test.<br>
  Brutus - NOVA's trained wardog. Findings mirrored into NOVA.db for the handler.</p>
</div>
</body>
</html>'''
    return html_content


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def build_results(mode, scope, hosts, host_results, flat_findings, rainbow_data, user_results):
    high = sum(1 for f in flat_findings if f.get("vulnerability_risk") in ("HIGH", "CRITICAL"))
    return {
        "tool": "brutus",
        "mode": mode,
        "zulu": _zulu(),
        "local_time": datetime.now().astimezone().isoformat(timespec="seconds"),
        "scope": scope,
        "hosts_scanned": hosts,
        "hosts": host_results,
        "service_findings": flat_findings,
        "summary": {
            "hosts_scanned": len(hosts),
            "open_services": len(flat_findings),
            "high_risk": high,
        },
        "password_reference_count": len(rainbow_data["passwords"]),
        "user_risk": user_results,
        "report_html": REPORT_PATH,
    }


def run(mode, scope_entries, timeout=0.5, write_nova=None, acknowledged=False):
    # Safety net: a real hunt must never proceed without an acknowledged gate.
    if mode == "real" and not acknowledged:
        print("BRUTUS: internal guard - real hunt invoked without an acknowledged "
              "authorization gate; refusing.")
        return {"ok": False, "refused": True, "error": "authorization not acknowledged"}

    print("=" * 70)
    print(f"BRUTUS - {'REAL LOCAL HUNT' if mode == 'real' else 'DEMO SANDBOX'}")
    print("=" * 70)
    print()

    rainbow_data = load_rainbow_table()
    print(f"[1/3] Weak-password reference: {len(rainbow_data['passwords'])} entries "
          f"(source: {rainbow_data.get('source')})")
    user_results = analyze_user_accounts(rainbow_data)
    print(f"[2/3] Weak-credential reference matrix: {len(user_results)} flagged")

    if mode == "real":
        print(f"[3/3] Real local scan of scope: {', '.join(scope_entries)}")
        hosts, host_results, flat, notes = run_real_hunt(scope_entries, timeout=timeout)
        for n in notes:
            print(f"      [note] {n}")
        service_findings = flat
    else:
        print("[3/3] Simulated service scan (no network touched)")
        service_findings = run_service_scanner_demo()
        hosts, host_results, flat = [], [], service_findings
        for f in service_findings:
            print(f"      Port {f['port']}: {f['service']} ({f['vulnerability_risk']})")

    print()
    html_content = generate_html_report(rainbow_data, user_results, service_findings,
                                        mode=mode, scope=scope_entries if mode == "real" else [])
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"HTML report: {REPORT_PATH}")

    results = build_results(mode, scope_entries, hosts, host_results, flat,
                            rainbow_data, user_results)
    with open(RESULTS_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"Results JSON: {RESULTS_JSON}")

    if write_nova is None:
        write_nova = (mode == "real")
    if write_nova:
        try:
            sys.path.insert(0, PROJECT_DIR)
            import nova_hunt
            nova_out = nova_hunt.record_hunt(results)
            if nova_out.get("ok"):
                print(f"NOVA palace: wrote {nova_out.get('facts')} fact(s) + report card "
                      f"#{nova_out.get('report_id')} into {nova_out.get('db_path')}")
            else:
                print(f"NOVA palace: NOT written ({nova_out.get('error')})")
            results["nova"] = nova_out
        except Exception as exc:  # pragma: no cover
            print(f"NOVA palace: hook error: {exc}")
            results["nova"] = {"ok": False, "error": str(exc)}

    print()
    print("=" * 70)
    s = results["summary"]
    print(f"DONE - mode={mode} hosts={s['hosts_scanned']} open_services={s['open_services']} high_risk={s['high_risk']}")
    print("=" * 70)
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="brutus_runner",
        description="Brutus - NOVA's local self-audit wardog. Real scan by default.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--real", action="store_true",
                      help="Real local scan of an explicit authorized scope (DEFAULT).")
    mode.add_argument("--demo", action="store_true",
                      help="Safe simulated sandbox run (non-destructive, no NOVA write).")
    parser.add_argument("--scope", action="append", default=[], metavar="HOST|CIDR",
                        help="Authorized target(s). Repeatable or comma-separated. "
                             "Combined with brutus_scope.txt.")
    parser.add_argument("--ack", "--yes", dest="ack", action="store_true",
                        help="Acknowledge the legal/authorization notice without a prompt "
                             "(required for headless/NOVA real runs).")
    parser.add_argument("--headless", action="store_true",
                        help="Force non-interactive mode (no prompts); requires --ack for real.")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="Per-port TCP connect timeout in seconds (default 0.5).")
    parser.add_argument("--nova", dest="nova", action="store_true", default=None,
                        help="Force-write findings into NOVA.db (default: on for --real).")
    parser.add_argument("--no-nova", dest="nova", action="store_false",
                        help="Do not write findings into NOVA.db.")
    args = parser.parse_args(argv)

    mode_name = "demo" if args.demo else "real"

    if mode_name == "real":
        scope_entries = gather_scope(args.scope)
        if not scope_entries:
            print(LEGAL_WARNING)
            print()
            print("=" * 70)
            print("BRUTUS REFUSES TO HUNT: no target scope set.")
            print("=" * 70)
            print()
            print("Real mode requires an explicit, authorized target scope.")
            print("Set one of:")
            print(f"  * edit the scope file: {SCOPE_FILE}")
            print("  * pass --scope <host|CIDR>   e.g.  --scope 127.0.0.1")
            print("                               e.g.  --scope 192.168.1.0/24")
            print()
            print("Only list hosts you OWN or are AUTHORIZED to test.")
            print("(Or run the safe sandbox:  python brutus_runner.py --demo)")
            return 2

        interactive = (not args.headless)
        try:
            if interactive and not sys.stdin.isatty():
                interactive = False
        except Exception:
            interactive = False
        if not authorization_gate(args.ack, interactive=interactive,
                                  scope_file_present=os.path.isfile(SCOPE_FILE)):
            return 3

        run("real", scope_entries, timeout=args.timeout, write_nova=args.nova, acknowledged=True)
        return 0

    # demo path (no gate needed; nothing is scanned)
    run("demo", [], timeout=args.timeout, write_nova=(args.nova is True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
