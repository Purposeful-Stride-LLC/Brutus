#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nova_hunt.py - NOVA's dispatch/readback hook for the Brutus wardog.

This is the clean seam between NOVA and Brutus. NOVA can:
  * dispatch a hunt            : nova_hunt.dispatch(scope=["127.0.0.1"], ack=True)
  * mirror findings to palace  : nova_hunt.record_hunt(results)
  * read findings back         : nova_hunt.read_results()

A real (headless) dispatch is gated: it requires an explicit acknowledgment
(ack=True / --ack) AND the allowlist scope file (brutus_scope.txt) to be
present, on top of a non-empty authorized scope. Without any of those it
refuses with a clear message. Brutus is a defensive self-audit instrument; it
does not crack passwords or reverse hashes.

Findings land in NOVA's SQLite palace (NOVA.db) as `facts` rows under WHI
`Tx-BRUTUS`, plus an open `reports` card, so they surface through NOVA's normal
db.hunt()/office.reports() surfaces. A copy is also written to
brutus_last_hunt.json in the project folder.

CLI:
  python nova_hunt.py --scope 127.0.0.1 --ack   # real hunt (headless-safe)
  python nova_hunt.py --demo                     # safe sandbox, mirrors to palace
  python nova_hunt.py --read                     # print latest findings from NOVA.db
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
RESULTS_JSON = PROJECT_DIR / "brutus_last_hunt.json"
SCOPE_FILE = PROJECT_DIR / "brutus_scope.txt"
WHI_BRUTUS = "Tx-BRUTUS"

# Default fieldkit location, relative to the user's home. Override with the
# NOVA_HOME environment variable to point at any fieldkit root.
DEFAULT_FIELDKITS = [
    Path.home() / "Documents" / "NOVA" / "NOVA_fieldkit_v2_0",
]


def locate_fieldkit() -> Path | None:
    """Find a NOVA fieldkit root that contains the `nova` package and a data dir."""
    cands = []
    env = os.environ.get("NOVA_HOME")
    if env:
        cands.append(Path(env))
    cands.extend(DEFAULT_FIELDKITS)
    for c in cands:
        try:
            if (c / "nova").is_dir() and (c / "data").is_dir():
                return c
        except OSError:
            continue
    return None


def _import_nova(root: Path):
    os.environ.setdefault("NOVA_HOME", str(root))
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from nova import db  # noqa: E402
    try:
        from nova import office  # noqa: E402
    except Exception:
        office = None
    return db, office


def record_hunt(results: dict, *, write_json: bool = True) -> dict:
    """Mirror a Brutus results dict into NOVA.db (facts + a report card)."""
    out = {
        "ok": False, "nova_home": None, "db_path": None, "facts": 0,
        "report_id": None, "json_path": None, "error": None,
    }

    if write_json:
        try:
            RESULTS_JSON.write_text(json.dumps(results, indent=2), encoding="utf-8")
            out["json_path"] = str(RESULTS_JSON)
        except OSError as exc:
            out["error"] = f"json write failed: {exc}"

    root = locate_fieldkit()
    if not root:
        out["error"] = "NOVA fieldkit not found (set NOVA_HOME)"
        return out
    out["nova_home"] = str(root)

    try:
        db, office = _import_nova(root)
        out["db_path"] = str(db.db_path())

        summary = results.get("summary", {}) or {}
        mode = results.get("mode", "real")
        scope = results.get("scope", []) or []
        zulu = results.get("zulu", "")
        title = (f"Brutus hunt [{mode}] {summary.get('open_services', 0)} open / "
                 f"{summary.get('high_risk', 0)} high-risk across "
                 f"{summary.get('hosts_scanned', 0)} host(s)")

        body = (f"mode={mode} scope={','.join(scope) or '(demo)'} zulu={zulu}\n"
                f"summary={json.dumps(summary)}\n\n"
                f"{json.dumps(results, indent=2)}")
        db.put_fact(WHI_BRUTUS, title, body, kind="code")
        facts = 1

        for host in results.get("hosts", []) or []:
            ports = host.get("open_ports", []) or []
            if not ports:
                continue
            svc_txt = ", ".join(f"{p['port']}/{p['service']}({p['vulnerability_risk']})" for p in ports)
            db.put_fact(
                WHI_BRUTUS,
                f"Brutus {host.get('host')}: {len(ports)} open",
                f"host={host.get('host')} zulu={zulu}\nopen={svc_txt}",
                kind="code",
            )
            facts += 1
        out["facts"] = facts

        if office is not None:
            try:
                rank = 2 if summary.get("high_risk", 0) else 1
                rid = office.report(rank, title[:150], body[:1900])
                out["report_id"] = rid
            except Exception as exc:
                out["report_warn"] = f"report card skipped: {exc}"

        out["ok"] = True
    except Exception as exc:
        out["error"] = f"palace write failed: {exc}"
    return out


def read_results(limit: int = 5) -> dict:
    """Read Brutus findings back out of NOVA.db (WHI Tx-BRUTUS), newest first."""
    out = {"ok": False, "facts": [], "json": None, "error": None}
    if RESULTS_JSON.is_file():
        try:
            out["json"] = json.loads(RESULTS_JSON.read_text(encoding="utf-8"))
        except Exception:
            pass
    root = locate_fieldkit()
    if not root:
        out["error"] = "NOVA fieldkit not found (set NOVA_HOME)"
        return out
    try:
        db, _ = _import_nova(root)
        con = db.connect()
        rows = con.execute(
            "SELECT zulu, whi, title, body FROM facts WHERE whi=? ORDER BY id DESC LIMIT ?",
            (WHI_BRUTUS, limit),
        ).fetchall()
        con.close()
        out["facts"] = [dict(r) for r in rows]
        out["ok"] = True
    except Exception as exc:
        out["error"] = str(exc)
    return out


def dispatch(scope=None, demo: bool = False, timeout: float = 0.5, ack: bool = False) -> dict:
    """Run Brutus programmatically and mirror the results into NOVA.db.

    Real (non-demo) dispatch is gated and requires BOTH:
      * ack=True  (explicit authorization acknowledgment), and
      * the allowlist scope file (brutus_scope.txt) present,
    on top of a non-empty authorized scope. Refuses clearly otherwise.
    """
    sys.path.insert(0, str(PROJECT_DIR))
    import brutus_runner as br

    if demo:
        return br.run("demo", [], timeout=timeout, write_nova=True)

    # Legal/authorization gate for headless dispatch.
    print(br.LEGAL_WARNING)
    if not SCOPE_FILE.is_file():
        return {"ok": False, "refused": True,
                "error": f"allowlist scope file missing: {SCOPE_FILE}"}
    if not ack:
        return {"ok": False, "refused": True,
                "error": "authorization not acknowledged - call dispatch(..., ack=True) "
                         "(or nova_hunt.py --ack) to confirm authorized targets"}

    if isinstance(scope, str):
        scope = [scope]
    entries = br.gather_scope(scope or [])
    if not entries:
        return {"ok": False, "refused": True,
                "error": "no scope set - edit brutus_scope.txt or pass scope=[...]"}

    print("[auth] Headless acknowledgment accepted (ack=True) + scope file present.")
    return br.run("real", entries, timeout=timeout, write_nova=True, acknowledged=True)


def _cli(argv=None):
    import argparse
    p = argparse.ArgumentParser(prog="nova_hunt",
                                description="Dispatch the Brutus wardog or read its findings from NOVA.db.")
    p.add_argument("--scope", action="append", default=[], metavar="HOST|CIDR",
                   help="Authorized target(s); repeatable/comma-separated.")
    p.add_argument("--demo", action="store_true", help="Safe sandbox run.")
    p.add_argument("--ack", "--yes", dest="ack", action="store_true",
                   help="Acknowledge the legal/authorization notice (required for real).")
    p.add_argument("--timeout", type=float, default=0.5)
    p.add_argument("--read", action="store_true", help="Print latest Brutus findings from NOVA.db.")
    args = p.parse_args(argv)

    if args.read:
        data = read_results()
        print(json.dumps(data, indent=2))
        return 0 if data.get("ok") else 1

    res = dispatch(scope=args.scope, demo=args.demo, timeout=args.timeout, ack=args.ack)
    if res.get("refused"):
        print("Brutus refused: " + res.get("error", "no scope"))
        return 2
    print(json.dumps(res.get("summary", res), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
