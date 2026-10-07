# Brutus

**A disciplined, scope-gated self-audit network-hygiene tool — NOVA's "wardog".**

Brutus performs a *real* local TCP service scan against an explicit, authorized
target scope, risk-rates what it finds, cross-references a published
weak-password list for basic credential-hygiene context, and (optionally) reports
its findings back to the NOVA field kit. It is a **defensive self-audit
instrument**: it finds exposure so it can be fixed. It is **not** an offensive
tool — there is intentionally **no password-cracking or hash-reversal
capability** included (see *Responsible Use*).

---

## What Brutus is

- A standalone command-line auditor you point at hosts **you own or are
  explicitly authorized to test**.
- "NOVA's trained wardog / cerberus": it can be dispatched by the NOVA field kit
  and drop its findings into NOVA's local palace (`NOVA.db`) for readback.
- Leashed by design: every real scan is gated behind a legal/authorization
  acknowledgment **and** an allowlist scope. No scope → it refuses to run.

## Key features

- **Real local TCP connect scan** — threaded probe of 22 common service ports per
  host, with a configurable connect timeout.
- **Risk rating** — each open service is tagged LOW / MEDIUM / HIGH by type
  (e.g. SMB, RDP, Telnet, VNC → HIGH).
- **Weak-password reference hygiene check** — compares an illustrative account set
  against a published common/breached-password *reference list*
  (`rainbow_table.py`). This is a lookup list for awareness only; it does **not**
  crack anything.
- **Scope allowlist (the leash)** — targets come from `--scope` and/or
  `brutus_scope.txt` (hosts, IPs, CIDRs). Defaults to localhost only.
- **Legal / authorization gate** — a required acknowledgment before any real scan.
- **NOVA dispatch hook** (`nova_hunt.py`) — dispatch a hunt and read findings back
  from `NOVA.db`.
- **HTML + JSON reports** — human-readable `report.html` and machine-readable
  `brutus_last_hunt.json` for each run.

## Install

- **Python 3.8+**, **standard library only** — no `pip install` required. See
  `requirements.txt`. Clone/download and run from the project folder.
- The optional NOVA readback path imports NOVA's `nova` package from a NOVA field
  kit; it is auto-located under your home directory or via the `NOVA_HOME`
  environment variable. If no field kit is found, scans still complete and write
  `report.html` + `brutus_last_hunt.json`; only the NOVA mirror is skipped.

## Usage

Brutus runs a **real** scan by default; `--demo` is an explicit, simulated,
non-destructive sandbox.

```bash
# REAL local hunt (DEFAULT). Shows the legal notice; type 'I AGREE' when prompted.
# Scope is read from brutus_scope.txt (localhost by default).
python brutus_runner.py

# REAL hunt, headless-safe (pre-acknowledged) against authorized targets
python brutus_runner.py --ack --scope 127.0.0.1
python brutus_runner.py --real --ack --scope 192.168.1.0/24 --scope 192.168.1.10

# SAFE simulated sandbox (no network touched, nothing written to NOVA.db)
python brutus_runner.py --demo

# Options
#   --scope HOST|CIDR   authorized target(s); repeatable / comma-separated
#   --ack               acknowledge the legal notice without a prompt (headless)
#   --timeout SECONDS   per-port TCP connect timeout (default 0.5)
#   --no-nova           do not write findings to NOVA.db
```

### The scope allowlist

In real mode Brutus only scans targets you authorize, via `--scope` and/or
`brutus_scope.txt` (one host / IP / CIDR per line; `#` starts a comment). The
shipped default is **localhost only**, with a commented example subnet you can
widen to your own authorized range. **With no scope set, real mode refuses to
run.**

### The legal / authorization gate

Before **any** real scan Brutus displays:

> *Only scan systems you own or networks you are explicitly authorized to audit;
> you are responsible for all activity.*

- **Interactive:** you must type `I AGREE` to proceed.
- **Headless / automated:** you must pass `--ack` **and** the allowlist scope file
  must be present. Missing either → Brutus refuses with a clear message.

## NOVA integration

`nova_hunt.py` is the clean seam between NOVA and Brutus.

```bash
# Dispatch a hunt and mirror results into NOVA.db (headless -> needs --ack)
python nova_hunt.py --scope 127.0.0.1 --ack
python nova_hunt.py --demo

# Read the latest findings back out of NOVA.db
python nova_hunt.py --read
```

```python
import nova_hunt
nova_hunt.dispatch(scope=["127.0.0.1"], ack=True)   # real (gated)
nova_hunt.dispatch(demo=True)                        # sandbox
nova_hunt.read_results()                             # read back
```

Findings are written to NOVA's SQLite palace (`NOVA.db`) as `facts` rows under
the WHI tag `Tx-BRUTUS` (one summary fact per hunt plus one per host with open
services) and as an open report card, so they surface through NOVA's normal
`db.hunt()` / `office.reports()` tools. A copy is also written to
`brutus_last_hunt.json` in the project folder. See `nova.ai` for the full NOVA
operating playbook.

## Responsible use / legal

- **Only scan systems you own or are explicitly authorized to audit.** You, the
  operator, are solely responsible for all activity performed with this tool.
  Unauthorized scanning may be illegal.
- Keep the scope allowlist tight; never widen it to third-party or public
  networks. The default is localhost.
- Brutus is a **defensive self-audit** instrument. **Offensive
  password-cracking / hash-reversal capability is intentionally NOT included**,
  and the tool does not attempt exploitation. Password checks rely only on a
  published weak-password *reference list* for awareness.

## Project layout

```
brutus_runner.py     Main entrypoint (argparse: --real default / --demo, legal gate, scan)
nova_hunt.py         NOVA dispatch + readback hook (writes to NOVA.db)
nova.ai              NOVA operating playbook
brutus_scope.txt     Authorized target allowlist (the leash; localhost default)
requirements.txt     Dependencies note (standard library only)
target_analyzer.py   Port/service scan helpers
service_scanner.py   Service detection helpers
rainbow_table.py     Published weak-password reference list
risk_analyzer.py     Account risk assessment helpers
risk_demo.py         Small risk demo
auth_gate.py         Human-in-the-loop authorization helper (interactive)
wifi_survey.py       Local Wi-Fi survey helper
brutus.bat / .ps1    Human launchers
package.bat          Real (guarded) PyInstaller build helper
```

---

© 2026 Purposeful Stride LLC. All rights reserved. See `LICENSE`.
