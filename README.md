
# Firewall Rule Simulation (Python)

A lightweight tool to model and test firewall rules locally. It simulates inbound/outbound traffic against configurable rule sets and shows which packets would be allowed, blocked, or logged — without touching production devices.

## Features

- Define rules with fields: direction (IN/OUT), protocol (TCP/UDP/ICMP), src/dst IP (CIDR or any), src/dst port (number/range/any), action (ALLOW/BLOCK/LOG)
- First-match semantics with short-circuit on ALLOW/BLOCK; LOG records and continues
- CLI for batch simulation
- Simple GUI (Tkinter) to add/remove rules and test packets interactively

## Quick Start

Requirements: Python 3.9+

```bash
python -m venv .venv
. .venv/Scripts/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Run CLI
python -m firewall_simulator.cli --rules examples/rules.txt --packets examples/packets.csv

# Run GUI
python -m firewall_simulator.gui
```

## Rule Syntax

Each rule is a single line. Fields are space-separated `key=value`. Unspecified fields default to wildcard `any`.

Supported keys: `dir`, `proto`, `src`, `dst`, `sport`, `dport`, `action`.

Examples:

```
action=LOG dir=IN proto=TCP dport=22 src=10.0.0.0/8
action=ALLOW dir=IN proto=TCP dport=22
action=BLOCK dir=IN
```

Semantics:
- First matching rule decides outcome when action is ALLOW or BLOCK.
- LOG appends an entry to the decision log and evaluation continues.
- If no rule matches with a terminating action, default is BLOCK.

## Packets Input (CLI)

CSV headers: `dir,proto,src,dst,sport,dport`

```
IN,TCP,10.0.0.1,192.168.1.10,51515,22
OUT,UDP,192.168.1.10,8.8.8.8,5353,53
```

## Project Structure

```
firewall_simulator/
  __init__.py
  models.py
  engine.py
  parser.py
  cli.py
  gui.py
examples/
  rules.txt
  packets.csv
requirements.txt
README.md
```

## Notes

- This tool is a simulator only; it does not modify system firewall settings (iptables/UFW).
- IP matching uses Python's `ipaddress` module. Ports support single values and ranges like `1000-2000`.
- Direction values: `IN` or `OUT`.


