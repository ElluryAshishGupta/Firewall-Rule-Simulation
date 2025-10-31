from __future__ import annotations

import argparse
import csv
from dataclasses import asdict
from pathlib import Path
from typing import List

from .engine import evaluate_packet
from .models import Action, Direction, Packet
from .parser import parse_rules


def load_rules_from_file(path: Path):
	text = path.read_text(encoding="utf-8")
	return parse_rules(text)


def load_packets_from_csv(path: Path) -> List[Packet]:
	packets: List[Packet] = []
	with path.open(newline="", encoding="utf-8") as f:
		reader = csv.DictReader(f)
		for row in reader:
			packets.append(
				Packet(
					direction=Direction((row.get("dir") or row.get("direction") or "IN").upper()),
					protocol=(row.get("proto") or row.get("protocol") or None),
					source_ip=row.get("src") or row.get("source_ip") or None,
					destination_ip=row.get("dst") or row.get("destination_ip") or None,
					source_port=int(row["sport"]) if (row.get("sport") and row["sport"].strip()) else None,
					destination_port=int(row["dport"]) if (row.get("dport") and row["dport"].strip()) else None,
				)
			)
	return packets


def main():
	parser = argparse.ArgumentParser(description="Firewall Rule Simulator")
	parser.add_argument("--rules", required=True, help="Path to rules file")
	parser.add_argument("--packets", required=True, help="Path to packets CSV file")
	parser.add_argument("--verbose", action="store_true", help="Show matched rules")
	args = parser.parse_args()

	rules = load_rules_from_file(Path(args.rules))
	packets = load_packets_from_csv(Path(args.packets))

	for i, pkt in enumerate(packets, start=1):
		decision = evaluate_packet(rules, pkt)
		print(f"Packet {i}: {pkt.direction} {pkt.protocol or '-'} {pkt.source_ip}:{pkt.source_port} -> {pkt.destination_ip}:{pkt.destination_port}")
		print(f"  Decision: {decision.final_action}{' (default)' if decision.defaulted else ''}")
		if args.verbose and decision.matched_rules:
			for idx, r in enumerate(decision.matched_rules, start=1):
				print(f"    matched[{idx}]: action={r.action} dir={r.direction or 'any'} proto={r.protocol or 'any'} src={r.source_ip_spec or 'any'} dst={r.destination_ip_spec or 'any'} sport={r.source_port_spec or 'any'} dport={r.destination_port_spec or 'any'}")


if __name__ == "__main__":
	main()


