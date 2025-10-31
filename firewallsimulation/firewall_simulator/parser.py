from __future__ import annotations

from typing import Iterable, List, Optional

from .models import Action, Direction, Rule, parse_ip_spec, parse_port_spec


def parse_rule_line(line: str) -> Optional[Rule]:
	stripped = line.strip()
	if not stripped or stripped.startswith("#"):
		return None
	parts = stripped.split()
	kwargs = {}
	for part in parts:
		if "=" not in part:
			continue
		key, value = part.split("=", 1)
		key = key.strip().lower()
		value = value.strip()
		if key == "action":
			kwargs["action"] = Action(value.upper())
		elif key == "dir":
			kwargs["direction"] = Direction(value.upper())
		elif key == "proto":
			kwargs["protocol"] = value.upper()
		elif key == "src":
			kwargs["source_ip_spec"] = parse_ip_spec(value)
		elif key == "dst":
			kwargs["destination_ip_spec"] = parse_ip_spec(value)
		elif key == "sport":
			kwargs["source_port_spec"] = parse_port_spec(value)
		elif key == "dport":
			kwargs["destination_port_spec"] = parse_port_spec(value)
		else:
			# ignore unknown keys for forward compatibility
			pass
	if "action" not in kwargs:
		raise ValueError(f"Rule missing action: {line}")
	return Rule(**kwargs)


def parse_rules(text: str) -> List[Rule]:
	rules: List[Rule] = []
	for idx, raw in enumerate(text.splitlines(), start=1):
		try:
			rule = parse_rule_line(raw)
			if rule is not None:
				rules.append(rule)
		except Exception as exc:
			raise ValueError(f"Error parsing rule at line {idx}: {raw}\n{exc}") from exc
	return rules


