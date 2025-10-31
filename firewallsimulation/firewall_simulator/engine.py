from __future__ import annotations

from typing import Iterable, List, Tuple

from .models import Action, Decision, Packet, Rule


def evaluate_packet(rules: Iterable[Rule], packet: Packet) -> Decision:
	matched_rules: List[Rule] = []
	for rule in rules:
		if not rule.matches(packet):
			continue
		matched_rules.append(rule)
		if rule.action == Action.LOG:
			continue
		# First terminating action decides
		return Decision(final_action=rule.action, matched_rules=matched_rules, defaulted=False)
	# No terminating match -> default BLOCK
	return Decision(final_action=Action.BLOCK, matched_rules=matched_rules, defaulted=True)


def evaluate_packets(rules: Iterable[Rule], packets: Iterable[Packet]) -> List[Decision]:
	return [evaluate_packet(rules, pkt) for pkt in packets]


