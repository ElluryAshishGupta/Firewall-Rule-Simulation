from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from ipaddress import ip_address, ip_network, IPv4Address, IPv4Network
from typing import List, Optional, Tuple, Union


class Action(str, Enum):
	ALLOW = "ALLOW"
	BLOCK = "BLOCK"
	LOG = "LOG"


class Direction(str, Enum):
	IN = "IN"
	OUT = "OUT"


PortSpec = Union[int, Tuple[int, int], None]


def parse_port_spec(value: Optional[str]) -> PortSpec:
	if value is None or value == "any":
		return None
	if "-" in value:
		start_str, end_str = value.split("-", 1)
		start = int(start_str)
		end = int(end_str)
		if start > end:
			raise ValueError("Port range start must be <= end")
		return (start, end)
	return int(value)


def port_matches(spec: PortSpec, actual: Optional[int]) -> bool:
	if spec is None:
		return True
	if actual is None:
		return False
	if isinstance(spec, int):
		return actual == spec
	start, end = spec
	return start <= actual <= end


def parse_ip_spec(value: Optional[str]) -> Optional[Union[IPv4Network, str]]:
	if value is None or value == "any":
		return None
	# Allow wildcard "*" as any
	if value == "*":
		return None
	if "/" in value:
		return ip_network(value, strict=False)
	# single IP address
	return str(ip_address(value))


def ip_matches(spec: Optional[Union[IPv4Network, str]], actual: Optional[str]) -> bool:
	if spec is None:
		return True
	if actual is None:
		return False
	addr = ip_address(actual)
	if isinstance(spec, str):
		return str(addr) == spec
	return addr in spec


@dataclass(frozen=True)
class Packet:
	direction: Direction
	protocol: Optional[str] = None  # TCP, UDP, ICMP, or None
	source_ip: Optional[str] = None
	destination_ip: Optional[str] = None
	source_port: Optional[int] = None
	destination_port: Optional[int] = None


@dataclass
class Rule:
	action: Action
	direction: Optional[Direction] = None
	protocol: Optional[str] = None
	source_ip_spec: Optional[Union[IPv4Network, str]] = None
	destination_ip_spec: Optional[Union[IPv4Network, str]] = None
	source_port_spec: PortSpec = None
	destination_port_spec: PortSpec = None

	def matches(self, packet: Packet) -> bool:
		if self.direction is not None and packet.direction != self.direction:
			return False
		if self.protocol is not None and (packet.protocol or "").upper() != self.protocol:
			return False
		if not ip_matches(self.source_ip_spec, packet.source_ip):
			return False
		if not ip_matches(self.destination_ip_spec, packet.destination_ip):
			return False
		if not port_matches(self.source_port_spec, packet.source_port):
			return False
		if not port_matches(self.destination_port_spec, packet.destination_port):
			return False
		return True


@dataclass
class Decision:
	final_action: Action
	matched_rules: List[Rule]
	defaulted: bool


