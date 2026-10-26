"""Input validation for operator-supplied values.

Everything an operator types (targets, ports, paths, names) passes through
these functions before it reaches the engine or any external tool.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

# Absolute ceiling regardless of configuration: a /22. The configured limit is
# usually much smaller (default /24).
HARD_MAX_HOSTS = 1024
HARD_MAX_PORTS = 4096

_HOSTNAME_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
_SAFE_TEXT = re.compile(r"^[\w .,:;@/#()'&+\-]*$", re.UNICODE)


class ValidationError(ValueError):
    """Raised for invalid operator input. The message is safe to display."""


@dataclass(frozen=True)
class Target:
    """A validated, explicitly scoped scan target."""

    raw: str
    kind: str                      # "ip", "network", "hostname"
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None
    hostname: str | None

    @property
    def host_count(self) -> int:
        if self.network is None:
            return 1
        if self.network.num_addresses <= 2:
            return self.network.num_addresses
        # Exclude network and broadcast addresses for IPv4 ranges.
        return self.network.num_addresses - (2 if self.network.version == 4 else 0)

    def iter_hosts(self) -> list[str]:
        if self.network is None:
            return [self.hostname or self.raw]
        if self.network.num_addresses == 1:
            return [str(self.network.network_address)]
        return [str(h) for h in self.network.hosts()]

    def contains(self, address: str) -> bool:
        if self.network is None:
            return address.lower() == (self.hostname or "").lower()
        try:
            return ipaddress.ip_address(address) in self.network
        except ValueError:
            return False


def validate_hostname(name: str) -> str:
    name = (name or "").strip().rstrip(".")
    if not name or len(name) > 253:
        raise ValidationError("Hostname must be 1-253 characters.")
    labels = name.split(".")
    if not all(_HOSTNAME_LABEL.match(label) for label in labels):
        raise ValidationError(f"'{name}' is not a valid hostname.")
    if re.fullmatch(r"[\d.-]+", name):
        raise ValidationError(f"'{name}' looks like a malformed IP address or an address range.")
    return name.lower()


def _check_address(addr: ipaddress.IPv4Address | ipaddress.IPv6Address, raw: str) -> None:
    if addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        raise ValidationError(f"'{raw}' is a multicast/unspecified/reserved address and cannot be scanned.")
    if isinstance(addr, ipaddress.IPv4Address) and addr == ipaddress.IPv4Address("255.255.255.255"):
        raise ValidationError("The broadcast address cannot be scanned.")


def parse_target(raw: str, max_hosts: int = 256) -> Target:
    """Validate a single target: an IP address, a CIDR range, or a hostname.

    Ranges larger than ``max_hosts`` (and never more than ``HARD_MAX_HOSTS``)
    are rejected so that the tool cannot sweep an entire corporate network.
    Dash ranges and wildcards are deliberately unsupported.
    """
    raw = (raw or "").strip()
    if not raw:
        raise ValidationError("Target must not be empty.")
    if any(c in raw for c in " ,;*|&$`\\\"'<>\n\t"):
        raise ValidationError("Specify exactly one target per entry (no lists, wildcards or shell characters).")
    limit = min(max_hosts, HARD_MAX_HOSTS)

    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ValidationError(f"'{raw}' is not a valid CIDR network: {exc}") from None
        _check_address(net.network_address, raw)
        target = Target(raw=raw, kind="network", network=net, hostname=None)
        if target.host_count > limit:
            raise ValidationError(
                f"'{raw}' contains {target.host_count} hosts; the authorized limit is {limit}. "
                "Split the scope into smaller, explicitly authorized ranges.")
        return target

    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return Target(raw=raw, kind="hostname", network=None, hostname=validate_hostname(raw))
    _check_address(addr, raw)
    return Target(raw=raw, kind="ip", network=ipaddress.ip_network(addr), hostname=None)


def parse_ports(spec: str, max_ports: int = 1024) -> list[int]:
    """Parse a port list such as ``"22,80,443,8000-8010"``."""
    spec = (spec or "").replace(" ", "")
    if not spec:
        raise ValidationError("Port specification must not be empty.")
    if not re.fullmatch(r"\d+(-\d+)?(,\d+(-\d+)?)*", spec):
        raise ValidationError("Ports must look like '22,80,443' or '8000-8010'.")
    limit = min(max_ports, HARD_MAX_PORTS)
    ports: set[int] = set()
    for part in spec.split(","):
        lo_s, _, hi_s = part.partition("-")
        lo, hi = int(lo_s), int(hi_s or lo_s)
        if not (1 <= lo <= 65535 and 1 <= hi <= 65535) or lo > hi:
            raise ValidationError(f"Invalid port range '{part}'.")
        ports.update(range(lo, hi + 1))
        if len(ports) > limit:
            raise ValidationError(f"Too many ports: the limit is {limit}.")
    return sorted(ports)


def validate_free_text(value: str, field_name: str, max_len: int = 200,
                       required: bool = True) -> str:
    """Validate operator-entered text (names, ticket numbers, scope statements)."""
    value = (value or "").strip()
    if required and not value:
        raise ValidationError(f"{field_name} is required.")
    if len(value) > max_len:
        raise ValidationError(f"{field_name} must be at most {max_len} characters.")
    if not _SAFE_TEXT.match(value):
        raise ValidationError(f"{field_name} contains unsupported characters.")
    return value


def safe_filename(value: str, max_len: int = 64) -> str:
    """Reduce an arbitrary string (e.g. a hostname) to a safe file-name fragment."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "").strip("._")
    return (cleaned or "unnamed")[:max_len]


def validate_output_dir(path: str | Path) -> Path:
    """Resolve an operator-chosen output directory (must be an existing directory)."""
    p = Path(path).expanduser()
    if not str(path).strip():
        raise ValidationError("Output directory must not be empty.")
    try:
        p = p.resolve()
    except OSError as exc:
        raise ValidationError(f"Cannot resolve output directory: {exc}") from None
    if not p.is_dir():
        raise ValidationError(f"Output directory '{p}' does not exist.")
    return p
