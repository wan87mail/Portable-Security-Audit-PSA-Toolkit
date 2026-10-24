"""Authorization workflow: the notice, operator confirmation and remote scope.

No assessment can start without an :class:`AuthorizationRecord`. Remote
targets additionally need an entry in :class:`TargetScope`, each with its own
permission reference and explicit confirmation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from psatoolkit.core.validation import (HARD_MAX_HOSTS, Target, ValidationError, parse_target,
                                        validate_free_text)

CONFIRMATION_PHRASE = "I AM AUTHORIZED"

AUTHORIZATION_NOTICE = """\
AUTHORIZED USE ONLY

This toolkit performs security assessments of computer systems. You may use
it ONLY on systems that you own or for which you hold explicit, written
authorization from the system owner to perform a security assessment.

Unauthorized scanning or assessment of computer systems may be illegal under
computer misuse laws in your jurisdiction (for example the U.S. Computer
Fraud and Abuse Act, the UK Computer Misuse Act 1990, or Malaysia's Computer
Crimes Act 1997) and may violate organisational policy.

By continuing you confirm that:
  1. You are authorized to assess this computer and every remote target you add.
  2. The assessment scope and timing have been approved (change ticket,
     engagement letter or equivalent).
  3. You understand that the assessment is read-only by default, but may still
     generate log entries, alerts in security monitoring tools, and network
     traffic when network modules are used.

All activity is recorded in a tamper-evident audit log on this drive.
"""

NOTICE_SHA256 = hashlib.sha256(AUTHORIZATION_NOTICE.encode("utf-8")).hexdigest()


class AuthorizationError(Exception):
    """Raised when authorization is missing, incomplete or out of scope."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class AuthorizationRecord:
    operator: str
    organization: str
    engagement_reference: str      # ticket / engagement letter / change number
    scope_statement: str
    host: str                      # local host being assessed
    method: str                    # "gui", "cli-interactive", "cli-argument", "demo"
    confirmed_at: datetime
    notice_sha256: str = NOTICE_SHA256

    def to_dict(self) -> dict[str, Any]:
        return {
            "operator": self.operator,
            "organization": self.organization,
            "engagement_reference": self.engagement_reference,
            "scope_statement": self.scope_statement,
            "host": self.host,
            "method": self.method,
            "confirmed_at": self.confirmed_at.isoformat(timespec="seconds"),
            "notice_sha256": self.notice_sha256,
        }


def create_authorization(*, operator: str, organization: str, engagement_reference: str,
                         scope_statement: str, host: str, confirmed: bool,
                         method: str) -> AuthorizationRecord:
    """Validate operator input and create the authorization record.

    ``confirmed`` must be the result of an explicit operator action (ticking
    the GUI checkbox or typing :data:`CONFIRMATION_PHRASE`), never a default.
    """
    if confirmed is not True:
        raise AuthorizationError("Authorization was not confirmed. The assessment cannot start.")
    try:
        return AuthorizationRecord(
            operator=validate_free_text(operator, "Operator name", 100),
            organization=validate_free_text(organization, "Organization", 100, required=False),
            engagement_reference=validate_free_text(engagement_reference, "Authorization reference", 100),
            scope_statement=validate_free_text(scope_statement, "Scope statement", 500, required=False)
            or "Local host only",
            host=host,
            method=method,
            confirmed_at=_now(),
        )
    except ValidationError as exc:
        raise AuthorizationError(str(exc)) from None


def phrase_matches(typed: str) -> bool:
    return (typed or "").strip().upper() == CONFIRMATION_PHRASE


@dataclass(frozen=True)
class AuthorizedTarget:
    target: Target
    permission_reference: str
    confirmed_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.raw,
            "kind": self.target.kind,
            "host_count": self.target.host_count,
            "permission_reference": self.permission_reference,
            "confirmed_at": self.confirmed_at.isoformat(timespec="seconds"),
        }


@dataclass
class TargetScope:
    """The explicit list of remote targets the operator is authorized to scan."""

    max_hosts_per_target: int = 256
    max_total_hosts: int = 256
    targets: list[AuthorizedTarget] = field(default_factory=list)

    @property
    def total_hosts(self) -> int:
        return sum(t.target.host_count for t in self.targets)

    def add(self, raw: str, permission_reference: str, confirmed: bool) -> AuthorizedTarget:
        if confirmed is not True:
            raise AuthorizationError(f"Permission to scan '{raw}' was not confirmed.")
        try:
            ref = validate_free_text(permission_reference, "Permission reference", 100)
            target = parse_target(raw, self.max_hosts_per_target)
        except ValidationError as exc:
            raise AuthorizationError(str(exc)) from None
        if any(t.target.raw == target.raw for t in self.targets):
            raise AuthorizationError(f"'{raw}' is already in the authorized scope.")
        limit = min(self.max_total_hosts, HARD_MAX_HOSTS)
        if self.total_hosts + target.host_count > limit:
            raise AuthorizationError(
                f"Adding '{raw}' would exceed the total scope limit of {limit} hosts.")
        entry = AuthorizedTarget(target=target, permission_reference=ref, confirmed_at=_now())
        self.targets.append(entry)
        return entry

    def remove(self, raw: str) -> None:
        self.targets = [t for t in self.targets if t.target.raw != raw]

    def clear(self) -> None:
        self.targets.clear()

    def is_authorized(self, address: str) -> bool:
        return any(t.target.contains(address) for t in self.targets)

    def require(self, address: str) -> None:
        if not self.is_authorized(address):
            raise AuthorizationError(f"'{address}' is outside the authorized scope; refusing to contact it.")

    def preview(self, ports: list[int], rate_per_second: int) -> dict[str, Any]:
        """Dry-run summary shown to the operator before any traffic is sent."""
        probes = self.total_hosts * len(ports)
        return {
            "targets": [t.to_dict() for t in self.targets],
            "total_hosts": self.total_hosts,
            "ports_per_host": len(ports),
            "total_connection_attempts": probes,
            "rate_limit_per_second": rate_per_second,
            "estimated_minimum_duration_seconds": round(probes / max(rate_per_second, 1), 1),
        }

    def to_dict(self) -> list[dict[str, Any]]:
        return [t.to_dict() for t in self.targets]
