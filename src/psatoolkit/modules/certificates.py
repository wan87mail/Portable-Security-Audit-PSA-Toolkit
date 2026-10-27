"""Shared certificate evaluation for Windows and Linux certificate checks."""

from __future__ import annotations

from datetime import date
from typing import Any

from psatoolkit.core.engine import AssessmentContext, Check
from psatoolkit.core.models import Confidence, Finding, FindingStatus, Severity
from psatoolkit.modules._common import cwe

EXPIRY_WARNING_DAYS = 30
WEAK_SIGNATURES = ("md5", "sha1")
MIN_RSA_BITS = 2048


def evaluate_certificates(ctx: AssessmentContext, check: Check, certs: list[dict[str, Any]],
                          today: date | None = None) -> list[Finding]:
    """Produce findings for certificates.

    Each cert dict has: subject, issuer, not_after (date), signature_algorithm,
    key_bits (int|None), key_type, source (file path or store location).
    """
    today = today or date.today()
    findings: list[Finding] = []
    for c in certs:
        days = (c["not_after"] - today).days
        ev = ctx.evidence("Certificate metadata (public data only)", c["source"],
                          {**c, "not_after": c["not_after"].isoformat(), "days_remaining": days})
        name = c.get("subject") or c["source"]
        sig = (c.get("signature_algorithm") or "").lower()
        common = dict(component=f"Certificate {name}", evidence=[ev], confidence=Confidence.HIGH,
                      status=FindingStatus.CONFIRMED)
        if days < 0:
            findings.append(ctx.finding(
                check, title=f"Certificate expired {-days} day(s) ago: {name}", severity=Severity.HIGH,
                description=f"The certificate at {c['source']} expired on {c['not_after']}.",
                impact="Clients either fail to connect or are trained to ignore certificate warnings, enabling "
                       "man-in-the-middle attacks.",
                remediation="Renew and deploy a replacement certificate; remove the expired one if unused.",
                verification="Re-run the check, or inspect the served certificate with a TLS client.",
                severity_rationale="High: an expired certificate in use breaks authentication of the service; "
                                   "lower if the certificate is no longer bound to any service.",
                references=[cwe(324, "Use of a Key Past its Expiration Date")], **common))
        elif days <= EXPIRY_WARNING_DAYS:
            findings.append(ctx.finding(
                check, title=f"Certificate expires in {days} day(s): {name}", severity=Severity.MEDIUM,
                description=f"The certificate at {c['source']} expires on {c['not_after']}.",
                impact="Service outage or certificate warnings when it expires.",
                remediation="Renew the certificate before expiry and automate renewal where possible.",
                verification="Confirm the new expiry date after renewal.",
                severity_rationale="Medium: imminent availability and trust risk.",
                references=[cwe(298, "Improper Validation of Certificate Expiration")], **common))
        if any(w in sig for w in WEAK_SIGNATURES):
            findings.append(ctx.finding(
                check, title=f"Certificate uses a weak signature algorithm ({c.get('signature_algorithm')}): {name}",
                severity=Severity.MEDIUM, description=f"{c['source']} is signed with {c.get('signature_algorithm')}.",
                impact="SHA-1/MD5 signatures are vulnerable to collision attacks and are rejected by modern clients.",
                remediation="Reissue the certificate with a SHA-256 (or stronger) signature.",
                verification="openssl x509 -noout -text | grep 'Signature Algorithm'",
                severity_rationale="Medium: weakens certificate authenticity guarantees.",
                references=[cwe(327, "Use of a Broken or Risky Cryptographic Algorithm")], **common))
        bits = c.get("key_bits")
        if bits and "rsa" in (c.get("key_type") or "").lower() and bits < MIN_RSA_BITS:
            findings.append(ctx.finding(
                check, title=f"Certificate uses a {bits}-bit RSA key: {name}", severity=Severity.MEDIUM,
                description=f"{c['source']} has an RSA key shorter than {MIN_RSA_BITS} bits.",
                impact="Short RSA keys may be factored, allowing impersonation or decryption.",
                remediation=f"Reissue with an RSA key of at least {MIN_RSA_BITS} bits (3072 recommended) or ECDSA P-256.",
                verification="openssl x509 -noout -text | grep 'Public-Key'",
                severity_rationale="Medium: below current minimum key-strength guidance (NIST SP 800-131A).",
                references=[cwe(326, "Inadequate Encryption Strength")], **common))
    return findings
