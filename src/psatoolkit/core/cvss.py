"""CVSS helpers: v3.x base-score calculation and qualitative severity bands.

Vulnerability feeds often provide only the vector string. The base score is
computed with the formulas of the CVSS v3.1 specification (FIRST), which also
apply to v3.0 vectors for the base metrics used here. CVSS v4.0 vectors are
recorded but not scored locally.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from psatoolkit.core.models import Severity

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class CvssError(ValueError):
    pass


@dataclass(frozen=True)
class CvssScore:
    version: str
    vector: str
    score: float | None

    @property
    def severity(self) -> Severity | None:
        return severity_from_score(self.score)


def roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest one-decimal number >= value, robust to float error."""
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (math.floor(int_input / 10_000) + 1) / 10.0


def parse_vector(vector: str) -> tuple[str, dict[str, str]]:
    m = re.fullmatch(r"CVSS:(3\.[01]|4\.0)/(.+)", (vector or "").strip())
    if not m:
        raise CvssError(f"not a CVSS v3/v4 vector: {vector!r}")
    metrics = {}
    for part in m.group(2).split("/"):
        key, _, value = part.partition(":")
        if not key or not value or key in metrics:
            raise CvssError(f"malformed metric {part!r}")
        metrics[key] = value
    return m.group(1), metrics


def base_score_v3(vector: str) -> float:
    version, m = parse_vector(vector)
    if not version.startswith("3"):
        raise CvssError("only CVSS v3.x vectors can be scored locally")
    try:
        if any(k not in m for k in _REQUIRED):
            raise KeyError
        scope = m["S"]
        av, ac, ui = _W["AV"][m["AV"]], _W["AC"][m["AC"]], _W["UI"][m["UI"]]
        pr = _PR[scope][m["PR"]]
        c, i, a = (_W["CIA"][m[k]] for k in ("C", "I", "A"))
    except KeyError:
        raise CvssError(f"incomplete or invalid base metrics in {vector!r}") from None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        return roundup(min(impact + exploitability, 10))
    return roundup(min(1.08 * (impact + exploitability), 10))


def score_vector(vector: str, given_score: float | None = None) -> CvssScore:
    """Return a CvssScore; computes v3 scores, keeps a supplied score for v4."""
    version, _ = parse_vector(vector)
    if version.startswith("3"):
        return CvssScore(version, vector, base_score_v3(vector))
    return CvssScore(version, vector, given_score)


def severity_from_score(score: float | None) -> Severity | None:
    """CVSS v3/v4 qualitative rating scale."""
    if score is None:
        return None
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO
