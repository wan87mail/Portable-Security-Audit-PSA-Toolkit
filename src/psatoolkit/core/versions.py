"""Package version comparison: Debian (dpkg), RPM and a generic dotted scheme.

All functions return -1, 0 or 1 like the classic ``cmp``.
"""

from __future__ import annotations

import re


def _cmp(a, b) -> int:
    return (a > b) - (a < b)


# --------------------------------------------------------------------------
# dpkg (deb-version(7))
# --------------------------------------------------------------------------

def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) else 0
            bc = _dpkg_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return _cmp(ac, bc)
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = _cmp(a[i], b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _dpkg_split(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    upstream, _, revision = v.rpartition("-") if "-" in v else (v, "", "")
    return epoch, upstream, revision


def dpkg_compare(a: str, b: str) -> int:
    ea, ua, ra = _dpkg_split(a)
    eb, ub, rb = _dpkg_split(b)
    if ea != eb:
        return _cmp(ea, eb)
    return _dpkg_verrevcmp(ua, ub) or _dpkg_verrevcmp(ra, rb)


# --------------------------------------------------------------------------
# RPM (rpmvercmp)
# --------------------------------------------------------------------------

def rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not a[i].isalnum() and a[i] not in "~^":
            i += 1
        while j < len(b) and not b[j].isalnum() and b[j] not in "~^":
            j += 1
        # tilde sorts before everything, even the end of the string
        if (i < len(a) and a[i] == "~") or (j < len(b) and b[j] == "~"):
            if not (i < len(a) and a[i] == "~"):
                return 1
            if not (j < len(b) and b[j] == "~"):
                return -1
            i += 1
            j += 1
            continue
        # caret sorts after the end of the string but before any other segment
        if (i < len(a) and a[i] == "^") or (j < len(b) and b[j] == "^"):
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue
        if i >= len(a) or j >= len(b):
            break
        if a[i].isdigit():
            m1 = re.match(r"\d+", a[i:]).group(0)
            m2 = re.match(r"\d+", b[j:])
            if not m2:
                return 1          # numeric segment beats alpha segment
            m2s = m2.group(0)
            r = _cmp(int(m1), int(m2s))
            i += len(m1)
            j += len(m2s)
        else:
            m1 = re.match(r"[A-Za-z]+", a[i:]).group(0)
            m2 = re.match(r"[A-Za-z]+", b[j:])
            if not m2:
                return -1
            m2s = m2.group(0)
            r = _cmp(m1, m2s)
            i += len(m1)
            j += len(m2s)
        if r:
            return r
    rest_a, rest_b = i < len(a), j < len(b)
    return _cmp(rest_a, rest_b)


def _rpm_split(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    version, _, release = v.rpartition("-") if "-" in v else (v, "", "")
    return epoch, version, release


def rpm_compare(a: str, b: str) -> int:
    ea, va, ra = _rpm_split(a)
    eb, vb, rb = _rpm_split(b)
    if ea != eb:
        return _cmp(ea, eb)
    return rpmvercmp(va, vb) or (rpmvercmp(ra, rb) if ra and rb else 0)


# --------------------------------------------------------------------------
# Generic (Windows DisplayVersion, upstream versions)
# --------------------------------------------------------------------------

def _generic_parts(v: str) -> list[tuple[int, int | str]]:
    return [(1, int(p)) if p.isdigit() else (0, p.lower()) for p in re.findall(r"\d+|[A-Za-z]+", v or "")]


def generic_compare(a: str, b: str) -> int:
    pa, pb = _generic_parts(a), _generic_parts(b)
    for x, y in zip(pa, pb):
        if x != y:
            return _cmp(x, y)
    # "1.2" == "1.2.0"; extra non-zero numeric parts make a version newer
    tail_a = [p for p in pa[len(pb):] if p != (1, 0)]
    tail_b = [p for p in pb[len(pa):] if p != (1, 0)]
    return _cmp(bool(tail_a), bool(tail_b))


COMPARATORS = {"dpkg": dpkg_compare, "rpm": rpm_compare, "generic": generic_compare}
