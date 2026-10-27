# Offline vulnerability data (Module E)

Module E compares installed packages with an **offline snapshot** of
vulnerability advisories stored on the USB drive in `vulndata/`. The toolkit
never downloads data during an assessment and never sends inventory data
anywhere.

## How matching works and how to read results

1. The software inventory collects package names, versions and source package
   names (`dpkg-query`, `rpm`, or the Windows uninstall registry).
2. Each package is compared with advisories **for the same distribution
   release** (e.g. `ubuntu:24.04`) using the distribution's own version rules
   (dpkg or rpm ordering).
3. A package below an advisory's fixed version produces a **potential**
   finding. One finding is produced per source package, listing every
   matching advisory.

| Data source | Confidence | Why |
|---|---|---|
| Distribution advisories (Ubuntu, Debian, Rocky, AlmaLinux) | High | Fixed versions already account for back-ported patches. |
| Generic or organisation-supplied records (e.g. Windows applications) | Low | Version strings alone do not prove a vulnerability; manual validation is required. |

**Severity** comes from the highest CVSS base score among the matching
advisories (CVSS v3.x scores are computed from the vector and the source is
cited). If the distribution rates the issue differently in its own context,
both ratings are shown in the rationale. Without a CVSS score, the vendor
rating is used; without either, the severity is Medium, stated explicitly.

Findings are always *potential*. The tool does not test whether vulnerable code
is reachable and **never exploits anything**.

## Building or updating a snapshot (on an admin workstation)

Do this on a trusted, internet-connected **admin workstation**, never on an
assessment target.

1. Download the OSV exports for the distributions you assess, over HTTPS:

   ```
   https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip       (~80 MB)
   https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip       (~800 MB)
   https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/all.zip
   https://osv-vulnerabilities.storage.googleapis.com/AlmaLinux/all.zip
   ```

2. Convert them. Archives are read in memory and never extracted. Use
   `--distro` to keep only what you need (this makes the snapshot much smaller):

   ```bash
   python scripts/vulndata_from_osv.py --out build/vulndata --distro ubuntu --distro debian \
          --snapshot-date 2026-10-26 Ubuntu-all.zip Debian-all.zip
   ```

   Check the printed per-release record counts (e.g. `ubuntu:24.04: …`).

3. Replace `<USB>/vulndata/` with the output directory.
4. Rebuild the drive's integrity manifest (`scripts/build_manifest.py <USB root>`)
   and record the new manifest SHA-256.
5. Run `PortableSecurityAudit verify` on the drive.

The snapshot carries its own `manifest.json` with SHA-256 hashes of its data
files. Module E refuses to use a snapshot that fails verification and reports
this as a limitation.

## Freshness

`config/default.toml` → `[vulnerability_data] max_age_days = 30`. Older
snapshots are still used, but the report states that newer vulnerabilities are
not covered. Refresh the snapshot before each engagement.

## Custom records (e.g. Windows applications)

Organisations can add their own `*.jsonl` file (listed in `manifest.json`
with its SHA-256) using the record format in `src/psatoolkit/core/vulndb.py`.
For Windows programs, use `"ecosystem": "windows"`, `"match": "prefix"` and
the program's display name, for example:

```json
{"id": "CVE-YYYY-NNNNN", "ecosystem": "windows", "package": "Example Viewer", "match": "prefix",
 "ranges": [{"introduced": "0", "fixed": "5.2"}], "cvss": [{"vector": "CVSS:3.1/...", "source": "NVD"}],
 "summary": "...", "references": ["https://..."]}
```

These matches are reported with **low confidence** and require manual validation.

## Licensing

OSV aggregates data from many databases, each under its own terms. Review
<https://google.github.io/osv.dev/data/> before redistributing a snapshot
outside your organisation. The snapshot manifest records its source.
