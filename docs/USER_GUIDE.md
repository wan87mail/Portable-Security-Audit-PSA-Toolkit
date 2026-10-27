# IT administrator manual

Portable Security Audit (PSA) 1.0. This manual is for the people who prepare the
USB drive, run assessments and handle the results. Installation and building are
covered in the [README](../README.md) and [BUILD.md](BUILD.md). The individual
checks are listed in [CHECKS.md](CHECKS.md).

**Contents:**
1. [What the toolkit does and does not do](#1-what-the-toolkit-does-and-does-not-do)
2. [Roles](#2-roles)
3. [Engagement workflow](#3-engagement-workflow)
4. [Before the engagement](#4-before-the-engagement)
5. [Running an assessment](#5-running-an-assessment)
6. [What happens on the target](#6-what-happens-on-the-target)
7. [Reading the results](#7-reading-the-results)
8. [After the engagement](#8-after-the-engagement)
9. [Looking after the drive](#9-looking-after-the-drive)
10. [Configuration reference](#10-configuration-reference)
11. [Troubleshooting](#11-troubleshooting)
12. [Questions and limitations](#12-questions-and-limitations)

---

## 1. What the toolkit does and does not do

**It does:**
- read the security configuration of the computer it runs on (Windows 10/11,
  Windows Server 2019/2022/2025, Ubuntu 22.04/24.04, other Linux best-effort);
- compare installed software with an offline vulnerability snapshot you supply;
- compare settings with your organisation's own baselines;
- write explainable findings with evidence, severity, remediation and verification
  steps, as HTML, PDF, CSV and JSON reports, plus a tamper-evident audit log.

**It does not:**
- change any setting, install anything, or start or stop services;
- exploit vulnerabilities, collect credentials, dump password hashes or bypass
  antivirus/EDR;
- contact other computers. This build has **no network assessment module**:
  remote targets can be recorded for the report scope, but are never contacted;
- upload anything, or start automatically when the drive is inserted;
- certify compliance. Baseline results show how settings compare with your
  baseline, not formal conformity to CIS, ISO 27001 or any other standard.

A finding of type *potential* (for example, a version that appears in an advisory)
is a lead to verify, not proof of a vulnerability.

## 2. Roles

| Role | Responsibilities |
|---|---|
| **Drive custodian** | Builds or receives a release, prepares and verifies drives ([BUILD.md](BUILD.md)), keeps the manifest SHA-256 values on record, refreshes vulnerability data and baselines, stores drives securely. |
| **Operator** | Holds the written authorization, runs the assessment on the target, hands over the results, and returns the drive. |
| **Report owner** (for example, the system owner or security team) | Receives the report, verifies it, assigns remediation, and decides on retention. |

One person can hold several roles. The authorization should come from the
**system owner**, not from the operator.

## 3. Engagement workflow

```
 Authorization ─► Verify drive ─► Run on target ─► Verify report ─► Hand over ─► Remediate ─► Re-assess
  (ticket /        (verify,        (elevated if     (verify-report)  (export-     (owners)      (same steps;
   letter)          manifest hash)   authorized)                       report)                   findings close)
```

Use the [release checklist](RELEASE_CHECKLIST.md) section 4 as a per-engagement
checklist.

## 4. Before the engagement

1. **Get written authorization.** It should name the host(s), the time window,
   whether elevated (Administrator/root) execution is allowed, and where the
   results may be stored. You will type its reference (for example, a change
   ticket number) into the tool. The reference appears in the report and the
   audit log.
2. **Verify the drive** on a trusted computer:

   ```
   PortableSecurityAudit verify
   ```

   It must say **PASSED**, and the printed *Manifest SHA-256* must match the value
   the drive custodian recorded. If it says FAILED, don't use the drive.
3. **Refresh the inputs if needed.**
   - The vulnerability snapshot should be recent: older than 30 days is flagged
     (see [VULNDATA.md](VULNDATA.md)).
   - Check that the baselines for this kind of system are imported (`baselines`
     command, see [BASELINES.md](BASELINES.md)).
   - Rebuild the manifest after any change.
4. **Tell the endpoint-security team.** Running a tool from USB can trigger
   AV/EDR or device-control alerts. Give them the executable's SHA-256 (in the
   release notes). The toolkit never tries to evade or disable security
   controls.
5. **Decide where the reports go.** By default they are saved on the drive in
   `reports/`. If the drive is write-protected, or policy requires it, choose
   another folder with `--output` or **Change output folder…**. Reports describe
   the host's weaknesses, so store them like confidential documents. An
   encrypted drive (BitLocker To Go or LUKS) is recommended.

## 5. Running an assessment

### 5.1 Starting the tool

Nothing runs when you insert the drive. Start it yourself:

| Platform | Standard user | Elevated (more checks) |
|---|---|---|
| Windows | Double-click `PortableSecurityAudit.exe` | Right-click → **Run as administrator** |
| Linux | `bash /media/$USER/PSA/PortableSecurityAudit/PortableSecurityAudit.sh` | Same command with `sudo` |
| Linux, no GUI | Add a command, for example `… PortableSecurityAudit.sh info` | `sudo … PortableSecurityAudit.sh audit` |

Run elevated only when the authorization allows it. Without elevation some
checks are skipped. They appear under *Limitations* with the reason, and
the posture rating warns when coverage is low:

| Without elevation you lose |  |
|---|---|
| Windows | BitLocker status, audit policy, and SMB server configuration (SMBv1 may become *inconclusive*) |
| Linux | sudoers review, `/etc/shadow` flags, `sshd -T`, firewall rule sets, process names of other users' sockets, and root-only directories in file sweeps |

`info` shows, before anything runs, which checks will run on this host and
why others will be skipped.

### 5.2 The dashboard (GUI)

| Control | What it does |
|---|---|
| **1. Start Local Security Audit** | Shows the authorization notice. **Start** becomes clickable only after you enter your name and the authorization reference and tick the confirmation box. |
| **2. Configure Authorized Remote Target** | Records remote IPs, CIDR ranges (at most 256 hosts by default) or hostnames, each with its own permission reference. **Preview** validates an entry. Targets are recorded in the report scope only, because this build has no network module. |
| **3. Select Assessment Modules** | Chooses the modules. Modules that don't apply to this OS are greyed out with the reason. **Import baseline…** adds an organisational baseline. |
| **4. Run Network Assessment** | Explains that this build includes no network module. Nothing is sent. |
| **5. View Previous Reports** | Lists reports in the output folder; open, verify or export them. |
| **6. Export Report** | Verifies the latest report and copies it to a folder you choose (for example, a share for the report owner). Nothing is uploaded. |
| **7. Verify Tool Integrity** | Checks every program and data file on the drive against the manifest. |
| **8. STOP ASSESSMENT** | Emergency stop. Running checks are terminated, and partial results are saved and marked *stopped*. |

Also on the dashboard:
- **Demo mode** practises with sample findings and runs no commands.
- **Change output folder…** chooses where reports go.
- **Open Generated Report** opens the latest report.

The status log explains every skipped or failed check.

### 5.3 Command line

Every function is available without the GUI. Below, `PSA` stands for
`PortableSecurityAudit.exe` (Windows) or `bash PortableSecurityAudit.sh` (Linux).

| Command | Purpose |
|---|---|
| `PSA info` | Detected OS, privileges, and which checks will run or be skipped |
| `PSA modules -v` | Modules and checks with their requirements |
| `PSA audit` | Assessment with interactive authorization prompts |
| `PSA audit --demo` | Demonstration with sample data |
| `PSA audit --output DIR` | Write reports and (if the drive is read-only) logs to `DIR` |
| `PSA audit --modules windows_audit,baselines` | Run selected modules only (ids from `modules`) |
| `PSA reports [--output DIR]` | List previous reports |
| `PSA verify-report FOLDER` | Verify every file of a report (`SHA256SUMS` and the canonical content hash) |
| `PSA export-report FOLDER DEST [--formats html,pdf,csv]` | Verify a report and copy or re-render it to `DEST` |
| `PSA verify-log FILE` | Verify an audit log's hash chain |
| `PSA verify` | Verify the drive against `checksums/manifest.json` |
| `PSA selftest [--require-gui]` | Check that this build contains every component |
| `PSA baselines` / `PSA import-baseline FILE [--replace]` | List or import organisational baselines |
| `PSA build-manifest` | (Drive custodian) Rewrite the integrity manifest after changing the drive |
| `PSA preview-scan --target T [--ports P]` | Validate a target scope and show what a scan would contact; sends nothing |

**Scripted (non-interactive) runs** must state the authorization explicitly. The
phrase must be typed exactly:

```bash
PSA audit --operator "Jane Admin" --organization "Example Ltd" --reference "CHG-1234" \
          --scope "Finance file server FS01" --confirm "I AM AUTHORIZED" --output /secure/reports
```

**Exit codes:** `0` OK · `1` error · `2` usage error (for example, an unknown module or
an invalid target) · `3` authorization refused · `4` integrity
check failed (drive or report) · `130` stopped by the operator.

Press **Ctrl+C** at any time for an emergency stop.

### 5.4 How long it takes

A local audit usually takes 10–60 seconds. On Linux, the world-writable and
set-ID sweeps read the metadata of every file under `/usr`, `/etc`, `/opt` and
similar directories. On large servers with a cold cache this can take several
minutes. Each check has its own time budget (`check_timeout_seconds`). A check
that runs out of time is reported as a limitation, and the assessment continues.

## 6. What happens on the target

Knowing the toolkit's footprint helps you explain alerts and answer the system
owner's questions.

| Activity | Detail |
|---|---|
| **Programs started** | Only these 15, each limited to read-only arguments: `powershell` (inline `Get-*` queries), `net accounts`, `auditpol /get` (Windows); `systemctl`, `lsblk`, `dpkg-query`, `rpm -q`, `ip … show`, `ufw status`, `nft list`, `iptables -L/-S`, `apt list`, `dnf --cacheonly`, `sshd -T` (Linux); `openssl x509 -noout`. They are run only from the system directories (and `tools/` on the drive for openssl), never through a shell. |
| **Files read** | Configuration and status files (for example `/etc/ssh/sshd_config` and `/proc/sys/...`), and file metadata during the permission sweeps. Device files, pipes and secret files (shadow, private keys, home directories) are never read by baselines. Evidence holds only the values compared. |
| **Files written** | The report folder, and logs on the drive (or in the output folder if the drive is read-only). On POSIX, report and log folders are owner-only. A private temporary folder in the system temp directory is removed at the end. |
| **Network** | None. Local modules open no connections, and nothing is uploaded. |
| **Logs on the target** | Windows may record process creation (event 4688 or Sysmon) and PowerShell script-block logs; Linux may record `sudo` use. That is expected and desirable for accountability. |
| **Settings changed** | None. |

## 7. Reading the results

### 7.1 Files

```
<output>/PSA-20261024-091500-AB12CD_<host>/
    report.html          open this first: posture, executive summary, roadmap, findings
    report.pdf           the same report for management and the audit file
    findings.csv         one row per finding, with owner / due date / ticket / state columns
    report.json          complete machine-readable results (the other formats are built from it)
    report.json.sha256   hash of report.json
    SHA256SUMS           hashes of every file above (sha256sum -c compatible)
logs/audit-PSA-20261024-091500-AB12CD.jsonl   hash-chained record of the run
logs/psa-YYYYMMDD.log                         application log
```

A complete sample is in [examples/demo-report/](examples/demo-report/).

### 7.2 A finding

Each finding has:
- an **ID** and **title**;
- a **severity** (Critical, High, Medium, Low or Informational) with its rationale;
- a **status** and **confidence**;
- the affected host and component;
- description, **evidence** (redacted), impact, and **references** (CVE with CVSS,
  CWE, or baseline item);
- **remediation** and **verification** steps, and whether manual validation is
  required.

| Status | Meaning |
|---|---|
| **confirmed** | The setting or condition was observed directly. |
| **potential** | Indirect evidence, for example a version string or install date. Validate manually before acting. |
| **inconclusive** | The tool could not decide. Follow the verification step. |
| **informational** | Inventory or context, not a weakness. |

The **risk score** (0–10) ranks work: severity × status × confidence. The
**priority** places each finding on the roadmap:
- **immediate:** Critical, or confirmed High with high confidence;
- **short-term:** other High findings;
- **planned:** Medium and Low;
- **monitoring:** Informational.

### 7.3 Posture rating

| Rating | Meaning |
|---|---|
| Critical risk | At least one confirmed Critical finding |
| High risk | A potential Critical, or three or more confirmed High findings |
| Elevated risk | At least one High finding |
| Moderate risk | Medium findings only |
| Low risk | No Critical, High or Medium findings |

When fewer than 75% of the applicable checks completed (often because the run
was not elevated), the rating warns that the real posture may be worse.

### 7.4 Limitations

The **Limitations** section lists every check that was skipped, failed or timed
out, with the reason (missing privileges, missing tool, no snapshot, and so on).
Read it before you draw conclusions: a clean report with many limitations is not
a clean bill of health.

## 8. After the engagement

1. **Verify the report** before handing it over: `PSA verify-report <folder>`.
2. **Hand it over** with **Export Report** or `PSA export-report <folder> <share>`.
   Exports are refused if the report fails verification. Record the
   `SHA256SUMS` hash of `report.json` in the ticket.
3. **Copy the audit log** (`logs/audit-<id>.jsonl`) to protected storage. It is
   tamper-*evident*, not tamper-proof.
4. **Apply your retention policy.** Remove reports from the drive once the
   report owner has them. The toolkit never deletes reports itself.
5. **Remediation tracking:** import `findings.csv` into your tracker. Its
   `owner`, `due_date`, `ticket` and `remediation_state` columns are left empty
   for that purpose. Cells that would start a spreadsheet formula are prefixed
   with an apostrophe.
6. **Re-assess** after remediation, with the same steps. A finding's
   `fingerprint` stays stable between runs, so you can match it across reports.

## 9. Looking after the drive

| Task | How |
|---|---|
| Update the program | On the build workstation: `python scripts/prepare_usb.py <drive> --update --windows-build … --linux-build …`. Reports, logs, `config/local.toml`, baselines and vulnerability data are kept. |
| Refresh vulnerability data | Build a snapshot ([VULNDATA.md](VULNDATA.md)), then `prepare_usb.py <drive> --update --vulndata <snapshot>`. |
| Add a baseline | `PSA import-baseline <file>`, then `PSA build-manifest`. |
| Change settings | Create or edit `config/local.toml` (never `default.toml`), then `PSA build-manifest`. |
| Check a drive | `PSA verify`, and compare the manifest SHA-256 with your record. |
| Write-protect | Use a hardware switch or a read-only filesystem, and set `output_dir` so reports go elsewhere. |

Rebuilding the manifest prints a new manifest SHA-256. Record it, because it
replaces the old value.

## 10. Configuration reference

Defaults are in `config/default.toml`. Put overrides in `config/local.toml`, or
pass `--config FILE`. Values outside the safe bounds are clamped, and a warning
is logged.

| Section and key | Default | Meaning (bounds) |
|---|---|---|
| `general.offline_mode` | `true` | Never contact external services. No shipped check needs the internet. |
| `general.output_dir` | `""` | Report folder; empty means `<drive>/reports` |
| `execution.command_timeout_seconds` | `30` | Per external command (1–600) |
| `execution.check_timeout_seconds` | `120` | Per check (5–3600) |
| `execution.max_output_bytes` | `2000000` | Captured output per command; the rest is discarded |
| `network.*` | see file | Scope limits for recorded targets and `preview-scan` (for example `max_hosts_per_target` 256, hard ceiling 1024). No network module uses them in this build. |
| `reporting.formats` | `json, html, pdf, csv` | Report formats; JSON is always written |
| `reporting.include_raw_evidence` | `true` | Include evidence data (always redacted) |
| `vulnerability_data.directory` | `""` | Snapshot folder; empty means `<drive>/vulndata` |
| `vulnerability_data.max_age_days` | `30` | Older snapshots are flagged as a limitation |
| `baselines.directory` | `""` | Baseline folder; empty means `<drive>/baselines` |
| `baselines.enabled` | `[]` | Baseline names to use; empty means every applicable baseline |
| `logging.level` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR` |

## 11. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `The GUI is unavailable` | Tkinter or a display is missing (normal on servers). Use the command line. |
| `Output directory ... is not writable` (exit 1) | The drive is write-protected or full. Use `--output` or **Change output folder…**. |
| `Authorization refused` (exit 3) | The name or reference is missing, or the phrase was not typed exactly as `I AM AUTHORIZED`. |
| `Integrity check FAILED` (exit 4) | Files changed since the drive was prepared. Don't use the drive; rebuild it from a trusted release. |
| `verify` lists *unexpected files* | Something was added to the drive, such as an imported baseline. If you added it, run `build-manifest`. |
| Many checks `skipped: Requires administrator/root` | Run elevated, if the authorization allows it. |
| A check `timed out` | The system is slow or very large. Raise `check_timeout_seconds` in `config/local.toml` and re-run. |
| `Python 3.10+ was not found` (Linux) | Use the Linux build in `linux/`, or a host with system Python 3.10+. |
| `Permission denied` starting the Linux build | The drive is mounted `noexec`. The launcher falls back to the source edition (needs Python 3.10+). |
| Blocked by AV, AppLocker, WDAC or SmartScreen | Ask the endpoint team to allow the signed executable's hash. Don't disable protection. |
| `selftest` shows `[WARN] GUI` | The build has no usable Tkinter. The CLI works; rebuild with a python.org or distribution Python for the GUI. |

## 12. Questions and limitations

**Can it scan the network?** No. This build has no network assessment module.
Remote targets and `preview-scan` only record and validate a scope.

**Does it prove compliance?** No. Baselines compare settings with your own rules.
Use the results as input to an audit, not as certification.

**Can a compromised host fool it?** Yes. A host-based tool trusts the operating
system it runs on. If you suspect a compromise, use your incident-response
process, not this toolkit.

**Are reports confidential?** Yes. They list weaknesses. Secrets are redacted,
but host names, accounts and configuration remain. Protect them accordingly.

Known residual risks are listed in [SECURITY_REVIEW.md](SECURITY_REVIEW.md#3-residual-risks-and-limitations).
