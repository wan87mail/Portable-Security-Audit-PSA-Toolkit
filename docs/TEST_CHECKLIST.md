# Manual test checklist (real hosts)

Automated tests use mocked system data, plus a live read-only audit of the CI
runners (Windows Server 2022/2025, Ubuntu 22.04/24.04). Before field use, run
this checklist on a **lab** machine of each target type that you own,
especially Windows 10/11 desktops, which CI does not cover. It is part of the
[release checklist](RELEASE_CHECKLIST.md). Record the result,
the tool version and the OS build in your change ticket.

Use a throw-away VM snapshot so you can confirm the "no changes" items by
comparing before and after.

## Demo mode (any computer, no authorization scope needed)

- [ ] `audit --demo` produces findings at every severity (Critical to Informational) and every status
      (confirmed, potential, inconclusive, informational).
- [ ] The report shows one simulated check error and one privilege skip under *Limitations*, and sample
      vulnerability-data and baseline entries under *Data sources*.
- [ ] Every format carries the DEMONSTRATION banner; the audit log contains no `command_start` events.

## Reports

- [ ] `report.html` opens offline in Edge/Chrome/Firefox and prints with all findings expanded.
- [ ] `report.pdf` opens in a PDF reader; page numbers read "Page X of Y".
- [ ] `findings.csv` opens in Excel with correct columns; no cell runs as a formula.
- [ ] `verify-report <folder>` passes, then fails after editing any file in the folder.
- [ ] **Export Report** / `export-report` refuses a modified `report.json`.

## Baselines (Module F)

- [ ] `import-baseline baselines/examples/example-ubuntu-server.json` succeeds; importing it again without `--replace` is refused.
- [ ] A baseline that reads `/etc/shadow` with `file_kv`, or that has a registry path containing a quote, is rejected with a clear message.
- [ ] On an Ubuntu lab host, change `UMASK` in `/etc/login.defs` and confirm the rule result changes accordingly.
- [ ] On Windows as a standard user, `auditpol` rules appear as *could not be evaluated* (privileges), not as passed.
- [ ] The report's *Data sources* show the baseline name, version and SHA-256.

## Vulnerability data (Module E)

- [ ] With no `vulndata/` snapshot, VULN-PKG-001 is skipped with instructions.
- [ ] After building a snapshot (docs/VULNDATA.md), an intentionally outdated lab package is reported with the fixed version.
- [ ] Modifying `vulndata/records.jsonl` makes the check refuse the data (integrity failure).

## All platforms

- [ ] `verify` passes on the prepared drive, and the manifest SHA-256 matches the release notes.
- [ ] `info` shows the correct OS name, build, architecture and elevation state.
- [ ] `audit --demo` runs no commands (confirm in the audit log: no `command_start` events).
- [ ] A real `audit` completes; every *skipped* check gives an understandable reason.
- [ ] Ctrl+C / **STOP** during the Linux file sweeps or Windows service ACL check stops within a few seconds, and the report is marked `stopped`.
- [ ] `verify-report` and `verify-log` pass on the outputs.
- [ ] The report contains no passwords, hashes, tokens or private keys (search it for `$6$`, `$y$`, `BEGIN`, `password=`).
- [ ] Running from a write-protected USB with `--output` to another drive works.

## Windows (10, 11, Server 2019, 2022, 2025)

Run once as a standard user and once as Administrator.

- [ ] No PowerShell window flashes; no UAC prompt appears.
- [ ] WIN-FW-001: disable the Public profile in the lab and confirm a High finding.
- [ ] WIN-AV-001: with Defender running, no finding; with a third-party AV, Defender passive mode is handled.
- [ ] WIN-SMB-001: as admin, the SMBv1 state matches `Get-SmbServerConfiguration`; as a user, a privilege limitation is listed.
- [ ] WIN-RDP-001: enable RDP without NLA in the lab and confirm a Medium finding.
- [ ] WIN-ACCT-001: on an English install, policy values match `net accounts`; on a non-English install, the check is skipped with an explanation.
- [ ] WIN-ACCT-002 / 003: account and Administrators lists match `lusrmgr.msc`; on a domain controller, a clear skip.
- [ ] WIN-PATCH-001: the latest install date matches *Settings > Windows Update > Update history*.
- [ ] WIN-BL-001 (admin): the state matches `manage-bde -status`.
- [ ] WIN-SVC-001: create a lab service with an unquoted path containing spaces and confirm the finding.
- [ ] WIN-PERM-001: grant `Users:(M)` on a lab service binary and confirm a High finding.
- [ ] WIN-TLS-001: set `TLS 1.0\Server\Enabled=1` in the lab and confirm a Medium finding.
- [ ] WIN-AUDIT-001 (admin): the results match `auditpol /get /category:*`.
- [ ] **No changes:** compare `reg export HKLM\SYSTEM`, `Get-Service` and `Get-NetFirewallRule` before and after; they must be identical.

## Linux (Ubuntu 22.04, 24.04; optionally Debian or RHEL family)

Run once as a normal user and once with `sudo`.

- [ ] It runs with the system Python (`bash PortableSecurityAudit.sh`) from a `noexec` USB mount.
- [ ] LNX-PATCH-001: the pending security count matches `apt list --upgradable | grep -c -- -security`.
- [ ] LNX-SSH-001: as root, the values match `sshd -T`; as a user, a limitation mentions `sshd -T`.
- [ ] LNX-FW-001: with `ufw enable`, no finding; with ufw disabled and no nftables rules, a Medium finding.
- [ ] LNX-SUDO-001 / LNX-ACCT-001: skipped without root; with root, they match `/etc/sudoers*` and the accounts.
- [ ] LNX-PERM-001: `touch /usr/local/bin/x && chmod o+w /usr/local/bin/x` in the lab produces a High finding.
- [ ] LNX-SUID-001: `cp /usr/bin/find /tmp/f && chmod u+s /tmp/f` (lab, as root) produces a High finding.
- [ ] LNX-ENC-001: on a LUKS laptop, no finding; on a plain VM, a Low *potential* finding.
- [ ] LNX-MAC-001: on Ubuntu with AppArmor, no finding.
- [ ] **No changes:** compare `sudo find /etc -newer <marker>` before and after; there must be no new or modified files. Also check that `/var/lib/apt/lists` timestamps are unchanged (the tool never runs `apt update`).
