# Security, dependency and usability review (Phase 9)

Review of toolkit version 0.8.0 (merged as PR #3), with the fixes released in 0.9.0.
This is an internal code review by the development team. It is not an independent
penetration test or a formal certification. Re-run it for every release that touches
`core/safe_exec.py`, `core/hostfs.py`, `core/baseline.py`, the report writers or the
build pipeline.

## 1. Scope and method

| Area | Files reviewed |
|---|---|
| Command execution and the read-only policy | `core/safe_exec.py`, every `runner.run(...)` call in `modules/` |
| Target filesystem access | `core/hostfs.py`, Linux checks, baseline collectors |
| Untrusted inputs | baselines (`core/baseline.py`, `import-baseline`), report folders (`verify-report`, `export-report`), configuration, vulnerability snapshots, OSV converter |
| Outputs | JSON/HTML/PDF/CSV writers, `SHA256SUMS`, audit and application logs, folder permissions |
| Launchers and packaging | `scripts/PortableSecurityAudit.{sh,bat}`, `packaging/`, `.github/workflows/build.yml` |
| Usability | CLI help, error messages and behaviour for common operator mistakes |

The method was a manual review of each trust boundary. Every policy rule was tested
against the real argument syntax of the tool it governs. Each fix has a regression test
(about 45 new test cases, 515 in total), was checked with a live read-only audit of an Ubuntu 24.04 host,
and with the Windows Server 2022/2025 CI runners.

### Trust boundaries

1. **The target host is untrusted.** A compromised or hostile target can plant files,
   symlinks, FIFOs and executables, and set environment variables. The tool often runs
   elevated on it.
2. **Imported baselines and handed-over report folders** come from other people. They
   are validated and treated as data only.
3. **The USB drive and the build workstation are trusted**, protected by the integrity
   manifest, code signing and the pinned build chain.

## 2. Findings

Severity is rated as if the affected control were the last line of defence. The
"Reachable" column says whether the 0.8.0 release actually exposed the issue.
"Defence in depth" means that only code inside the toolkit could supply the arguments,
and no shipped check did.

| ID | Severity | Area | Finding | Reachable in 0.8.0 | Fix (0.9.0) |
|---|---|---|---|---|---|
| SR-01 | **High** | Command resolution (Windows) | `shutil.which()` searched the **current directory** first (Python 3.10, and 3.12 unless `NoDefaultCurrentDirectoryInExePath` is set) and accepted `.com`/`.bat`/`.cmd` through `PATHEXT`. A `powershell.exe` or `net.com` planted in the working directory would run, possibly elevated (CWE-427). | **Yes**, when the tool is started from a folder writable by others | Own resolver: `<name>.exe` only, looked up only in the Windows directory reported by `GetSystemWindowsDirectoryW` (and the USB `tools/` folder for openssl). Executable names must match `[a-z0-9._-]`. |
| SR-02 | **High** | Baseline file reads | A `file_kv`/`file_contains` rule could name a device or FIFO. Opening `/dev/watchdog` arms the hardware watchdog (the host **reboots**), and opening a FIFO blocks forever. | **Yes**, through an imported baseline | `HostFS` resolves the path, refuses anything that is not a regular file *before* opening, opens non-blocking with `O_NOFOLLOW`/`O_NOCTTY`, and re-checks the open handle. |
| SR-03 | **High** | Baseline secret protection | `//etc/shadow` or `/etc/./shadow` passed the secret-file patterns, so a rule such as `file_kv key=root` would put the root password **hash** into the report. | **Yes**, through an imported baseline | Paths must be canonical (`posixpath.normpath`, no leading `//`). |
| SR-04 | Medium | Baseline secret protection | A rule on a harmless-looking path that is a symlink to a protected file (e.g. `/tmp/x -> /etc/shadow`, planted on the target) would read that file. | Yes, needs a planted symlink plus a matching rule | The collector resolves the path on the target and refuses to read when the real path is protected (reported as inconclusive). |
| SR-05 | Medium | Command output | Output was collected in full and only then truncated, so a very large output could exhaust memory. | Unlikely (outputs of shipped commands are small) | Reader threads cap output while it is read and discard the excess. |
| SR-06 | Medium | Child process environment (Windows) | Commands inherited the host's full environment, including `PATH`, `PSModulePath` and profiler variables (`COR_*`), which can redirect what PowerShell loads. | Yes | Minimal environment: system `PATH` and `PSModulePath` only, plus the standard Windows variables. |
| SR-07 | Medium | Report confidentiality (POSIX) | Report folders and logs were created with the default umask (often world-readable), for example when `--output` points at a shared or temporary location. | Yes | Report, export and log folders are created `0700`. The Linux launcher sets `umask 077`. FAT/exFAT USB drives have no permissions, so keep the drive physically controlled. |
| SR-08 | Medium | Command policy (defence in depth) | The allow-list had 28 programs, but the checks use 15. Several rules had gaps: `net share NAME=PATH` creates a share with positional arguments only; `hostname NAME` sets the hostname on Linux; `ss -K` kills sockets; `netsh -f FILE` runs a script and `netsh wlan ... key=clear` shows Wi-Fi keys; `nmap -oN FILE` writes files; `cryptsetup luksDump --dump-master-key` exposes keys. | No (defence in depth) | **Least-privilege allow-list**: only the 15 programs the checks run. A test fails if the list grows without review. |
| SR-09 | Medium | Command policy (defence in depth) | Rules for retained programs were deny-lists that missed command-running forms: `ip netns exec`, `ip -batch`, `ip xfrm state deleteall`, `nft -f`, `apt -o APT::...::=cmd`, `rpm --pipe`/`--eval`/`%(...)`, and `openssl x509 -out` / `s_client` (network). | No (defence in depth) | Allow-lists for `ip`, `auditpol`, `net`, `dpkg-query` and `openssl`, plus targeted denials for `nft`, `apt` and `rpm`. |
| SR-10 | Low | Command policy | `dnf check-update` without `--cacheonly` would refresh repository metadata over the network and write the cache. | No (checks pass `--cacheonly`) | `--cacheonly`/`-C` is now required by the policy. |
| SR-11 | Low | Baseline import | The file was validated and then copied again (TOCTOU), and the whole file was read before the size check. | Yes, low impact | Read once, bounded and regular files only; the validated bytes are written atomically. |
| SR-12 | Low | Report verification | `verify-report`, `export-report` and `SHA256SUMS` read report folders from other people without size or file-type limits. | Yes, low impact | Bounded reads (`read_limited`); FIFOs and devices are refused. |
| SR-13 | Low | Launchers | The Windows source launcher ran `py` through a `PATH`/current-directory lookup. The Linux launcher used the caller's `PATH` for `findmnt`. | Yes, source edition only | Absolute `py.exe` path; the Linux launcher pins `PATH`. |
| SR-14 | Low | Supply chain | CI actions were referenced by movable tags, and build dependencies were pinned by version but not by hash; `pip install --upgrade pip` fetched an unpinned pip. | Yes (build pipeline) | Actions pinned to commit SHAs; `requirements-build.lock` with hashes for every package, installed with `--require-hashes --only-binary=:all:`. |

The 0.8.0 phases (CI on Windows) also found and fixed: report checksum files written with
CRLF on Windows (so `sha256sum -c` failed), and Python 3.10's `platform.win32_ver()`
starting `cmd /c ver` outside the command policy.

### Areas reviewed with no finding

- **Shell use**: no `shell=True`, `os.system` or string commands anywhere. `CommandRunner.run`
  rejects strings, and PowerShell scripts are constants that may not contain double quotes.
- **Baseline injection**: every parameter is validated by a strict regular expression
  before it reaches PowerShell or `systemctl`, including the registry path, service names
  and unit names (a leading `-` is impossible).
- **HTML report**: every value is escaped, there is no JavaScript, the CSP is
  `default-src 'none'`, and only `https://` references become links.
- **CSV report**: formula-injection prefixes (`= + - @ TAB CR`) are neutralised.
- **PDF writer**: strings are escaped (`\ ( )`), and nothing from the report becomes a PDF
  action or link.
- **OSV converter**: zip members are read in memory with declared-size limits, never
  extracted to disk, and `zipfile` stops at the declared size.
- **Secrets**: evidence, logs and command output pass through redaction. Baseline
  evidence holds only the compared value.

## 3. Residual risks and limitations

| Risk | Mitigation and guidance |
|---|---|
| On Windows, stopping a command kills the PowerShell process but not any children it started. The shipped scripts start none. | Keep checks to single cmdlets. A future version could use a Job Object. |
| Symlink checks are path-based and can race with an attacker who changes links during the read. | Values only, never whole files, reach the report. Secret files are refused both by path and by resolved path. |
| A hostile target can lie: rootkits, fake binaries in system directories, falsified `/proc`. | No host-based tool can rule this out. The report says "verify manually" where it matters. Use an offline or forensic process for suspected compromise. |
| FAT/exFAT USB drives cannot protect report confidentiality, and anyone with the drive can read the reports. | Use an encrypted drive (BitLocker To Go or LUKS), or write reports to `--output` on protected storage. Hand reports over with `export-report`. |
| The audit log is tamper-*evident*, not tamper-proof. | Copy logs to protected storage after each engagement, and record the manifest and report hashes in the ticket. |
| The PowerShell policy is pattern-based. | It is a second layer; the scripts themselves are constants reviewed in code. |

## 4. Dependency review

| Component | Version | Where | Assessment |
|---|---|---|---|
| Python standard library | 3.10–3.13 | runtime | No third-party runtime packages, so there is no runtime supply chain. Keep the build interpreter patched (python.org or the distribution). |
| Tcl/Tk | 8.6 | GUI (bundled by PyInstaller) | Use the python.org or distribution build; Tk 9 standalone builds are unsupported. |
| PyInstaller (+ altgraph, hooks-contrib, packaging, setuptools; Windows: pefile, pywin32-ctypes) | 6.19.0 | build only | Hash-locked in `requirements-build.lock`. GPL-2.0 with a bootloader exception (see `LICENSES.md`). |
| pytest (+ pluggy, iniconfig, pygments) | 9.x | tests only | Never shipped. |
| GitHub Actions: checkout, setup-python, upload/download-artifact | v4.4.0 / v5.6.0 / v4.6.2 / v4.3.0 | CI | Pinned to commit SHAs. The workflow has `permissions: contents: read`. |
| openssl, system tools | host versions | target | Not shipped by default. Anything placed in `tools/` is covered by the integrity manifest. |

**Updating the lock:** change `requirements-build.txt`, then run
`uv pip compile requirements-build.txt --universal --generate-hashes --python-version 3.10 --no-header -o requirements-build.lock`.
Review the diff and let CI build both editions. To update actions, resolve the new
release tag to its commit SHA (`git ls-remote --tags https://github.com/actions/<name>`)
and keep the `# vX.Y.Z` comment.

## 5. Usability review

| ID | Issue | Change |
|---|---|---|
| UX-01 | `--target` and `preview-scan` were offered although this build has no network module, so an operator could believe remote hosts were assessed. | Help text says so; adding a target and `preview-scan` print "remote targets are recorded … but are not contacted". |
| UX-02 | In demo mode, `--target` was silently ignored. | A notice is printed. |
| UX-03 | `--operator`, `--organization`, `preview-scan` options and several positional arguments had no help text. | Help text added. |
| UX-04 | A baseline path written as `//etc/x` or `/etc/./x` produced a generic error. | The error shows the canonical form to use. |

Behaviour confirmed as already good: non-interactive runs refuse without
`--confirm "I AM AUTHORIZED"`; an unknown module lists the available ones; an invalid
baseline names the file and the reason; a failed integrity check returns a distinct exit
code (`EXIT_INTEGRITY`).

## 6. Checklist for future changes

- [ ] A new external program needs a policy rule, an entry in
      `test_policy_only_lists_programs_the_checks_use`, and allowed and denied test cases.
- [ ] New file reads on the target go through `HostFS` (regular files only).
- [ ] New baseline collectors validate every parameter with a strict regular expression,
      and content-reading collectors honour `SECRET_PATTERNS`.
- [ ] New inputs from other people are read with `read_limited`.
- [ ] Dependency or action updates go through the lock and SHA pins in section 4.
