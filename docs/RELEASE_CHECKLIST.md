# Release checklist

Use sections 1–3 for every release of the toolkit, and section 4 for every engagement.
Copy the list into the release ticket and tick the items as you go. A release is
ready only when every item is ticked or has a written, approved exception.

## 1. Prepare

- [ ] All changes for the release are merged into `main`, and CI on `main` is green.
- [ ] `src/psatoolkit/__init__.py` has the new version (semantic versioning: a
      breaking change to the report format, CLI or baseline format means a major version).
- [ ] [CHANGELOG.md](../CHANGELOG.md) has an entry for the version: date, added,
      changed, fixed and security items.
- [ ] `python scripts/gen_checks_doc.py` was run; `docs/CHECKS.md` names the new version.
- [ ] The example report in `docs/examples/` is regenerated if the report format
      changed. Run `audit --demo`, copy the report folder and the audit log, and
      check that `verify-report` passes on the copy.
- [ ] The docs describe what the release actually does. At minimum, re-read the
      README status table, [USER_GUIDE.md](USER_GUIDE.md) sections 5–6 (controls,
      commands, footprint) and [CHECKS.md](CHECKS.md).
- [ ] Security review: work through the checklist in
      [SECURITY_REVIEW.md](SECURITY_REVIEW.md#6-checklist-for-future-changes) for
      every change to command execution, file access, baselines, report writers or
      the build. Record new findings and residual risks there.
- [ ] Private vulnerability reporting is enabled for the repository (Settings → Security),
      so the reporting route in [SECURITY.md](../SECURITY.md) works.
- [ ] Dependencies and actions: the lock is current, and actions are pinned to
      SHAs (SECURITY_REVIEW.md section 4). Check PyInstaller and the Python build
      interpreter for security releases.

## 2. Verify

- [ ] `python -m pytest` passes locally on the oldest (3.10) and newest supported Python.
- [ ] The CI run for the release commit is green in **all** jobs: 8 test jobs, `build-windows`,
      `build-linux`, `usb-image`.
- [ ] The CI live-audit artifacts (`live-audit-*`) were opened for one Windows and one Linux
      runner. Checks produced real results, with no unexpected *timed out*, *error* or
      policy-denied entries.
- [ ] [TEST_CHECKLIST.md](TEST_CHECKLIST.md) was completed on hosts CI does not cover:
      at least one **Windows 10 or 11 desktop** (GUI, standard user and administrator),
      and one **Linux desktop** (GUI). Note the OS builds in the ticket.
- [ ] The demo mode, export, `verify-report` and `verify` flows were run from an assembled
      drive, not from the repository.

## 3. Build, sign and publish

- [ ] The builds come from the release commit: either the CI artifacts
      `PortableSecurityAudit-windows`, `-linux` and `-usb`, or local builds with
      `packaging/build_windows.ps1` and `build_linux.sh`, which install from
      `requirements-build.lock` with `--require-hashes`.
- [ ] The Windows executable is **Authenticode-signed** (`build_windows.ps1 -SignThumbprint …`
      or `signtool` on the CI artifact), and `Get-AuthenticodeSignature` reports `Valid`.
- [ ] `PortableSecurityAudit selftest --require-gui` passes on both frozen builds.
- [ ] The release drive image was assembled with `scripts/prepare_usb.py` (plus a
      vulnerability snapshot if one is shipped), and `verify` reports **PASSED**.
- [ ] Recorded in the release notes:
  - [ ] SHA-256 of `PortableSecurityAudit.exe` and of the Linux binary
  - [ ] the **manifest SHA-256** printed by `prepare_usb.py`
  - [ ] the vulnerability snapshot date and its SHA-256, if shipped
  - [ ] Python and PyInstaller versions used for the build
- [ ] The endpoint-security team received the executable hash and signer for allow-listing.
- [ ] Tag the release commit (`git tag -s vX.Y.Z`; push the tag) and publish the release
      notes with the artifacts and their hashes.
- [ ] Previous drives are scheduled for update (`prepare_usb.py --update`), and their
      custodians have the new manifest SHA-256.

### Release notes template

```
Portable Security Audit vX.Y.Z (YYYY-MM-DD)

Highlights: …
Security fixes: … (see docs/SECURITY_REVIEW.md)
Upgrade notes: … (config, baseline or report-format changes)

Artifacts                         SHA-256
PortableSecurityAudit.exe         …
linux/PortableSecurityAudit       …
Drive manifest (checksums/manifest.json)  …
Vulnerability snapshot (date)     …

Built with Python … / PyInstaller … from commit …
Tested: CI run …; manual checklist on Windows 11 23H2 (build …), Ubuntu 24.04 desktop.
```

## 4. Per-engagement checklist (operator)

**Before**
- [ ] Written authorization names the host(s), the time window, whether elevated execution
      is allowed, and where results may be stored. Note its reference.
- [ ] `verify` reports PASSED on a trusted machine, and the manifest SHA-256 matches the
      recorded value.
- [ ] Vulnerability snapshot age is within policy; the right baselines are imported.
- [ ] Endpoint-security team informed; output location chosen (encrypted drive or
      protected share).

**During**
- [ ] `info` was checked: the expected checks will run, and the reasons for skipped
      checks are understood.
- [ ] Assessment run with the authorization reference; elevated only if authorized.
- [ ] Any emergency stop is noted in the ticket (the report is marked *stopped*).

**After**
- [ ] `verify-report` passes; the report was handed over with `export-report`, and the
      `report.json` hash is recorded in the ticket.
- [ ] Audit log copied to protected storage.
- [ ] Reports removed from the drive per the retention policy; drive returned to the
      custodian.
- [ ] Remediation tracked (`findings.csv`); re-assessment scheduled.

## 5. If a release must be withdrawn

1. Mark the release as withdrawn in the release notes, and say why: a security
   finding, wrong results, or a broken build.
2. Tell the drive custodians to stop using affected drives. `verify` against the new
   release's manifest identifies them.
3. Fix the problem, add a regression test, record it in `SECURITY_REVIEW.md` if it is a
   security issue, and release a new version through sections 1–3.
4. Re-run assessments whose results may have been affected, and tell the report owners.
