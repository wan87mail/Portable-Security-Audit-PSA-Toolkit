# Operator guide (Phase 2 edition)

This guide covers the features delivered so far. It is expanded into the full
IT administrator manual in Phase 10.

## Before you start

1. **Obtain written authorization** (change ticket, engagement letter) naming
   the hosts and the time window. You will enter its reference in the tool.
2. **Verify the drive** on a trusted machine: `PortableSecurityAudit verify`.
   Compare the printed *Manifest SHA-256* with the value in the release notes.
3. Tell the endpoint-security team. Running tools from USB can trigger
   AV/EDR alerts or be blocked by device-control policy. The toolkit will not
   attempt to bypass any control.

## Running an assessment

The toolkit never starts automatically when the drive is inserted. Launch it yourself:

| Platform | Standard user | Elevated (more checks) |
|---|---|---|
| Windows | Double-click `PortableSecurityAudit.exe` (Phase 8) or `scripts\PortableSecurityAudit.bat` | Right-click > *Run as administrator* |
| Linux | `bash PortableSecurityAudit.sh` | `sudo bash PortableSecurityAudit.sh` |

### GUI

1. Optional: tick **Demo mode** to practise with sample data.
2. **3. Select Assessment Modules**. Modules that do not apply to this OS are
   shown greyed out with the reason.
3. **1. Start Local Security Audit**. Read the notice, enter your name and
   the authorization reference, and tick the confirmation box. *Start* stays
   disabled until all three are done.
4. Watch progress, the severity counters and the status log. Skipped checks
   explain why (for example, missing privileges or a missing tool).
5. **8. STOP ASSESSMENT** terminates running checks immediately; partial
   results are still saved and marked *stopped*.
6. **Open Generated Report** / **6. Export Report** copies the report folder
   to a location you choose. Nothing is ever uploaded.

**2. Configure Authorized Remote Target** records each remote IP, CIDR range
(at most 256 hosts by default) or hostname together with its permission
reference. **Preview** validates the entry without sending any traffic.

### CLI

```bash
PortableSecurityAudit info                     # what will run here, and what will be skipped
PortableSecurityAudit audit                    # interactive authorization prompts
PortableSecurityAudit audit --demo             # sample data, no commands executed
PortableSecurityAudit audit --output D:\reports   # if the USB drive is read-only
PortableSecurityAudit preview-scan --target 10.0.5.0/28 --ports 22,443   # dry run
```

Press **Ctrl+C** for an emergency stop.

## Outputs

```
reports/PSA-20261024-091500-AB12CD_<host>/report.json         findings, evidence, limitations
reports/PSA-20261024-091500-AB12CD_<host>/report.json.sha256  file hash (sha256sum format)
logs/audit-PSA-20261024-091500-AB12CD.jsonl                    hash-chained audit trail
logs/psa-YYYYMMDD.log                                          application log
```

Verify them later with `verify-report <path>` and `verify-log <path>`.

If the drive is read-only, both reports and logs go to the folder you choose.

## Privileges

Checks that need Administrator/root are listed by `info` and in the report's
limitations, together with the reason. Run elevated only when the
authorization covers it. The tool never elevates itself.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `The GUI is unavailable` | Tkinter or a display is missing (normal on servers). Use the CLI. |
| `Output directory ... is not writable` | The USB drive is write-protected or full. Use `--output` or *Change output folder*. |
| `Authorization refused` (exit 3) | Operator name or reference missing, or the confirmation phrase was not typed exactly as `I AM AUTHORIZED`. |
| `Integrity check FAILED` (exit 4) | Files changed since the drive was prepared. Do not use the drive. Rebuild it from a trusted release. |
| `Python 3.10+ was not found` (Linux) | Use the frozen Linux build, or a host with system Python 3.10+. |
| Launcher blocked on Windows | AppLocker/WDAC/SmartScreen. Ask the endpoint team to allow the signed executable's hash. |
