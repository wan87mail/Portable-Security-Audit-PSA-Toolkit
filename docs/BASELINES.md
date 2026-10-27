# Security baselines (Module F)

Module F compares the assessed system with **your organisation's own
baseline**: a JSON file listing the settings you require. Every rule that is
not met becomes a finding with the severity you chose. Rules that cannot be
evaluated (for example, without administrator rights) are listed under
*Limitations* and are never counted as passed.

> Results are **deviations from the supplied baseline**. They are not a formal
> compliance assessment or certification. CIS Benchmark content is licensed by
> CIS and is not shipped; organisations with a licence may transcribe the
> settings they adopt into this format.

## Quick start

```bash
PSA baselines                                                     # list imported baselines
PSA import-baseline baselines/examples/example-ubuntu-server.json # validate + copy into baselines/
PSA build-manifest                                                # cover the new file in the integrity manifest
PSA audit                                                         # Module F runs with the local audit
```

In the GUI: **3. Select Assessment Modules → Import baseline…**.

Two example baselines are in `baselines/examples/` (Ubuntu server, Windows
workstation). They are **examples**: review every rule against your policy
before importing them. Files in `examples/` are never loaded automatically.

## File format

```json
{
  "format": "psa-baseline-1",
  "name": "Contoso Linux Server Standard",
  "version": "3.2",
  "source": "Contoso IT Security Policy ISP-07, approved 2026-05",
  "applies_to": {"os_family": "linux", "distro": ["ubuntu", "debian"]},
  "rules": [
    {"id": "SSH-01", "title": "SSH root login is disabled", "severity": "high",
     "check": {"type": "sshd", "key": "permitrootlogin", "default": "prohibit-password"},
     "expected": {"op": "in", "value": ["no", "prohibit-password"]},
     "rationale": "Why the rule exists (shown as the impact).",
     "remediation": "How to fix it.", "verification": "How to confirm the fix.",
     "reference": "ISP-07 section 4.2"}
  ]
}
```

| Field | Required | Notes |
|---|---|---|
| `id` | yes | `A-Z a-z 0-9 . _ -`, up to 40 characters, unique |
| `title` | yes | What must be true, e.g. "SSH root login is disabled" |
| `severity` | no | `critical`, `high`, `medium` (default), `low`, `informational` |
| `check` | yes | A collector `type` and its parameters (below) |
| `check.default` | no | Value to assume when the setting is not present (e.g. the OS default) |
| `expected` | yes | `op` and `value` |
| `case_sensitive` | no | Text comparisons ignore case unless `true` |

### Collectors

| `type` | OS | Parameters | Value compared |
|---|---|---|---|
| `sshd` | Linux | `key` (lower-case sshd keyword) | Effective value (`sshd -T` as root; otherwise parsed config files) |
| `sysctl` | Linux | `name` (e.g. `net.ipv4.tcp_syncookies`) | Value from `/proc/sys` |
| `file_kv` | Linux | `path`, `key`, `separator` (`=`, `:` or `whitespace`) | Value of the key in the file |
| `file_contains` | Linux | `path`, `text` | `true` or `false` |
| `file_mode` | Linux | `path`, optional `owner_uid` | Permission bits (use op `mode_max`) and owner |
| `package` | Linux, Windows | `name` | Installed version, or absent |
| `service` | Linux | `unit`, `property` (`enabled` / `active`) | `systemctl is-enabled` / `is-active` output |
| `registry` | Windows | `path` (`HKLM:\...`), `name` | Registry value |
| `net_accounts` | Windows | `key`: `min_length`, `history`, `lockout_threshold`, `max_age`, `lockout_duration` | Number ("Never" = 0) |
| `windows_service` | Windows | `name`, `property` (`start_type` / `status`) | e.g. `Automatic`, `Disabled`, `Running` |
| `auditpol` | Windows (admin) | `guid` (subcategory GUID) | 0 none, 1 success, 2 failure, 3 both |

### Operators

`eq`, `ne`, `in`, `not_in`, `ge`, `le`, `gt`, `lt` (numeric), `exists`,
`absent`, `contains`, `not_contains`, `mode_max` (file permissions no wider
than, e.g. `"0640"`). A value that is not set compares as *absent*: `ne`,
`not_in`, `not_contains` and `absent` pass; other operators fail, unless
`check.default` supplies a value.

## Security restrictions

Baseline files are data, not code, so even a malicious baseline cannot harm the target:

- Only the collectors above exist. There is no command, script or regular-expression rule type.
- Every parameter is validated against a strict pattern. Registry paths and
  service names cannot contain quotes, `$`, backticks or `;`. File paths must
  be absolute, without `..`.
- The contents of secret files cannot be read: `/etc/shadow`, `/etc/gshadow`,
  SSH host private keys, `/etc/ssl/private/*`, `*.key`, `/root/*`, `/home/*`
  and `.ssh` directories. Their *permissions* can still be checked with `file_mode`.
- Findings record only the single value compared, never file contents.
- The usual read-only command policy still applies to every query.
- Imported baselines are hashed; the SHA-256 appears in the report, and the
  drive integrity manifest covers them after `build-manifest`.

## Choosing severities

Use the severity of the *risk*, not the effort of the fix: for example,
**Critical** for unauthenticated remote access, **High** for removing a
key security control, **Medium** for weakened controls, and **Low** for
hardening and hygiene. The report states that the baseline author assigned
the severity.
