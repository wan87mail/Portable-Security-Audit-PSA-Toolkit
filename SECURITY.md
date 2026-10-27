# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| < 1.0 | No (pre-release phases; update to 1.0) |

## Reporting a vulnerability

Please report security problems in the toolkit **privately**, not in a public
issue. Use GitHub's **Report a vulnerability** button (Security tab →
*Advisories*) on this repository.

Please include:
- the toolkit version (`PortableSecurityAudit --version`) and the edition (Windows `.exe`, Linux build, or source);
- the operating system of the target and of the build machine;
- the steps to reproduce, and what you expected instead;
- whether the issue can change the target, expose secrets in reports or logs, run unintended programs, or affect drive or report integrity.

The maintainers will acknowledge the report and agree a fix timeline with you. Fixes are released as a new
version, recorded in [CHANGELOG.md](CHANGELOG.md) and
[docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md), and come with a regression test.

## What counts as a vulnerability here

The toolkit promises to be **read-only**, to run **only allow-listed programs**,
to keep **secrets out of reports**, and to make **tampering with the drive or a
report detectable**. Anything that breaks one of these promises is in scope, for
example:
- a check, baseline or input that changes the target, or runs a program or argument outside the read-only policy;
- secrets (password hashes, keys, tokens) appearing in reports, evidence or logs;
- a modified drive or report that still passes `verify` or `verify-report`;
- code execution from a crafted baseline, vulnerability snapshot, report folder or configuration file.

**Out of scope:**
- findings *about the systems you assess*: those belong in your own reports;
- the documented residual risks in `docs/SECURITY_REVIEW.md` section 3. Ideas for
  reducing them are still welcome.

## Using the toolkit safely

Use it only on systems you are authorized to assess. Verify the drive before
each engagement, and treat reports as confidential. See the
[IT administrator manual](docs/USER_GUIDE.md).
