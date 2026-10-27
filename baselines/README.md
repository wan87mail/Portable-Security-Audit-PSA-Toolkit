# Baselines

Imported organisational security baselines (`*.json`) live in this folder and
are evaluated by Module F during each assessment. Import them with
`PortableSecurityAudit import-baseline <file>`, or in the GUI via
**Select Assessment Modules → Import baseline…**. The file is validated before
it is copied here.

`examples/` contains two illustrative baselines (Ubuntu server, Windows
workstation). They are not loaded automatically; review and adapt them first.

Format, collectors and security restrictions are described in
[docs/BASELINES.md](../docs/BASELINES.md). Results are deviations from the
supplied baseline, not a formal compliance certification.
