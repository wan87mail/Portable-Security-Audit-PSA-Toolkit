# Licences

## Portable Security Audit toolkit

The toolkit source code is released under the MIT licence (`pyproject.toml`).
Replace this with your organisation's licence if you distribute it internally
under different terms.

## Runtime dependencies

The Phase 1–2 runtime uses **only the Python standard library**.

| Component | Licence | Shipped on USB? | Notes |
|---|---|---|---|
| CPython 3.10+ | PSF License 2.0 | Embedded in the Phase 8 Windows `.exe`; Linux uses the system interpreter | |
| Tcl/Tk (via `tkinter`) | Tcl/Tk licence (BSD-style) | Embedded in the Windows `.exe` | Optional on Linux (`python3-tk`) |

## Development-only dependencies (not shipped)

| Component | Licence |
|---|---|
| pytest | MIT |
| PyInstaller (Phase 8) | GPL-2.0 with a bootloader exception that permits distributing the built executable under any licence |

## Optional third-party tools (later phases, not bundled by default)

| Tool | Licence | Notes |
|---|---|---|
| Nmap | Nmap Public Source License (NPSL) | Free for internal use; read the NPSL before redistributing it on drives given to third parties. Place it in `tools/<os>/` only after reviewing the licence. |
| OpenSSL | Apache-2.0 (3.x) | Usually present on Linux targets already. |
| Greenbone/OpenVAS | AGPL-3.0 / GPL | Integrated as an external, separately-run server; never shipped on the USB drive. |

## Content

- CIS Benchmarks are licensed by the Center for Internet Security. The toolkit
  references benchmark *titles* only and ships no CIS content. Import your
  licensed baselines into `baselines/`.
- Microsoft Security Baselines are published by Microsoft under its own terms.
- CVE® is a registered trademark of The MITRE Corporation; NVD data is in the
  public domain (U.S. Government work).
