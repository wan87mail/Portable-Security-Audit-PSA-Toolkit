# Check catalogue

Generated from the code by `scripts/gen_checks_doc.py` (toolkit 1.0.0). Do not edit by hand.

All checks are read-only. **Admin** means the check is skipped without Administrator/root and the reason is listed in the report's limitations. Checks marked *partial* run without elevation but record reduced coverage.

## A. System information and asset discovery

Asset identification, network, listening ports, exposed services and software inventory.

| ID | Check | OS | Admin | Needs | What it verifies |
|---|---|---|---|---|---|
| SYS-ASSET-001 | Asset identification | linux, windows | No | - | Records host name, OS, build, architecture, uptime and privilege context. |
| SYS-ASSET-002 | Platform support and end-of-life | linux, windows | No | - | Flags operating systems outside the supported/tested list. |
| SYS-NET-001 | Network interfaces and active connections | linux, windows | No | - | Lists interfaces, addresses and a summary of established connections. |
| SYS-PORTS-001 | Listening ports and services | linux, windows | No | - | Inventory of TCP/UDP ports listening on this host, with owning process where visible. |
| SYS-PORTS-002 | Risky services exposed to the network | linux, windows | No | - | Flags well-known risky or sensitive services that listen beyond loopback. |
| SYS-SW-001 | Installed software inventory | linux, windows | No | - | Lists installed packages/programs (name and version) for patch and licence review. |

## B. Windows security audit

Firewall, antivirus, SMB, RDP, UAC, accounts, patching, BitLocker, services, permissions, credential protection, TLS and audit policy.

| ID | Check | OS | Admin | Needs | What it verifies |
|---|---|---|---|---|---|
| WIN-FW-001 | Windows Defender Firewall profiles | windows | No | - | Verifies every firewall profile is enabled and blocks unsolicited inbound traffic. |
| WIN-AV-001 | Antivirus / Microsoft Defender status | windows | No | - | Checks that real-time antivirus protection is active and signatures are current. |
| WIN-SMB-001 | SMB protocol security (SMBv1, signing) | windows | No | - | Checks for SMBv1 and whether SMB signing is required. |
| WIN-RDP-001 | Remote Desktop exposure and security | windows | No | - | Checks whether RDP is enabled and whether NLA and TLS are enforced. |
| WIN-UAC-001 | User Account Control (UAC) configuration | windows | No | - | Checks UAC is enabled with secure prompting and remote token filtering. |
| WIN-ACCT-001 | Password and account lockout policy | windows | No | `net` | Compares the effective local password and lockout policy with the Microsoft baseline. |
| WIN-ACCT-002 | Guest and local user accounts | windows | No | - | Reviews local accounts for an enabled Guest, accounts without passwords and stale accounts. |
| WIN-ACCT-003 | Local Administrators group membership | windows | No | - | Lists members of the local Administrators group and flags excessive membership. |
| WIN-PATCH-001 | Security update recency | windows | No | - | Checks when updates were last installed, the Windows Update service and pending reboots. |
| WIN-BL-001 | BitLocker drive encryption | windows | **Yes**: BitLocker volume status (Get-BitLockerVolume) is only readable by administrators. | - | Checks that the operating system volume (and fixed data volumes) are encrypted. |
| WIN-SVC-001 | Risky services and unquoted service paths | windows | No | - | Flags risky running services and services with unquoted executable paths (CWE-428). |
| WIN-PERM-001 | Service executable permissions | windows | No | - | Checks whether non-administrators can modify executables run by services. |
| WIN-LSA-001 | Credential protection settings (LSA, NTLM, WDigest, LLMNR) | windows | No | - | Checks settings that protect credentials in memory and on the network. |
| WIN-TLS-001 | Legacy SSL/TLS protocols (SCHANNEL) | windows | No | - | Flags SSL 2.0/3.0 and TLS 1.0/1.1 explicitly enabled for server use. |
| WIN-TLS-002 | Machine certificate validity | windows | No | - | Checks certificates with private keys in LocalMachine\My for expiry and weak algorithms. |
| WIN-AUDIT-001 | Security audit policy | windows | **Yes**: auditpol /get requires an elevated session. | `auditpol` | Checks that key security events (logons, account changes, process creation) are audited. |

## C. Linux security audit

Patches, SSH, firewall, accounts, sudo, permissions, SUID, services, encryption, AppArmor/SELinux, kernel parameters and certificates.

| ID | Check | OS | Admin | Needs | What it verifies |
|---|---|---|---|---|---|
| LNX-PATCH-001 | Pending security updates | linux | No | - | Uses the local package manager cache to list pending (security) updates. |
| LNX-SSH-001 | SSH server configuration | linux | No | - | Checks root login, password and empty-password authentication, forwarding and algorithms. |
| LNX-FW-001 | Host firewall status | linux | No | - | Determines whether ufw, firewalld, nftables or iptables filter inbound traffic. |
| LNX-PRIV-001 | Privileged accounts and groups | linux | No | - | Finds UID 0 accounts besides root and lists members of privileged groups. |
| LNX-SUDO-001 | Sudo rules | linux | **Yes**: /etc/sudoers and /etc/sudoers.d are readable only by root (mode 0440). | - | Reviews sudoers for rules granting all users sudo, password-less full root, or no authentication. |
| LNX-ACCT-001 | Accounts with empty or weakly hashed passwords | linux | **Yes**: /etc/shadow is readable only by root. | - | Derives flags from /etc/shadow; password hashes are never stored or reported. |
| LNX-ACCT-002 | Password quality and lockout policy | linux | No | - | Checks PAM password quality, login failure lockout and the password hashing method. |
| LNX-PERM-001 | World-writable files and directories in system locations | linux | No | - | Searches system directories for files/directories any user can modify. |
| LNX-PERM-002 | Permissions on sensitive configuration files | linux | No | - | Verifies ownership and permissions of account, sudo, SSH, cron and boot files. |
| LNX-SUID-001 | SUID/SGID binaries | linux | No | - | Lists set-user-ID/set-group-ID programs and flags dangerous or unexpected ones. |
| LNX-SVC-001 | Unnecessary or insecure services | linux | No | `systemctl` | Lists running systemd services and sockets and flags legacy or risky ones. |
| LNX-ENC-001 | Disk encryption of the root filesystem | linux | No | `lsblk` | Determines whether the root filesystem sits on a LUKS/dm-crypt device. |
| LNX-MAC-001 | AppArmor / SELinux status | linux | No | - | Checks that a mandatory access control system is enabled and enforcing. |
| LNX-KERN-001 | Kernel security parameters (sysctl) | linux | No | - | Compares selected kernel parameters with hardening recommendations. |
| LNX-TLS-001 | Service TLS certificates | linux | No | `openssl` | Checks certificates used by common services (web, mail, proxy) for expiry and weak algorithms. |

## E. Vulnerability assessment (offline data)

Matches installed software against an offline, integrity-checked vulnerability snapshot.

| ID | Check | OS | Admin | Needs | What it verifies |
|---|---|---|---|---|---|
| VULN-PKG-001 | Known vulnerabilities in installed software (offline data) | linux, windows | No | - | Compares installed package versions with the offline vulnerability snapshot (vendor fixed versions); no network access and no exploitation. |

## F. Security baselines (organisation-supplied)

Compares the system with imported baseline files and lists deviations.

| ID | Check | OS | Admin | Needs | What it verifies |
|---|---|---|---|---|---|
| BASE-001 | Organisational security baselines | linux, windows | No | - | Compares the configuration with imported baseline files (baselines/*.json); reports deviations, not formal compliance. |

## Checks that use elevation when available (partial without it)

| ID | Without elevation | With elevation |
|---|---|---|
| SYS-PORTS-001 | Ports listed; process names only for your own sockets | Process names for all sockets |
| WIN-SMB-001 | Registry values (SMBv1 may be *inconclusive*) | `Get-SmbServerConfiguration` |
| LNX-SSH-001 | Parses sshd_config files (root-only includes are skipped) | `sshd -T` effective config |
| LNX-FW-001 | Service state and ufw.conf (*potential*) | Full ufw/nftables/iptables rule sets |
| LNX-PERM-001, LNX-SUID-001 | Directories readable by the user | Complete sweep |
| LNX-MAC-001 | AppArmor enabled flag | Profile enforce/complain counts |
| LNX-TLS-001 | Readable certificate directories | Includes /etc/letsencrypt |
