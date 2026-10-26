"""Module B tests with mocked PowerShell / command output (no Windows needed)."""

from datetime import date

import pytest

from fakes import WINDOWS_OS, FakeRunner, by_severity, make_ctx, titles
from psatoolkit.core.engine import SkipCheck
from psatoolkit.core.models import FindingStatus, Severity
from psatoolkit.modules import windows_audit as w
from psatoolkit.modules._common import ps_command, ps_registry_script


def ctx_with(*rules, elevated=True, is_server=False):
    runner = FakeRunner()
    for prefix, kwargs in rules:
        runner.on(*prefix, **kwargs)
    return make_ctx(WINDOWS_OS, runner, elevated=elevated, is_server=is_server), runner


def ps(contains, data):
    return (("powershell",), {"contains": contains, "json_": data})


# -- every PowerShell script passes the read-only policy ---------------------------------

ALL_SCRIPTS = [
    w.FirewallProfilesCheck.PS, w.DefenderCheck.PS, w.SmbCheck.PS, w.LocalAccountsCheck.PS, w.LocalAdminsCheck.PS,
    w.PatchStatusCheck.PS, w.BitLockerCheck.PS, w.ServicesCheck.PS, w.ServiceBinaryPermissionsCheck.PS,
    w.MachineCertificatesCheck.PS, ps_registry_script(w.RdpCheck.SPEC), ps_registry_script(w.UacCheck.SPEC),
    ps_registry_script(w.CredentialProtectionCheck.SPEC),
]


@pytest.mark.parametrize("script", ALL_SCRIPTS)
def test_powershell_scripts_pass_read_only_policy(script):
    argv = ps_command(script)
    FakeRunner().policy.check(argv[0], argv[1:])
    assert '"' not in script


def test_ps_command_rejects_double_quotes():
    with pytest.raises(ValueError):
        ps_command('Get-Date -Format "x"')


def test_powershell_failure_becomes_skip():
    ctx, _ = ctx_with((("powershell",), {"returncode": 1, "stderr": "Get-NetFirewallProfile : Access denied"}))
    with pytest.raises(SkipCheck, match="Access denied"):
        w.FirewallProfilesCheck().run(ctx)


def test_powershell_missing_becomes_skip():
    ctx, _ = ctx_with()
    with pytest.raises(SkipCheck):
        w.UacCheck().run(ctx)


# -- firewall ----------------------------------------------------------------------------

def test_firewall_disabled_and_default_allow():
    ctx, _ = ctx_with(ps("Get-NetFirewallProfile", [
        {"Name": "Domain", "Enabled": "True", "DefaultInboundAction": "NotConfigured"},
        {"Name": "Private", "Enabled": "False", "DefaultInboundAction": "Block"},
        {"Name": "Public", "Enabled": "True", "DefaultInboundAction": "Allow"}]))
    sev = by_severity(w.FirewallProfilesCheck().run(ctx))
    assert "Private" in sev["high"][0] and "Public" in sev["medium"][0]


def test_firewall_ok():
    ctx, _ = ctx_with(ps("Get-NetFirewallProfile", [{"Name": n, "Enabled": "True", "DefaultInboundAction": "Block"}
                                                    for n in ("Domain", "Private", "Public")]))
    assert w.FirewallProfilesCheck().run(ctx) == []
    assert "3 firewall profiles" in ctx.notes[0]


# -- antivirus ---------------------------------------------------------------------------

def defender(**over):
    base = {"AMServiceEnabled": True, "AntivirusEnabled": True, "RealTimeProtectionEnabled": True,
            "AntivirusSignatureAge": 1, "IsTamperProtected": True, "AMRunningMode": "Normal"}
    return {**base, **over}


def test_defender_healthy():
    ctx, _ = ctx_with(ps("Get-MpComputerStatus", {"Defender": defender(), "Products": []}))
    assert w.DefenderCheck().run(ctx) == []


def test_defender_realtime_off_old_signatures_no_tamper():
    ctx, _ = ctx_with(ps("Get-MpComputerStatus", {"Defender": defender(RealTimeProtectionEnabled=False,
                                                                       AntivirusSignatureAge=30,
                                                                       IsTamperProtected=False), "Products": []}))
    sev = by_severity(w.DefenderCheck().run(ctx))
    assert len(sev["high"]) == 1 and "30 days" in sev["medium"][0] and len(sev["low"]) == 1


def test_defender_passive_with_active_third_party_is_fine():
    ctx, _ = ctx_with(ps("Get-MpComputerStatus", {
        "Defender": defender(AMRunningMode="Passive Mode", RealTimeProtectionEnabled=False),
        "Products": [{"displayName": "Contoso EDR", "productState": 0x061000}]}))
    assert w.DefenderCheck().run(ctx) == []


def test_third_party_disabled_and_unknown_status():
    ctx, _ = ctx_with(ps("Get-MpComputerStatus", {"Defender": None,
                                                  "Products": [{"displayName": "Contoso AV", "productState": 0x060100}]}))
    f = w.DefenderCheck().run(ctx)
    assert f[0].severity == Severity.HIGH and f[0].status == FindingStatus.POTENTIAL
    ctx, _ = ctx_with(ps("Get-MpComputerStatus", {"Defender": None, "Products": []}))
    f = w.DefenderCheck().run(ctx)
    assert f[0].status == FindingStatus.INCONCLUSIVE


def test_security_center_state_decoding():
    assert w.decode_security_center_state(397568) == {"enabled": True, "up_to_date": True}   # 0x061100
    assert w.decode_security_center_state(393472) == {"enabled": False, "up_to_date": True}  # 0x060100
    assert w.decode_security_center_state(397584)["up_to_date"] is False                    # 0x061110


# -- SMB / RDP / UAC ---------------------------------------------------------------------

def test_smb1_enabled_and_signing_not_required_on_server():
    ctx, _ = ctx_with(ps("LanmanServer", {"Server": {"EnableSMB1Protocol": True, "RequireSecuritySignature": False},
                                          "Smb1ClientPresent": True, "Smb1ClientStart": 2}), is_server=True)
    sev = by_severity(w.SmbCheck().run(ctx))
    assert "SMBv1 server" in sev["high"][0]
    assert "signing" in sev["medium"][0]
    assert "client driver" in sev["low"][0]


def test_smb_unknown_without_admin_uses_registry():
    ctx, _ = ctx_with(ps("LanmanServer", {"Server": None, "RegSMB1": None, "RegRequireSigning": 1}), elevated=False)
    f = w.SmbCheck().run(ctx)
    assert [x.status for x in f] == [FindingStatus.INCONCLUSIVE]
    assert ctx.partial and ctx.partial[0].category == "privilege"


def test_smb_hardened():
    ctx, _ = ctx_with(ps("LanmanServer", {"RegSMB1": 0, "RegRequireSigning": 1, "Server": None,
                                          "Smb1ClientPresent": False}))
    assert w.SmbCheck().run(ctx) == []


def test_rdp_disabled_and_policy_override():
    ctx, _ = ctx_with(ps("Terminal Server", {"ts.fDenyTSConnections": 1}))
    assert w.RdpCheck().run(ctx) == []
    ctx, _ = ctx_with(ps("Terminal Server", {"ts.fDenyTSConnections": 1, "pol.fDenyTSConnections": 0,
                                             "tcp.UserAuthentication": 0, "tcp.SecurityLayer": 0,
                                             "tcp.MinEncryptionLevel": 2}))
    t = titles(w.RdpCheck().run(ctx))
    assert any("enabled" in x for x in t) and any("NLA" in x for x in t) and any("TLS" in x for x in t)
    assert any("encryption level" in x for x in t)


def test_rdp_policy_nla_overrides_local_setting():
    ctx, _ = ctx_with(ps("Terminal Server", {"ts.fDenyTSConnections": 0, "tcp.UserAuthentication": 0,
                                             "pol.UserAuthentication": 1, "tcp.SecurityLayer": 2}))
    assert [f.severity for f in w.RdpCheck().run(ctx)] == [Severity.INFO]


def test_uac_weaknesses():
    ctx, _ = ctx_with(ps("Policies\\System", {"sys.EnableLUA": 0, "sys.ConsentPromptBehaviorAdmin": 0,
                                              "sys.PromptOnSecureDesktop": 0, "sys.LocalAccountTokenFilterPolicy": 1}))
    sev = by_severity(w.UacCheck().run(ctx))
    assert len(sev["high"]) == 1 and len(sev["medium"]) == 2 and len(sev["low"]) == 1


def test_uac_defaults_are_fine():
    ctx, _ = ctx_with(ps("Policies\\System", {"sys.EnableLUA": 1}))
    assert w.UacCheck().run(ctx) == []


# -- accounts ----------------------------------------------------------------------------

NET_ACCOUNTS = """Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              6
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        WORKSTATION
The command completed successfully.
"""


def test_password_policy_weak():
    ctx, _ = ctx_with((("net", "accounts"), {"stdout": NET_ACCOUNTS}))
    sev = by_severity(w.PasswordPolicyCheck().run(ctx))
    assert "length is 6" in sev["medium"][0] and "lockout" in sev["medium"][1].lower()
    assert "history" in sev["low"][0]


def test_password_policy_strong_and_non_english():
    strong = NET_ACCOUNTS.replace("length:                              6", "length:                              14") \
        .replace("maintained:                None", "maintained:                24") \
        .replace("threshold:                                    Never", "threshold:                                    5")
    ctx, _ = ctx_with((("net", "accounts"), {"stdout": strong}))
    assert w.PasswordPolicyCheck().run(ctx) == []
    ctx, _ = ctx_with((("net", "accounts"), {"stdout": "Minimale Kennwortlänge:   6\n"}))
    with pytest.raises(SkipCheck, match="not in English"):
        w.PasswordPolicyCheck().run(ctx)


def test_local_accounts():
    users = [
        {"Name": "Administrator", "Enabled": True, "SID": "S-1-5-21-1-2-3-500", "PasswordRequired": True,
         "LastLogonDays": 1},
        {"Name": "Guest", "Enabled": True, "SID": "S-1-5-21-1-2-3-501", "PasswordRequired": False},
        {"Name": "kiosk", "Enabled": True, "SID": "S-1-5-21-1-2-3-1001", "PasswordRequired": False, "LastLogonDays": 3},
        {"Name": "olduser", "Enabled": True, "SID": "S-1-5-21-1-2-3-1002", "PasswordRequired": True,
         "LastLogonDays": 400},
        {"Name": "disabled", "Enabled": False, "SID": "S-1-5-21-1-2-3-1003", "PasswordRequired": False},
    ]
    ctx, _ = ctx_with(ps("Get-LocalUser", users))
    t = titles(w.LocalAccountsCheck().run(ctx))
    assert "The Guest account is enabled" in t
    assert any("no password requirement" in x for x in t)
    assert any("built-in Administrator" in x for x in t)
    assert any("unused for over 90 days" in x for x in t)


def test_local_admins_excessive():
    members = [{"Name": "PC\\Administrator", "SID": "S-1-5-21-1-500"}, {"Name": "CORP\\Domain Admins",
                                                                          "SID": "S-1-5-21-9-512"}] + \
              [{"Name": f"PC\\user{i}", "SID": f"S-1-5-21-1-{1000 + i}"} for i in range(3)]
    ctx, _ = ctx_with(ps("Get-LocalGroupMember", members))
    f = w.LocalAdminsCheck().run(ctx)
    assert f[0].severity == Severity.INFO and f[1].severity == Severity.MEDIUM
    ctx, _ = ctx_with(ps("Get-LocalGroupMember", members[:3]))
    assert len(w.LocalAdminsCheck().run(ctx)) == 1


# -- patching ----------------------------------------------------------------------------

def patch_data(installed_on, **over):
    return {"HotFixes": [{"HotFixID": "KB5031356", "InstalledOn": installed_on}], "Build": "22631", "UBR": 2428,
            "WuStart": "Manual", "RebootRequired": False, **over}


@pytest.mark.parametrize("installed,expected", [("2026-10-10", None), ("2026-09-01", Severity.MEDIUM),
                                                ("2026-05-01", Severity.HIGH)])
def test_patch_recency(installed, expected):
    ctx, _ = ctx_with(ps("Get-HotFix", patch_data(installed)))
    f = w.PatchStatusCheck(today=date(2026, 10, 24)).run(ctx)
    assert [x.severity for x in f] == ([expected] if expected else [])
    assert ctx.partial  # offline limitation always recorded


def test_patch_service_disabled_reboot_and_no_dates():
    ctx, _ = ctx_with(ps("Get-HotFix", patch_data(None, WuStart="Disabled", RebootRequired=True)))
    t = titles(w.PatchStatusCheck(today=date(2026, 10, 24)).run(ctx))
    assert "Update installation dates are unavailable" in t
    assert "Windows Update service is disabled" in t
    assert any("reboot" in x.lower() for x in t)


# -- BitLocker ---------------------------------------------------------------------------

def test_bitlocker_requires_admin_flag():
    assert w.BitLockerCheck.requires_admin and w.BitLockerCheck.admin_reason


@pytest.mark.parametrize("server,expected", [(False, Severity.HIGH), (True, Severity.MEDIUM)])
def test_bitlocker_os_volume_off(server, expected):
    ctx, _ = ctx_with(ps("Get-BitLockerVolume", [
        {"MountPoint": "C:", "VolumeType": "OperatingSystem", "VolumeStatus": "FullyDecrypted",
         "ProtectionStatus": "Off", "EncryptionPercentage": 0},
        {"MountPoint": "D:", "VolumeType": "Data", "VolumeStatus": "FullyEncrypted", "ProtectionStatus": "On",
         "EncryptionMethod": "Aes128"}]), is_server=server)
    f = w.BitLockerCheck().run(ctx)
    assert f[0].severity == expected and f[1].severity == Severity.LOW


def test_bitlocker_unavailable():
    ctx, _ = ctx_with(ps("Get-BitLockerVolume", {"Available": False}), is_server=True)
    assert w.BitLockerCheck().run(ctx)[0].status == FindingStatus.POTENTIAL


# -- services and permissions --------------------------------------------------------------

@pytest.mark.parametrize("path,expected", [
    (r"C:\Program Files\Vendor App\svc.exe -k run", r"C:\Program Files\Vendor App\svc.exe"),
    (r'"C:\Program Files\Vendor\svc.exe"', None),
    (r"C:\Tools\svc.exe", None),
    (r"C:\Windows\system32\svchost.exe -k netsvcs", None),
    ("", None),
])
def test_unquoted_service_path(path, expected):
    assert w.unquoted_service_path(path) == expected


def test_services_check():
    services = [
        {"Name": "TlntSvr", "DisplayName": "Telnet", "State": "Running", "StartMode": "Auto",
         "PathName": r"C:\Windows\System32\tlntsvr.exe"},
        {"Name": "Spooler", "State": "Running", "StartMode": "Auto", "PathName": r"C:\Windows\System32\spoolsv.exe"},
        {"Name": "VendorSvc", "State": "Running", "StartMode": "Auto",
         "PathName": r"C:\Program Files\Vendor Tool\agent.exe", "StartName": "LocalSystem"},
        {"Name": "RemoteRegistry", "State": "Stopped", "StartMode": "Disabled", "PathName": "x"},
    ]
    ctx, _ = ctx_with(ps("Win32_Service", services), is_server=True)
    t = titles(w.ServicesCheck().run(ctx))
    assert any("Telnet" in x for x in t) and any("Spooler" in x for x in t)
    assert "Unquoted service path: VendorSvc" in t
    assert not any("RemoteRegistry" in x for x in t)
    ctx, _ = ctx_with(ps("Win32_Service", services), is_server=False)
    assert not any("Spooler" in x for x in titles(w.ServicesCheck().run(ctx)))


def test_service_binary_permissions():
    rows = [{"Service": "VendorSvc", "Path": r"C:\Vendor\agent.exe", "Identity": "BUILTIN\\Users",
             "Sid": "S-1-5-32-545", "Rights": "Modify, Synchronize"},
            {"Service": "VendorSvc2", "Path": r"C:\Vendor\agent.exe", "Identity": "Everyone", "Sid": "S-1-1-0",
             "Rights": "FullControl"}]
    ctx, _ = ctx_with(ps("Get-Acl", rows))
    f = w.ServiceBinaryPermissionsCheck().run(ctx)
    assert len(f) == 1 and f[0].severity == Severity.HIGH and "VendorSvc2" in f[0].affected_component


# -- credential protection, TLS, certificates, audit ----------------------------------------

def test_credential_protection_weak():
    ctx, _ = ctx_with(ps("WDigest", {"wd.UseLogonCredential": 1, "lsa.LmCompatibilityLevel": 1, "lsa.NoLMHash": 0,
                                     "lsa.RunAsPPL": None, "lsa.RestrictAnonymousSAM": 0, "dns.EnableMulticast": None}))
    sev = by_severity(w.CredentialProtectionCheck().run(ctx))
    assert len(sev["high"]) == 2 and len(sev["medium"]) == 2 and len(sev["low"]) == 2


def test_credential_protection_hardened():
    ctx, _ = ctx_with(ps("WDigest", {"wd.UseLogonCredential": 0, "lsa.LmCompatibilityLevel": 5, "lsa.NoLMHash": 1,
                                     "lsa.RunAsPPL": 1, "lsa.RestrictAnonymousSAM": 1, "dns.EnableMulticast": 0}))
    assert w.CredentialProtectionCheck().run(ctx) == []


def test_schannel():
    ctx, _ = ctx_with(ps("SCHANNEL", {"SSL_3.0.Enabled": 1, "TLS_1.0.Enabled": 4294967295, "TLS_1.1.Enabled": 0}))
    sev = by_severity(w.SchannelProtocolsCheck().run(ctx))
    assert "SSL 3.0" in sev["high"][0] and "TLS 1.0" in sev["medium"][0] and len(sev["medium"]) == 1


def test_machine_certificates():
    rows = [{"Subject": "CN=web01", "NotAfter": "2026-10-01", "SigAlg": "sha256RSA", "KeyBits": 2048,
             "KeyAlg": "RSA", "Thumbprint": "AA"},
            {"Subject": "CN=old", "NotAfter": "2027-01-01", "SigAlg": "sha1RSA", "KeyBits": 1024, "KeyAlg": "RSA",
             "Thumbprint": "BB"},
            {"Subject": "CN=soon", "NotAfter": "2026-11-10", "SigAlg": "sha256ECDSA", "KeyBits": None,
             "KeyAlg": "ECC", "Thumbprint": "CC"}]
    ctx, _ = ctx_with(ps("Cert:", rows))
    t = titles(w.MachineCertificatesCheck(today=date(2026, 10, 24)).run(ctx))
    assert any("expired 23 day" in x for x in t)
    assert any("weak signature" in x for x in t) and any("1024-bit" in x for x in t)
    assert any("expires in 17 day" in x for x in t)


AUDITPOL = """Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
PC,System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success,,1
PC,System,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},Success and Failure,,3
PC,System,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success,,1
PC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3
PC,System,Account Lockout,{0CCE9217-69AE-11D9-BED3-505054503030},Failure,,2
PC,System,Special Logon,{0CCE921B-69AE-11D9-BED3-505054503030},Success,,1
PC,System,Audit Policy Change,{0CCE922F-69AE-11D9-BED3-505054503030},Success,,1
PC,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},No Auditing,,0
"""


def test_audit_policy_gaps():
    ctx, _ = ctx_with((("auditpol",), {"stdout": AUDITPOL}))
    f = w.AuditPolicyCheck().run(ctx)
    assert len(f) == 1 and "Credential Validation" in f[0].description and "Process Creation" in f[0].description
    assert "Logon (" not in f[0].description


def test_auditpol_text_fallback_and_garbage():
    no_values = AUDITPOL.replace(",,1\n", ",,\n").replace(",,3\n", ",,\n")
    assert w.parse_auditpol_csv(no_values)["{0CCE9215-69AE-11D9-BED3-505054503030}"] == 3
    ctx, _ = ctx_with((("auditpol",), {"stdout": "garbage"}))
    with pytest.raises(SkipCheck):
        w.AuditPolicyCheck().run(ctx)
