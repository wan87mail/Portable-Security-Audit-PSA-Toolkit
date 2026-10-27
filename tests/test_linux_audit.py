"""Module C tests with an in-memory filesystem and mocked commands."""

import json
import stat as st
from datetime import date

import pytest

from fakes import LINUX_OS, FakeFS, FakeRunner, by_severity, make_ctx, titles
from psatoolkit.core.engine import SkipCheck
from psatoolkit.core.hostfs import HostFS
from psatoolkit.core.models import FindingStatus, Severity
from psatoolkit.modules import linux_audit as l


def ctx(fs=None, runner=None, elevated=True, is_server=True):
    return make_ctx(LINUX_OS, runner or FakeRunner(), fs or FakeFS(), elevated=elevated, is_server=is_server)


# -- patching ------------------------------------------------------------------------------

APT = """Listing...
openssl/noble-updates,noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]
libssl3t64/noble-updates,noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]
vim/noble-updates 2:9.1.0016-1ubuntu7.4 amd64 [upgradable from: 2:9.1.0016-1ubuntu7.3]
"""
NOW = 1_800_000_000.0


def test_parse_apt_upgradable():
    pkgs = l.parse_apt_upgradable(APT)
    assert [p["package"] for p in pkgs] == ["openssl", "libssl3t64", "vim"]
    assert [p["security"] for p in pkgs] == [True, True, False]
    assert pkgs[0]["installed"] == "3.0.13-0ubuntu3.4"


def test_apt_security_updates_and_reboot():
    fs = FakeFS().add("/var/lib/apt/periodic/update-success-stamp", "", mtime=NOW - 3600) \
        .add("/etc/apt/apt.conf.d/20auto-upgrades", 'APT::Periodic::Unattended-Upgrade "1";') \
        .add("/run/reboot-required", "").add("/run/reboot-required.pkgs", "linux-base\n")
    runner = FakeRunner(available={"apt"}).on("apt", "list", stdout=APT)
    c = ctx(fs, runner)
    sev = by_severity(l.PatchStatusCheck(now=lambda: NOW).run(c))
    assert sev["medium"] == ["2 security update(s) pending"]
    assert "reboot" in sev["low"][0]
    assert not c.partial


def test_apt_stale_cache_no_auto_updates():
    fs = FakeFS().add("/var/lib/apt/periodic/update-success-stamp", "", mtime=NOW - 30 * 86400)
    runner = FakeRunner(available={"apt"}).on("apt", "list", stdout="Listing...\n")
    c = ctx(fs, runner)
    f = l.PatchStatusCheck(now=lambda: NOW).run(c)
    assert [x.status for x in f] == [FindingStatus.INCONCLUSIVE, FindingStatus.POTENTIAL]
    assert "apt update" in c.partial[0].description


def test_many_security_updates_is_high():
    lines = "\n".join(f"pkg{i}/noble-security 1.{i} amd64 [upgradable from: 1.0]" for i in range(12))
    runner = FakeRunner(available={"apt"}).on("apt", "list", stdout=lines)
    fs = FakeFS().add("/etc/apt/apt.conf.d/20auto-upgrades", 'APT::Periodic::Unattended-Upgrade "1";')
    f = l.PatchStatusCheck(now=lambda: NOW).run(ctx(fs, runner))
    assert f[0].severity == Severity.HIGH


def test_dnf_and_no_package_manager():
    runner = FakeRunner(available={"dnf"}).on("dnf", "-q", "--cacheonly", "check-update", returncode=100,
                                              stdout="openssl.x86_64  3.0.7-25  updates\n") \
        .on("dnf", "-q", "--cacheonly", "updateinfo", stdout="RHSA-2024:1 Important/Sec. openssl-3.0.7-25\n")
    f = l.PatchStatusCheck().run(ctx(FakeFS(), runner))
    assert f[0].severity == Severity.MEDIUM
    with pytest.raises(SkipCheck):
        l.PatchStatusCheck().run(ctx(FakeFS(), FakeRunner(available=set())))


# -- SSH -------------------------------------------------------------------------------------

def test_sshd_config_parsing_include_first_wins_and_match():
    fs = FakeFS() \
        .add("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n"
                                     "PasswordAuthentication yes\nMatch User backup\n  PermitRootLogin no\n") \
        .add("/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication no\n") \
        .add("/etc/ssh/sshd_config.d/99-secret.conf", None)
    fs.denied.add("/etc/ssh/sshd_config.d/99-secret.conf")
    settings, read, unreadable = l.parse_sshd_config(fs)
    assert settings["passwordauthentication"] == "no"      # include processed first, first value wins
    assert settings["permitrootlogin"] == "yes"            # Match block not applied globally
    assert unreadable == ["/etc/ssh/sshd_config.d/99-secret.conf"]


def test_ssh_effective_config_findings():
    out = ("permitrootlogin yes\npasswordauthentication yes\npermitemptypasswords yes\nx11forwarding yes\n"
           "maxauthtries 6\nciphers aes256-gcm@openssh.com,aes128-cbc\nmacs hmac-sha2-256,hmac-sha1\n"
           "kexalgorithms curve25519-sha256\n")
    fs = FakeFS().add("/etc/ssh/sshd_config", "")
    f = l.SshConfigCheck().run(ctx(fs, FakeRunner().on("sshd", "-T", stdout=out)))
    sev = by_severity(f)
    assert "empty passwords" in sev["critical"][0]
    assert "root login" in sev["high"][0]
    assert any("aes128-cbc" in t for t in sev["medium"]) and any("hmac-sha1" in t for t in sev["medium"])
    assert not any("kexalgorithms" in t for t in sev["medium"])
    assert len(sev["low"]) == 2


def test_ssh_non_root_uses_files_and_defaults():
    fs = FakeFS().add("/etc/ssh/sshd_config", "PermitRootLogin prohibit-password\n")
    c = ctx(fs, FakeRunner(), elevated=False)
    f = l.SshConfigCheck().run(c)
    assert titles(f) == ["SSH accepts password authentication", "SSH MaxAuthTries is 6"]  # OpenSSH defaults
    assert "default" in f[0].description
    assert c.partial and c.partial[0].category == "privilege"


def test_ssh_not_installed():
    c = ctx(FakeFS())
    assert l.SshConfigCheck().run(c) == [] and "not installed" in c.notes[0]


# -- firewall --------------------------------------------------------------------------------

NFT_FILTERING = """table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
	}
}"""
NFT_EMPTY = """table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
	}
}"""


def test_nft_and_iptables_parsers():
    assert l.nft_input_filtering(NFT_FILTERING) is True
    assert l.nft_input_filtering(NFT_EMPTY) is False
    assert l.nft_input_filtering("") is False
    assert l.iptables_input_filtering("-P INPUT ACCEPT\n-P FORWARD DROP\n-A DOCKER x") is False
    assert l.iptables_input_filtering("-P INPUT DROP\n") is True
    assert l.iptables_input_filtering("-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT") is True


def test_firewall_absent_as_root():
    runner = FakeRunner(available={"nft", "iptables"}).on("nft", stdout=NFT_EMPTY).on("iptables", stdout="-P INPUT ACCEPT")
    f = l.FirewallCheck().run(ctx(FakeFS(), runner))
    assert f[0].severity == Severity.MEDIUM and f[0].status == FindingStatus.CONFIRMED


def test_firewall_ufw_active_default_allow():
    runner = FakeRunner(available={"ufw"}).on("ufw", stdout="Status: active\nDefault: allow (incoming), allow (outgoing)")
    assert "allows incoming" in l.FirewallCheck().run(ctx(FakeFS(), runner))[0].title
    runner = FakeRunner(available={"ufw"}).on("ufw", stdout="Status: active\nDefault: deny (incoming), allow (outgoing)")
    assert l.FirewallCheck().run(ctx(FakeFS(), runner)) == []


def test_firewall_non_root_uses_service_state():
    fs = FakeFS().add("/etc/ufw/ufw.conf", "ENABLED=no\n")
    runner = FakeRunner(available={"systemctl"}).on("systemctl", "is-active", "firewalld", stdout="inactive") \
        .on("systemctl", "is-active", stdout="inactive", returncode=3)
    c = ctx(fs, runner, elevated=False)
    f = l.FirewallCheck().run(c)
    assert f[0].status == FindingStatus.POTENTIAL and c.partial
    fs = FakeFS().add("/etc/ufw/ufw.conf", "ENABLED=yes\n")
    assert l.FirewallCheck().run(ctx(fs, runner, elevated=False)) == []


# -- accounts and sudo ---------------------------------------------------------------------------

PASSWD = """root:x:0:0:root:/root:/bin/bash
toor:x:0:0::/root:/bin/bash
alice:x:1000:1000::/home/alice:/bin/bash
bob:x:1001:1001::/home/bob:/bin/bash
"""
GROUP = "root:x:0:\nsudo:x:27:alice\ndocker:x:999:bob\nalice:x:1000:\n"


def test_privileged_accounts():
    fs = FakeFS().add("/etc/passwd", PASSWD).add("/etc/group", GROUP)
    sev = by_severity(l.PrivilegedAccountsCheck().run(ctx(fs)))
    assert "toor" in sev["high"][0]
    assert "docker" in sev["medium"][0]
    assert sev["informational"] == ["2 account(s) in administrative groups"]   # alice (sudo), toor (gid 0)


def test_sudoers():
    sudoers = ("Defaults env_reset\nDefaults:deploy !authenticate\nroot ALL=(ALL:ALL) ALL\n"
               "%sudo ALL=(ALL:ALL) ALL\nci ALL=(ALL) NOPASSWD: ALL\nbackup ALL=(root) NOPASSWD: /usr/bin/rsync\n"
               "ALL ALL=(ALL) /usr/bin/whoami\nUser_Alias ADMINS = a, \\\n  b\n#includedir /etc/sudoers.d\n")
    fs = FakeFS().add("/etc/sudoers", sudoers, mode=0o440).add("/etc/sudoers.d/90-cloud", "ubuntu ALL=(ALL) NOPASSWD:ALL\n") \
        .add("/etc/sudoers.d/README.txt", "ALL ALL=(ALL) NOPASSWD: ALL")  # files with '.' are ignored by sudo
    sev = by_severity(l.SudoersCheck().run(ctx(fs)))
    assert sev["high"] == ["Sudo rule applies to every user"]
    assert "2 sudo rule(s)" in sev["medium"][0]
    assert "authentication is disabled" in sev["medium"][1]


def test_sudoers_unreadable_is_skip():
    fs = FakeFS().add("/etc/sudoers", None)
    fs.denied.add("/etc/sudoers")
    with pytest.raises(SkipCheck):
        l.SudoersCheck().run(ctx(fs))


@pytest.mark.parametrize("field,algo", [("", "empty"), ("!", "locked"), ("*", "locked"), ("!!", "locked"),
                                        ("$6$salt$hash", "sha512"), ("$y$j9T$salt$hash", "yescrypt"),
                                        ("$1$salt$hash", "md5"), ("abcdefghijklm", "des"),
                                        ("$2b$12$hash", "bcrypt"), ("$9$x$y", "other")])
def test_password_algorithm(field, algo):
    assert l.password_algorithm(field) == algo


def test_shadow_findings_never_contain_hashes():
    shadow = ("root:$6$abcdefgh$SECRETHASHVALUE:19000:0:99999:7:::\nguest::19000:0:99999:7:::\n"
              "legacy:$1$saltsalt$OLDSECRETHASH:19000::::::\nsvc:!:19000::::::\n")
    fs = FakeFS().add("/etc/shadow", shadow, mode=0o640)
    f = l.EmptyPasswordsCheck().run(ctx(fs))
    assert [x.severity for x in f] == [Severity.HIGH, Severity.MEDIUM]
    blob = json.dumps([[e.data for e in x.evidence] for x in f]) + " ".join(x.description for x in f)
    assert "SECRET" not in blob and "$6$" not in blob and "$1$" not in blob
    assert "guest" in blob and "legacy" in blob


def test_password_policy_missing_modules_and_md5():
    fs = FakeFS().add("/etc/pam.d/common-password", "password [success=1] pam_unix.so obscure yescrypt\n") \
        .add("/etc/pam.d/common-auth", "auth [success=1] pam_unix.so\n").add("/etc/login.defs", "ENCRYPT_METHOD MD5\n")
    t = titles(l.PasswordPolicyCheck().run(ctx(fs)))
    assert any("password quality" in x for x in t) and any("lockout" in x for x in t) and any("MD5" in x for x in t)


def test_password_policy_good_and_short_minlen():
    fs = FakeFS().add("/etc/pam.d/common-password", "password requisite pam_pwquality.so retry=3\n") \
        .add("/etc/security/pwquality.conf", "minlen = 14\n") \
        .add("/etc/pam.d/common-auth", "auth required pam_faillock.so preauth\n") \
        .add("/etc/login.defs", "ENCRYPT_METHOD YESCRYPT\n")
    assert l.PasswordPolicyCheck().run(ctx(fs)) == []
    fs.add("/etc/pam.d/common-password", "password requisite pam_pwquality.so minlen=6\n")
    assert l.PasswordPolicyCheck().run(ctx(fs))[0].severity == Severity.MEDIUM


# -- permissions --------------------------------------------------------------------------------

def test_world_writable_and_sticky():
    fs = FakeFS().add("/etc/cron.daily/job", "", mode=0o777).add("/usr/bin/tool", "", mode=0o755) \
        .add_dir("/usr/share/upload", mode=0o777).add_dir("/usr/share/ok-sticky", mode=0o1777) \
        .add_dir("/tmp", mode=0o777)
    f = l.WorldWritableCheck().run(ctx(fs))
    assert f[0].severity == Severity.HIGH
    paths = [h["path"] for h in f[0].evidence[0].data]
    assert paths == ["/etc/cron.daily/job", "/usr/share/upload"]
    assert "sticky" in f[1].title


def test_sensitive_file_permissions():
    fs = FakeFS().add("/etc/shadow", "", mode=0o644).add("/etc/passwd", "", mode=0o644) \
        .add("/etc/ssh/ssh_host_ed25519_key", "", mode=0o644).add("/etc/ssh/ssh_host_ed25519_key.pub", "", mode=0o644) \
        .add("/etc/crontab", "", mode=0o644, uid=1000).add_dir("/root", mode=0o700)
    sev = by_severity(l.SensitiveFilePermissionsCheck().run(ctx(fs)))
    assert sev["critical"] == ["Insecure permissions on /etc/shadow"]
    assert sev["high"] == ["Insecure permissions on /etc/ssh/ssh_host_ed25519_key"]
    assert sev["medium"] == ["Insecure permissions on /etc/crontab"]


def test_suid_classification():
    fs = FakeFS().add("/usr/bin/passwd", "", mode=0o4755).add("/usr/bin/find", "", mode=0o4755) \
        .add("/usr/bin/python3.12", "", mode=0o4755).add("/home/bob/.x/sh", "", mode=0o4755, uid=1001) \
        .add("/opt/vendor/helper", "", mode=0o2755).add("/usr/bin/ls", "", mode=0o755)
    sev = by_severity(l.SuidBinariesCheck().run(ctx(fs)))
    assert "trivial root" in sev["high"][0] and "user-writable" in sev["high"][1]
    f = l.SuidBinariesCheck().run(ctx(fs))
    assert {d["path"] for d in f[0].evidence[0].data} == {"/usr/bin/find", "/usr/bin/python3.12"}
    assert [d["path"] for d in f[2].evidence[0].data] == ["/opt/vendor/helper"]


# -- services, encryption, MAC, kernel -------------------------------------------------------------

def test_services():
    out = ("ssh.service loaded active running OpenBSD Secure Shell server\n"
           "telnet.socket loaded active listening Telnet\n"
           "vsftpd.service loaded active running vsftpd FTP server\n"
           "cups.service loaded active running CUPS\n")
    runner = FakeRunner().on("systemctl", "list-units", stdout=out)
    t = titles(l.ServicesCheck().run(ctx(runner=runner, is_server=True)))
    assert t == ["Service telnet.socket is running", "Service vsftpd.service is running",
                 "Service cups.service is running"]
    assert len(l.ServicesCheck().run(ctx(runner=runner, is_server=False))) == 2
    with pytest.raises(SkipCheck):
        l.ServicesCheck().run(ctx(runner=FakeRunner().on("systemctl", returncode=1)))


LSBLK_LUKS = {"blockdevices": [{"name": "nvme0n1", "type": "disk", "fstype": None, "mountpoint": None, "children": [
    {"name": "nvme0n1p1", "type": "part", "fstype": "vfat", "mountpoint": "/boot/efi"},
    {"name": "nvme0n1p3", "type": "part", "fstype": "crypto_LUKS", "mountpoint": None, "children": [
        {"name": "dm_crypt-0", "type": "crypt", "fstype": "LVM2_member", "mountpoint": None, "children": [
            {"name": "ubuntu--vg-root", "type": "lvm", "fstype": "ext4", "mountpoint": "/"}]}]}]}]}
LSBLK_PLAIN = {"blockdevices": [{"name": "vda", "type": "disk", "fstype": None, "mountpoint": None, "children": [
    {"name": "vda1", "type": "part", "fstype": "ext4", "mountpoints": ["/"]}]}]}


def test_root_encryption_detection():
    assert l.root_is_encrypted(LSBLK_LUKS) is True
    assert l.root_is_encrypted(LSBLK_PLAIN) is False
    assert l.root_is_encrypted({"blockdevices": [{"name": "loop0", "type": "loop", "mountpoint": "/snap/x"}]}) is None


def test_disk_encryption_check():
    run = lambda data: FakeRunner().on("lsblk", json_=data)  # noqa: E731
    assert l.DiskEncryptionCheck().run(ctx(runner=run(LSBLK_LUKS))) == []
    f = l.DiskEncryptionCheck().run(ctx(runner=run(LSBLK_PLAIN), is_server=False))
    assert f[0].severity == Severity.MEDIUM and f[0].status == FindingStatus.CONFIRMED
    f = l.DiskEncryptionCheck().run(ctx(runner=run(LSBLK_PLAIN), is_server=True))
    assert f[0].severity == Severity.LOW and f[0].manual_validation_required
    with pytest.raises(SkipCheck, match="container"):
        l.DiskEncryptionCheck().run(ctx(runner=run({"blockdevices": []})))


def test_mac():
    fs = FakeFS().add("/sys/module/apparmor/parameters/enabled", "Y\n") \
        .add("/sys/kernel/security/apparmor/profiles", "/usr/sbin/cupsd (enforce)\nsnap.x (complain)\n")
    assert l.MandatoryAccessControlCheck().run(ctx(fs)) == []
    fs = FakeFS().add("/sys/module/apparmor/parameters/enabled", "Y\n") \
        .add("/sys/kernel/security/apparmor/profiles", "a (complain)\n")
    assert "no profiles are enforcing" in l.MandatoryAccessControlCheck().run(ctx(fs))[0].title
    fs = FakeFS().add("/sys/fs/selinux/enforce", "0")
    assert "permissive" in l.MandatoryAccessControlCheck().run(ctx(fs))[0].title
    assert "No mandatory" in l.MandatoryAccessControlCheck().run(ctx(FakeFS()))[0].title


def test_kernel_parameters():
    fs = FakeFS()
    for path, value in {"kernel/randomize_va_space": "0", "fs/protected_symlinks": "0", "kernel/kptr_restrict": "1",
                        "net/ipv4/conf/all/accept_source_route": "1", "kernel/dmesg_restrict": "0"}.items():
        fs.add(f"/proc/sys/{path}", value + "\n")
    sev = by_severity(l.KernelHardeningCheck().run(ctx(fs)))
    assert sev["high"] == ["ASLR is disabled"] and sev["medium"] == ["Source-routed packets are accepted"]
    assert sev["low"] == ["2 kernel hardening parameter(s) deviate from recommendations"]
    with pytest.raises(SkipCheck):
        l.KernelHardeningCheck().run(ctx(FakeFS()))


# -- certificates ----------------------------------------------------------------------------------

X509 = """subject=CN = www.example.com
issuer=C = US, O = Let's Encrypt, CN = R11
notAfter=Nov  3 12:00:00 2026 GMT
Certificate:
    Data:
        Signature Algorithm: sha256WithRSAEncryption
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
"""


def test_parse_openssl_x509():
    info = l.parse_openssl_x509(X509)
    assert info["not_after"] == date(2026, 11, 3) and info["key_bits"] == 2048
    assert info["signature_algorithm"] == "sha256WithRSAEncryption" and info["subject"] == "CN = www.example.com"
    assert l.parse_openssl_x509("garbage") is None


def test_certificate_files_check():
    fs = FakeFS().add("/etc/nginx/ssl/site.crt", "x").add("/etc/nginx/ssl/site.key", "x") \
        .add("/etc/letsencrypt/live/a/privkey.pem", "x").add("/etc/nginx/ssl/dup.pem", "x")
    runner = FakeRunner().on("openssl", "x509", stdout=X509)
    c = ctx(fs, runner)
    f = l.CertificateFilesCheck(today=date(2026, 10, 24)).run(c)
    assert titles(f) == ["Certificate expires in 10 day(s): CN = www.example.com"]   # duplicate collapsed
    opened = [call[3] for call in runner.calls]
    assert "/etc/nginx/ssl/site.key" not in opened and "/etc/letsencrypt/live/a/privkey.pem" not in opened


# -- real HostFS -----------------------------------------------------------------------------------

@pytest.mark.skipif(__import__("sys").platform.startswith("win"), reason="symlinks need Developer Mode on Windows")
def test_hostfs_rooted_walk_does_not_follow_symlinks(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "a.conf").write_text("x=1")
    (tmp_path / "etc" / "loop").symlink_to(tmp_path)
    fs = HostFS(tmp_path)
    assert fs.try_read("/etc/a.conf") == ("x=1", None)
    assert fs.try_read("/etc/missing") == (None, "missing")
    seen = []
    stats = fs.walk(["/etc"], lambda p, s: seen.append((p, st.S_ISLNK(s.st_mode))))
    assert sorted(seen) == [("/etc/a.conf", False), ("/etc/loop", True)]
    assert stats.visited == 2
    with pytest.raises(ValueError):
        fs.read_text("relative/path")
