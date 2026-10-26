"""Module A and shared-helper tests."""

import pytest

from conftest import LINUX_OS
from fakes import WINDOWS_OS, FakeFS, FakeRunner, make_ctx, titles
from psatoolkit.core.engine import AssessmentEngine, Check, Module, SkipCheck, build_host_info
from psatoolkit.core.logging_setup import AuditLog
from psatoolkit.core.models import CheckStatus, Severity
from psatoolkit.modules import _common as c
from psatoolkit.modules import system_info as s

# 127.0.0.1:53 LISTEN, 0.0.0.0:22 LISTEN, 0.0.0.0:6379 LISTEN, 10.0.0.5:22 <- 10.0.0.9:51000 ESTABLISHED
PROC_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 1001 1
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1
   2: 00000000:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 1003 1
   3: 0500000A:0016 0900000A:C738 01 00000000:00000000 00:00000000 00000000     0        0 1004 1
"""
# [::]:23 LISTEN, [::1]:631 LISTEN
PROC_TCP6 = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0017 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2002 1
"""
# 0.0.0.0:161 unconnected (listening)
PROC_UDP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when ref pointer drops
  10: 00000000:00A1 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3001 2 0000000000000000 0
"""


def linux_fs():
    fs = FakeFS().add("/proc/net/tcp", PROC_TCP).add("/proc/net/tcp6", PROC_TCP6).add("/proc/net/udp", PROC_UDP)
    fs.add("/proc/42/comm", "sshd\n")
    fs.links["/proc/42/fd/3"] = "socket:[1002]"
    fs.links["/proc/42/fd/4"] = "/dev/null"
    return fs


def test_parse_proc_net_addresses():
    rows = c.parse_proc_net(PROC_TCP, "tcp")
    assert [(r["local"], r["lport"], r["state"]) for r in rows][:3] == [
        ("127.0.0.1", 53, "0A"), ("0.0.0.0", 22, "0A"), ("0.0.0.0", 6379, "0A")]
    assert rows[3]["remote"] == "10.0.0.9" and rows[3]["rport"] == 51000
    six = c.parse_proc_net(PROC_TCP6, "tcp6")
    assert [(r["local"], r["lport"]) for r in six] == [("::", 23), ("::1", 631)]


def test_loopback_detection():
    for addr in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "127.0.0.53%lo", "localhost"):
        assert c.is_loopback(addr)
    for addr in ("0.0.0.0", "::", "10.0.0.5", "*"):
        assert not c.is_loopback(addr)


def test_linux_listeners_with_process_owner():
    ctx = make_ctx(LINUX_OS, FakeRunner(), linux_fs())
    found = c.linux_listeners(ctx)
    assert {(l.proto, l.address, l.port) for l in found} == {
        ("tcp", "127.0.0.1", 53), ("tcp", "0.0.0.0", 22), ("tcp", "0.0.0.0", 6379), ("tcp6", "::", 23),
        ("tcp6", "::1", 631), ("udp", "0.0.0.0", 161)}
    ssh = next(l for l in found if l.port == 22)
    assert ssh.process == "sshd" and ssh.pid == 42
    with pytest.raises(SkipCheck):
        c.linux_listeners(make_ctx(LINUX_OS, FakeRunner(), FakeFS()))


def test_listening_ports_inventory():
    ctx = make_ctx(LINUX_OS, FakeRunner(), linux_fs(), elevated=False)
    f = s.ListeningPortsCheck().run(ctx)
    assert f[0].title == "4 network service(s) listening beyond loopback"
    assert ctx.partial and ctx.partial[0].category == "privilege"


def test_risky_services_linux():
    ctx = make_ctx(LINUX_OS, FakeRunner(), linux_fs())
    f = s.ExposedRiskyServicesCheck().run(ctx)
    assert [(x.severity, x.title.split(" is ")[0]) for x in f] == [
        (Severity.HIGH, "Telnet"), (Severity.MEDIUM, "SNMP"), (Severity.MEDIUM, "Redis")]
    assert all(x.manual_validation_required for x in f)


def test_risky_services_windows_listeners():
    rows = [{"proto": "tcp", "address": "0.0.0.0", "port": 445, "pid": 4, "process": "System"},
            {"proto": "tcp", "address": "::", "port": 21, "pid": 900, "process": "inetinfo"},
            {"proto": "tcp", "address": "127.0.0.1", "port": 3306, "pid": 1, "process": "mysqld"}]
    runner = FakeRunner().on("powershell", contains="Get-NetTCPConnection", json_=rows)
    f = s.ExposedRiskyServicesCheck().run(make_ctx(WINDOWS_OS, runner))
    assert titles(f) == ["FTP is listening on tcp/21 beyond loopback"]   # SMB normal on Windows; MySQL loopback


def test_network_interfaces_linux_ip_json_and_fallback():
    ip_json = [{"ifname": "eth0", "operstate": "UP", "addr_info": [
        {"family": "inet", "local": "10.0.0.5", "prefixlen": 24}, {"family": "inet6", "local": "fe80::1",
                                                                    "prefixlen": 64}]}]
    ctx = make_ctx(LINUX_OS, FakeRunner().on("ip", json_=ip_json), linux_fs())
    f = s.NetworkInterfacesCheck().run(ctx)
    data = f[0].evidence[0].data
    assert [i["address"] for i in data["interfaces"]] == ["10.0.0.5", "fe80::1"]
    assert data["established_tcp_connections"] == 1 and data["top_remote_hosts"][0]["address"] == "10.0.0.9"
    fs = linux_fs().add("/sys/class/net/eth0/operstate", "up\n")
    ctx = make_ctx(LINUX_OS, FakeRunner(), fs)
    f = s.NetworkInterfacesCheck().run(ctx)
    assert f[0].evidence[0].data["interfaces"] == [{"interface": "eth0", "state": "up", "address": None}]
    assert "ip" in ctx.partial[0].description


def test_network_interfaces_windows():
    runner = FakeRunner().on("powershell", contains="Get-NetIPAddress", json_=[
        {"InterfaceAlias": "Ethernet", "IPAddress": "192.168.1.20", "PrefixLength": 24, "AddressFamily": 2}]) \
        .on("powershell", contains="Get-NetTCPConnection", json_={"RemoteAddress": "52.1.2.3", "RemotePort": 443})
    data = s.NetworkInterfacesCheck().run(make_ctx(WINDOWS_OS, runner))[0].evidence[0].data
    assert data["interfaces"][0]["family"] == "IPv4" and data["remote_hosts"] == 1


def test_software_inventory():
    dpkg = "openssl\t3.0.13-0ubuntu3.4\tii \nold-pkg\t1.0\trc \nbash\t5.2.21-2ubuntu4\tii \n"
    f = s.SoftwareInventoryCheck().run(make_ctx(LINUX_OS, FakeRunner().on("dpkg-query", stdout=dpkg)))
    assert f[0].evidence[0].data == [{"name": "openssl", "version": "3.0.13-0ubuntu3.4"},
                                     {"name": "bash", "version": "5.2.21-2ubuntu4"}]
    rpm = FakeRunner().on("dpkg-query", error="not_found").on("rpm", stdout="openssl\t3.0.7-25.el9\n")
    assert "1 installed" in s.SoftwareInventoryCheck().run(make_ctx(LINUX_OS, rpm))[0].title
    with pytest.raises(SkipCheck):
        s.SoftwareInventoryCheck().run(make_ctx(LINUX_OS, FakeRunner()))
    win = FakeRunner().on("powershell", contains="Uninstall", json_=[
        {"DisplayName": "7-Zip", "DisplayVersion": "23.01", "Publisher": "Igor Pavlov"},
        {"DisplayName": "7-Zip", "DisplayVersion": "23.01", "Publisher": "Igor Pavlov"}])
    assert "1 installed" in s.SoftwareInventoryCheck().run(make_ctx(WINDOWS_OS, win))[0].title


def test_registry_script_and_int_parsing():
    script = c.ps_registry_script({"a": ("HKLM:\\SOFTWARE\\O'Brien", ["Val"])})
    assert "O''Brien" in script and "$o['a.Val']" in script
    assert c.as_int("5") == 5 and c.as_int(True) == 1 and c.as_int("x") is None and c.as_int(None) is None


def test_engine_propagates_notes_and_partial_limitations(config, authorization):
    class Partial(Check):
        check_id, title, supported_os = "P-1", "partial", frozenset({"linux"})

        def run(self, ctx):
            ctx.note("checked 3 things")
            ctx.limitation("could not read X", "privilege")
            return []

    engine = AssessmentEngine([Module("m", "M", "", "local", [Partial()])], config)
    runner = FakeRunner()
    result = engine.run(authorization=authorization, selected=["m"], host=build_host_info(LINUX_OS, "h", True),
                        os_info=LINUX_OS, runner=runner, audit=AuditLog(None), stop=runner.stop_token, fs=FakeFS())
    assert result.checks[0].status == CheckStatus.PASSED and result.checks[0].message == "checked 3 things"
    assert result.limitations[0].check_id == "P-1" and result.limitations[0].category == "privilege"
