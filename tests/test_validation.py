import pytest

from psatoolkit.core.validation import (HARD_MAX_HOSTS, ValidationError, parse_ports, parse_target, safe_filename,
                                        validate_free_text, validate_hostname, validate_output_dir)


def test_single_ip():
    t = parse_target("192.168.1.10")
    assert t.kind == "ip" and t.host_count == 1 and t.iter_hosts() == ["192.168.1.10"]
    assert t.contains("192.168.1.10") and not t.contains("192.168.1.11")


def test_cidr_within_limit():
    t = parse_target("10.0.0.0/24")
    assert t.kind == "network" and t.host_count == 254
    assert len(t.iter_hosts()) == 254
    assert t.contains("10.0.0.77") and not t.contains("10.0.1.1")


def test_cidr_over_configured_limit_rejected():
    with pytest.raises(ValidationError, match="authorized limit"):
        parse_target("10.0.0.0/23", max_hosts=256)


def test_hard_limit_cannot_be_exceeded_by_config():
    with pytest.raises(ValidationError):
        parse_target("10.0.0.0/16", max_hosts=10**9)
    assert parse_target("10.0.0.0/22", max_hosts=10**9).host_count <= HARD_MAX_HOSTS


def test_ipv6_single_and_huge_range():
    assert parse_target("2001:db8::1").kind == "ip"
    with pytest.raises(ValidationError):
        parse_target("2001:db8::/64")


@pytest.mark.parametrize("bad", [
    "", " ", "10.0.0.1,10.0.0.2", "10.0.0.*", "10.0.0.1; rm -rf /", "$(whoami)", "`id`",
    "host name", "a|b", "10.0.0.1-20", "224.0.0.1", "0.0.0.0", "255.255.255.255", "10.0.0.0/33",
    "-oN.example", "a..b", "999.1.1.1",
])
def test_rejects_invalid_or_dangerous_targets(bad):
    with pytest.raises(ValidationError):
        parse_target(bad)


def test_hostname_target():
    t = parse_target("Server01.corp.example.com")
    assert t.kind == "hostname" and t.hostname == "server01.corp.example.com"
    assert t.contains("SERVER01.corp.example.com")


def test_hostname_label_rules():
    assert validate_hostname("web-01") == "web-01"
    for bad in ("-web", "web-", "a" * 64, "x." * 130):
        with pytest.raises(ValidationError):
            validate_hostname(bad)


def test_ports():
    assert parse_ports("22, 80,443,8000-8002") == [22, 80, 443, 8000, 8001, 8002]
    assert parse_ports("80,80") == [80]
    for bad in ("", "0", "65536", "80-22", "22;id", "1-2-3", "a"):
        with pytest.raises(ValidationError):
            parse_ports(bad)
    with pytest.raises(ValidationError, match="Too many"):
        parse_ports("1-2000", max_ports=1024)


def test_free_text():
    assert validate_free_text("  CHG-1234 / Jane O'Neil  ", "x") == "CHG-1234 / Jane O'Neil"
    assert validate_free_text("", "x", required=False) == ""
    for bad in ("", "a" * 201, "x\ny", "<script>", "a;$(id)`"):
        with pytest.raises(ValidationError):
            validate_free_text(bad, "x")


def test_safe_filename():
    assert safe_filename("../../etc/passwd") == "etc_passwd"
    assert safe_filename("WEB01.corp") == "WEB01.corp"
    assert safe_filename("") == "unnamed"
    assert len(safe_filename("a" * 500)) == 64


def test_validate_output_dir(tmp_path):
    assert validate_output_dir(tmp_path) == tmp_path.resolve()
    with pytest.raises(ValidationError):
        validate_output_dir(tmp_path / "missing")
    with pytest.raises(ValidationError):
        validate_output_dir("  ")
