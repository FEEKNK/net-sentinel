"""Tests for Snort-compatible rule parsing and packet matching."""

import ipaddress

from app.core.snort_parser import match_rule, parse_snort_rules


def test_parse_valid_and_invalid_snort_rules() -> None:
    text = """
    # Comment line
    alert tcp any any -> any [80,8080] (msg:"HTTP SQLi"; content:"UNION SELECT"; nocase; sid:1001; priority:1;)
    alert tcp any any -> any 23 (msg:"Duplicate SID"; sid:1001;)
    bad syntax line without parens
    alert udp any any -> any 53 (sid:1002;)
    """
    res = parse_snort_rules(text)
    assert len(res.rules) == 1
    assert res.rules[0].sid == 1001
    assert res.rules[0].severity == "critical"
    assert res.rules[0].nocase is True
    assert len(res.errors) == 3


def test_match_rule_ports_ips_and_content() -> None:
    text = 'alert tcp !10.0.0.5 any -> $HOME_NET [80,8000:8085] (msg:"SQLi"; content:"union select"; nocase; sid:2001; priority:2;)'
    res = parse_snort_rules(text)
    rule = res.rules[0]
    home = [ipaddress.IPv4Network("192.168.1.0/24")]

    assert match_rule(
        rule,
        protocol="tcp",
        src_ip="203.0.113.10",
        src_port=54321,
        dst_ip="192.168.1.50",
        dst_port=8080,
        payload="GET /?q=1 UNION SELECT password",
        home_nets=home,
    )

    # Negated source IP should NOT match
    assert not match_rule(
        rule,
        protocol="tcp",
        src_ip="10.0.0.5",
        src_port=54321,
        dst_ip="192.168.1.50",
        dst_port=80,
        payload="UNION SELECT",
        home_nets=home,
    )

    # Wrong destination port should NOT match
    assert not match_rule(
        rule,
        protocol="tcp",
        src_ip="203.0.113.10",
        src_port=54321,
        dst_ip="192.168.1.50",
        dst_port=443,
        payload="UNION SELECT",
        home_nets=home,
    )
