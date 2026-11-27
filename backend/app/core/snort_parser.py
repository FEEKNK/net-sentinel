"""Lightweight Snort-compatible rule parser and packet matcher."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field


RULE_HEADER_RE = re.compile(
    r"^(alert|log|pass)\s+"
    r"(tcp|udp|icmp|ip|any)\s+"
    r"(\S+)\s+(\S+)\s+"
    r"(->|<>)\s+"
    r"(\S+)\s+(\S+)\s*"
    r"\((.*)\)\s*$",
    re.IGNORECASE,
)

OPTION_RE = re.compile(r'([a-zA-Z0-9_]+)\s*(?::\s*("(?:\\.|[^"])*"|[^;]+))?\s*;')


@dataclass(slots=True)
class SnortRule:
    """Parsed Snort rule representation."""

    sid: int
    action: str
    protocol: str
    src_ip: str
    src_port: str
    direction: str
    dst_ip: str
    dst_port: str
    msg: str
    contents: list[str] = field(default_factory=list)
    pcre: str | None = None
    pcre_flags: int = 0
    nocase: bool = False
    classtype: str = "misc-activity"
    priority: int = 3
    raw: str = ""

    @property
    def severity(self) -> str:
        """Map Snort priority (1..4) to NetSentinel severity levels."""
        if self.priority <= 1:
            return "critical"
        if self.priority == 2:
            return "high"
        if self.priority == 3:
            return "medium"
        return "low"


@dataclass(slots=True)
class RuleParseResult:
    """Result of parsing a Snort rules file or text."""

    rules: list[SnortRule]
    errors: list[dict[str, str | int]]


def parse_snort_rules(rules_text: str) -> RuleParseResult:
    """Parse multi-line Snort rules text, returning valid rules and line errors."""
    rules: list[SnortRule] = []
    errors: list[dict[str, str | int]] = []
    seen_sids: set[int] = set()

    for line_no, raw_line in enumerate(rules_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = RULE_HEADER_RE.match(line)
        if not match:
            errors.append({"line": line_no, "error": "Invalid Snort rule syntax", "raw": line[:120]})
            continue

        action, protocol, src_ip, src_port, direction, dst_ip, dst_port, opts_body = match.groups()
        opts = _parse_options(opts_body)

        msg = str(opts.get("msg", "")).strip()
        if not msg:
            errors.append({"line": line_no, "error": "Missing required 'msg' option", "raw": line[:120]})
            continue

        try:
            sid = int(str(opts.get("sid", "0")).strip())
        except ValueError:
            errors.append({"line": line_no, "error": "Invalid numeric 'sid'", "raw": line[:120]})
            continue
        if sid <= 0:
            errors.append({"line": line_no, "error": "Missing positive 'sid'", "raw": line[:120]})
            continue
        if sid in seen_sids:
            errors.append({"line": line_no, "error": f"Duplicate sid {sid}", "raw": line[:120]})
            continue
        seen_sids.add(sid)

        try:
            priority = int(str(opts.get("priority", "3")).strip())
        except ValueError:
            priority = 3

        contents: list[str] = opts.get("contents", [])
        nocase = bool(opts.get("nocase", False))
        classtype = str(opts.get("classtype", "misc-activity")).strip() or "misc-activity"

        raw_pcre = opts.get("pcre")
        pcre_pattern: str | None = None
        pcre_flags = 0
        if isinstance(raw_pcre, str) and raw_pcre:
            if len(raw_pcre) > 200:
                errors.append({"line": line_no, "error": "PCRE pattern exceeds 200 chars", "raw": line[:120]})
                continue
            pcre_pattern, pcre_flags = _parse_pcre_literal(raw_pcre)
            try:
                re.compile(pcre_pattern, pcre_flags)
            except re.error as exc:
                errors.append({"line": line_no, "error": f"Invalid PCRE regex: {exc}", "raw": line[:120]})
                continue

        rules.append(
            SnortRule(
                sid=sid,
                action=action.lower(),
                protocol=protocol.lower(),
                src_ip=src_ip,
                src_port=src_port,
                direction=direction,
                dst_ip=dst_ip,
                dst_port=dst_port,
                msg=msg,
                contents=contents,
                pcre=pcre_pattern,
                pcre_flags=pcre_flags,
                nocase=nocase,
                classtype=classtype,
                priority=priority,
                raw=line,
            )
        )

    return RuleParseResult(rules=rules, errors=errors)


def _parse_pcre_literal(raw: str) -> tuple[str, int]:
    """Parse `/pattern/flags` Snort PCRE literal into (pattern, re_flags)."""
    text = raw.strip()
    flags = 0
    if text.startswith("/") and text.count("/") >= 2:
        last_slash = text.rfind("/")
        pattern = text[1:last_slash]
        flag_str = text[last_slash + 1 :]
        if "i" in flag_str:
            flags |= re.IGNORECASE
        if "m" in flag_str:
            flags |= re.MULTILINE
        if "s" in flag_str:
            flags |= re.DOTALL
        return pattern, flags
    return text, flags


def _parse_options(opts_body: str) -> dict[str, object]:
    parsed: dict[str, object] = {"contents": [], "nocase": False}
    for m in OPTION_RE.finditer(opts_body):
        key = m.group(1).lower()
        val = m.group(2)
        if val is not None:
            val = val.strip()
            if len(val) >= 2 and val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
        if key == "content" and val:
            contents = parsed["contents"]
            assert isinstance(contents, list)
            contents.append(val)
        elif key == "nocase":
            parsed["nocase"] = True
        elif val is not None:
            parsed[key] = val
    return parsed


def _match_ip(rule_ip: str, actual_ip: str, home_nets: list[ipaddress.IPv4Network]) -> bool:
    token = rule_ip.strip()
    negate = token.startswith("!")
    if negate:
        token = token[1:].strip()

    matched = False
    if token.lower() == "any":
        matched = True
    elif token.upper() == "$HOME_NET":
        try:
            addr = ipaddress.ip_address(actual_ip)
            matched = any(addr in net for net in home_nets) if isinstance(addr, ipaddress.IPv4Address) else False
        except ValueError:
            matched = False
    elif token.upper() == "$EXTERNAL_NET":
        try:
            addr = ipaddress.ip_address(actual_ip)
            matched = not any(addr in net for net in home_nets) if isinstance(addr, ipaddress.IPv4Address) else True
        except ValueError:
            matched = False
    else:
        try:
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
                matched = ipaddress.ip_address(actual_ip) in net
            else:
                matched = str(ipaddress.ip_address(token)) == actual_ip
        except ValueError:
            matched = False

    return (not matched) if negate else matched


def _match_port(rule_port: str, actual_port: int | None) -> bool:
    token = rule_port.strip()
    if token.lower() == "any":
        return True
    if actual_port is None:
        return False

    negate = token.startswith("!")
    if negate:
        token = token[1:].strip()

    matched = False
    if token.startswith("[") and token.endswith("]"):
        items = [part.strip() for part in token[1:-1].split(",") if part.strip()]
        matched = any(_match_single_port_expr(item, actual_port) for item in items)
    else:
        matched = _match_single_port_expr(token, actual_port)

    return (not matched) if negate else matched


def _match_single_port_expr(expr: str, actual_port: int) -> bool:
    if ":" in expr:
        start_s, end_s = expr.split(":", 1)
        start = int(start_s) if start_s else 0
        end = int(end_s) if end_s else 65535
        return start <= actual_port <= end
    try:
        return int(expr) == actual_port
    except ValueError:
        return False


def match_rule(
    rule: SnortRule,
    *,
    protocol: str,
    src_ip: str,
    src_port: int | None,
    dst_ip: str,
    dst_port: int | None,
    payload: str,
    home_nets: list[ipaddress.IPv4Network],
) -> bool:
    """Evaluate whether a packet matches a parsed Snort rule."""
    if rule.action == "pass":
        return False
    if rule.protocol != "any" and rule.protocol != "ip" and rule.protocol != protocol.lower():
        return False

    forward = (
        _match_ip(rule.src_ip, src_ip, home_nets)
        and _match_port(rule.src_port, src_port)
        and _match_ip(rule.dst_ip, dst_ip, home_nets)
        and _match_port(rule.dst_port, dst_port)
    )
    reverse = False
    if rule.direction == "<>" and not forward:
        reverse = (
            _match_ip(rule.src_ip, dst_ip, home_nets)
            and _match_port(rule.src_port, dst_port)
            and _match_ip(rule.dst_ip, src_ip, home_nets)
            and _match_port(rule.dst_port, src_port)
        )

    if not (forward or reverse):
        return False

    if rule.contents:
        haystack = payload.lower() if rule.nocase else payload
        for needle in rule.contents:
            cmp_needle = needle.lower() if rule.nocase else needle
            if cmp_needle not in haystack:
                return False

    if rule.pcre:
        if not re.search(rule.pcre, payload[:4096], rule.pcre_flags):
            return False

    return True
