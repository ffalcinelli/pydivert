# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import logging
from typing import Any

from lark import Lark, Transformer, UnexpectedInput

logger = logging.getLogger(__name__)


class FilterSyntaxError(ValueError):
    """Raised when a WinDivert filter string has invalid syntax."""


WINDIVERT_GRAMMAR = r"""
    ?start: expression

    ?expression: ternary
               | logic_or

    ?ternary: logic_or "?" expression ":" expression

    ?logic_or: logic_and (("||" | "or") logic_and)*
    ?logic_and: logic_not (("&&" | "and") logic_not)*
    ?logic_not: ("!" | "not") logic_not -> not_expr
              | comparison
              | primary

    ?comparison: primary OPERATOR primary

    OPERATOR: "==" | "!=" | "<=" | ">=" | "<" | ">" | "="

    ?primary: field_access
            | value
            | "(" expression ")" -> parenthesized

    field_access: FIELD_NAME ("[" index "]")?
    index: "-" ? NUMBER ("b" | "w" | "d")?

    value: IPV4_ADDR
         | IPV6_ADDR
         | NUMBER
         | "true" -> true_val
         | "false" -> false_val
         | MACRO

    FIELD_NAME: /[a-zA-Z_][a-zA-Z0-9_\.]*/
    MACRO: /[A-Z][A-Z0-9_]*/
    NUMBER: /0x[0-9a-fA-F]+/ | /[0-9]+/
    IPV4_ADDR.3: /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
    IPV6_ADDR.2: /[0-9a-fA-F]*:[0-9a-fA-F:]+/ // Must contain at least one colon

    %import common.WS
    %ignore WS
"""


class WinDivertTransformer(Transformer):
    """
    Extracts structured rule components from a WinDivert filter.
    Returns a list of dictionaries, where each dictionary represents a set of AND-ed conditions (a rule).
    The list represents an OR of these rules.
    """

    def __init__(self):
        super().__init__()

    def field_access(self, children):
        name = str(children[0]).lower()
        # Keywords that are valid rules on their own
        if name == "ip":
            return [{"proto": "ip"}]
        if name == "tcp":
            return [{"proto": "tcp"}]
        if name == "udp":
            return [{"proto": "udp"}]
        if name == "icmp":
            return [{"proto": "icmp"}]
        if name == "inbound":
            return [{"direction": "inbound"}]
        if name == "outbound":
            return [{"direction": "outbound"}]
        if name == "loopback":
            return [{"loopback": True}]

        # TCP Flags as keywords
        if name in ("tcp.syn", "tcp.ack", "tcp.fin", "tcp.rst", "tcp.psh", "tcp.urg"):
            flag = name.split(".")[1]
            return [{"proto": "tcp", flag: True}]

        # Other names are just strings to be used in comparisons
        return name

    def value(self, children):
        return str(children[0])

    def true_val(self, _):
        return [{}]  # pragma: no cover

    def false_val(self, _):
        return [{"false": True}]  # pragma: no cover

    def expression(self, children):
        return children[0]  # pragma: no cover

    def ternary(self, children):
        # We simplify ternary for eBPF by just returning both possible rules
        # (effectively an OR of both branches)
        rules = []
        for child in children:
            if isinstance(child, list):
                rules.extend(child)
        return rules

    def parenthesized(self, children):
        return children[0]

    def _negate_rules(self, rules: list[dict]) -> list[dict]:
        """
        Negates a list of rules (OR of ANDs) by applying De Morgan's laws.
        Returns a new list of rules representing the negation.
        """
        if not rules:
            return [{}]  # pragma: no cover
        if rules == [{}]:
            return [{"false": True}]  # pragma: no cover

        negated_clauses = []
        for rule in rules:
            negated_clause = []
            for k, v in rule.items():
                if k == "false":
                    negated_clause.append({})
                elif k.startswith("!"):
                    negated_clause.append({k[1:]: v})
                else:
                    negated_clause.append({f"!{k}": v})
            negated_clauses.append(negated_clause)

        result = [{}]
        for clause_list in negated_clauses:
            new_result = []
            for existing_rule in result:
                for clause in clause_list:
                    merged = existing_rule.copy()
                    merged.update(clause)
                    new_result.append(merged)
            result = new_result
        return result

    def not_expr(self, children):
        return self._negate_rules(children[0])

    def logic_and(self, children):
        # We want the Cartesian product of all lists of rules
        result_rules = [{}]
        for child in children:
            if not isinstance(child, list) or not child:
                continue  # pragma: no cover
            new_result = []
            for existing_rule in result_rules:
                for new_rule_part in child:
                    merged = existing_rule.copy()
                    merged.update(new_rule_part)
                    new_result.append(merged)
            result_rules = new_result
        return result_rules

    def logic_or(self, children):
        # children is [list_of_dicts, operator, list_of_dicts, ...]
        rules = []
        for child in children:
            if isinstance(child, list):
                rules.extend(child)
        return rules

    def comparison(self, children):
        left, op, right = children
        # field_access for simple names might return a list of rules
        if isinstance(left, list):
            # This is unusual (e.g. "loopback == true") but we should handle it
            # For simplicity, we just extract the field name if it was a string
            return [{}]  # pragma: no cover

        field = self._normalize_field_name(str(left).lower())
        val = str(right)

        # Basic equality transpilation
        if op == "==" or op == "!=":
            rules = self._handle_port_comparison(field, val)
            if not rules:
                rules = self._handle_addr_comparison(field, val)
            if not rules and field == "ip.ttl":
                rules = [{"ttl": val}]

            if rules:
                return rules if op == "==" else self._negate_rules(rules)

        # For other operators or fields, we return an empty dict to allow user-space filtering
        return [{}]  # pragma: no cover

    def _normalize_field_name(self, field: str) -> str:
        mapping = {
            "ip.srcaddr": "ip.src",
            "ip.dstaddr": "ip.dst",
            "ipv6.srcaddr": "ipv6.src",
            "ipv6.dstaddr": "ipv6.dst",
            "tcp.srcport": "tcp.srcport",
            "tcp.dstport": "tcp.dstport",
            "udp.srcport": "udp.srcport",
            "udp.dstport": "udp.dstport",
        }
        return mapping.get(field, field)

    def _handle_port_comparison(self, field: str, val: str) -> list[dict[str, Any]] | None:
        import sys

        if field in ("tcp.dstport", "udp.dstport"):
            return [{"proto": field.split(".")[0], "dport": val}]
        if field in ("tcp.srcport", "udp.srcport"):
            return [{"proto": field.split(".")[0], "sport": val}]
        if field in ("tcp.port", "udp.port"):
            # Matches both source and destination
            proto = field.split(".")[0]
            if sys.platform.startswith("linux"):
                # On Linux we choose ONLY destination to avoid double interception loops
                return [{"proto": proto, "dport": val}]
            return [{"proto": proto, "dport": val}, {"proto": proto, "sport": val}]
        return None

    def _handle_addr_comparison(self, field: str, val: str) -> list[dict[str, Any]] | None:
        import sys

        res: list[dict[str, Any]] | None = None
        if field in ("ip.src", "ipv6.src", "ip.srcaddr", "ipv6.srcaddr"):
            res = [{"srcaddr": val}]
        elif field in ("ip.dst", "ipv6.dst", "ip.dstaddr", "ipv6.dstaddr"):
            res = [{"dstaddr": val}]  # pragma: no cover
        elif field in ("ip.addr", "ipv6.addr"):
            # Matches both source and destination
            if sys.platform.startswith("linux"):
                # On Linux we choose ONLY destination
                res = [{"dstaddr": val}]
            else:
                res = [{"srcaddr": val}, {"dstaddr": val}]

        if res and (val == "127.0.0.1" or val == "::1"):
            for r in res:
                r["loopback"] = True
        return res


class LegacyTransformer(Transformer):
    """
    Converts AST back to WinDivert filter string (used for testing/legacy).
    """

    def true_val(self, _):
        return "true"  # pragma: no cover

    def false_val(self, _):
        return "false"  # pragma: no cover

    def field_access(self, children):
        field_name = str(children[0]).lower()
        # Case-sensitive mapping for WinDivert 2.2+
        mapping = {
            # IP
            "ip.src": "ip.SrcAddr",
            "ip.srcaddr": "ip.SrcAddr",
            "ip.dst": "ip.DstAddr",
            "ip.dstaddr": "ip.DstAddr",
            "ip.ttl": "ip.TTL",
            "ip.protocol": "ip.Protocol",
            "ip.headerlength": "ip.HeaderLength",
            "ip.length": "ip.Length",
            # IPv6
            "ipv6.src": "ipv6.SrcAddr",
            "ipv6.srcaddr": "ipv6.SrcAddr",
            "ipv6.dst": "ipv6.DstAddr",
            "ipv6.dstaddr": "ipv6.DstAddr",
            "ipv6.hoplimit": "ipv6.HopLimit",
            "ipv6.nextheader": "ipv6.NextHeader",
            "ipv6.length": "ipv6.Length",
            "ipv6.trafficclass": "ipv6.TrafficClass",
            "ipv6.flowlabel": "ipv6.FlowLabel",
            # TCP
            "tcp.srcport": "tcp.SrcPort",
            "tcp.dstport": "tcp.DstPort",
            "tcp.seqnum": "tcp.SeqNum",
            "tcp.acknum": "tcp.AckNum",
            "tcp.headerlength": "tcp.HeaderLength",
            "tcp.payloadlength": "tcp.PayloadLength",
            "tcp.window": "tcp.Window",
            "tcp.urg": "tcp.Urg",
            "tcp.ack": "tcp.Ack",
            "tcp.psh": "tcp.Psh",
            "tcp.rst": "tcp.Rst",
            "tcp.syn": "tcp.Syn",
            "tcp.fin": "tcp.Fin",
            # UDP
            "udp.srcport": "udp.SrcPort",
            "udp.dstport": "udp.DstPort",
            "udp.length": "udp.Length",
            "udp.payloadlength": "udp.PayloadLength",
            # ICMP
            "icmp.type": "icmp.Type",
            "icmp.code": "icmp.Code",
            "icmp.checksum": "icmp.Checksum",
            "icmp.body": "icmp.Body",
            # ICMPv6
            "icmpv6.type": "icmpv6.Type",
            "icmpv6.code": "icmpv6.Code",
            "icmpv6.checksum": "icmpv6.Checksum",
            "icmpv6.body": "icmpv6.Body",
        }
        name = mapping.get(field_name, field_name)

        if len(children) > 1:  # pragma: no cover
            index = children[1]  # pragma: no cover
            return f"{name}[{index}]"  # pragma: no cover
        return name

    def index(self, children):
        return "".join(map(str, children))  # pragma: no cover

    def value(self, children):
        return str(children[0])

    def comparison(self, children):
        left, op, right = children
        # left is already the result of field_access (a string)
        field = left.lower()

        # Strip existing quotes to normalize
        val = str(right).strip("'\"")

        if op == "==":
            if field in ("ip.addr", "ipv6.addr"):
                proto = field.split(".")[0]  # pragma: no cover
                return f"({proto}.SrcAddr == {val} || {proto}.DstAddr == {val})"  # pragma: no cover
            if field in ("tcp.port", "udp.port"):
                proto = field.split(".")[0]  # pragma: no cover
                return f"({proto}.SrcPort == {val} || {proto}.DstPort == {val})"  # pragma: no cover

        if " " in val:
            val = f'"{val}"'  # pragma: no cover
        return f"{left} {op} {val}"

    def logic_and(self, children):
        return " && ".join(map(str, children))  # pragma: no cover

    def logic_or(self, children):
        return " || ".join(map(str, children))  # pragma: no cover

    def not_expr(self, children):
        return f"!({children[0]})"  # pragma: no cover

    def ternary(self, children):
        return f"({children[0]} ? {children[1]} : {children[2]})"  # pragma: no cover

    def parenthesized(self, children):
        return f"({children[0]})"  # pragma: no cover

    def expression(self, children):
        return str(children[0])  # pragma: no cover


class PythonEvalTransformer(Transformer):
    """
    Converts AST to a Python expression that can be evaluated with a packet.
    """

    def true_val(self, _):
        return "True"  # pragma: no cover

    def false_val(self, _):
        return "False"  # pragma: no cover

    def field_access(self, children):
        field_name = str(children[0]).lower()
        # Map WinDivert fields to packet properties/methods
        # Note: WinDivert is case-insensitive, but our Packet class uses lowercase attributes.
        mapping = {
            "ip.srcaddr": "packet.src_addr",
            "ip.src": "packet.src_addr",
            "ip.dstaddr": "packet.dst_addr",
            "ip.dst": "packet.dst_addr",
            "ip.addr": "AggregateField(packet.src_addr, packet.dst_addr)",
            "ipv6.srcaddr": "packet.src_addr",
            "ipv6.src": "packet.src_addr",
            "ipv6.dstaddr": "packet.dst_addr",
            "ipv6.dst": "packet.dst_addr",
            "ipv6.addr": "AggregateField(packet.src_addr, packet.dst_addr)",
            "tcp.srcport": "packet.src_port",
            "tcp.dstport": "packet.dst_port",
            "tcp.port": "AggregateField(packet.src_port, packet.dst_port)",
            "tcp.payloadlength": "len(packet.payload) if packet.payload else 0",
            "udp.srcport": "packet.src_port",
            "udp.dstport": "packet.dst_port",
            "udp.port": "AggregateField(packet.src_port, packet.dst_port)",
            "udp.payloadlength": "len(packet.payload) if packet.payload else 0",
            "icmp.type": "packet.icmp.type if packet.icmp else None",
            "icmp.code": "packet.icmp.code if packet.icmp else None",
            "icmpv6.type": "packet.icmp.type if packet.icmp else None",
            "icmpv6.code": "packet.icmp.code if packet.icmp else None",
            "tcp": "packet.tcp",
            "udp": "packet.udp",
            "icmp": "packet.icmp",
            "ipv4": "packet.ipv4",
            "ipv6": "packet.ipv6",
            "inbound": "packet.is_inbound",
            "outbound": "packet.is_outbound",
            "loopback": "packet.is_loopback",
        }
        if field_name in mapping:
            return mapping[field_name]

        # Fallback for other header fields (e.g. tcp.Syn, icmp.Type)
        if "." in field_name:  # pragma: no cover
            header, field = field_name.split(".", 1)  # pragma: no cover
            # Many WinDivert fields are lowercase in pydivert
            return f"packet.{header}.{field}"  # pragma: no cover

        return f"packet.{field_name}"  # pragma: no cover

    def value(self, children):
        val = str(children[0])
        # If it looks like an IP address, quote it.
        # Numbers should not be quoted.
        if "." in val or ":" in val:
            # Don't quote if already quoted or if it's a number
            try:
                float(val)
                return val  # pragma: no cover
            except ValueError:
                return f"'{val}'"
        return val

    def comparison(self, children):
        return f"({children[0]} {children[1]} {children[2]})"

    def logic_and(self, children):
        # filter out operators
        parts = [str(c) for c in children if str(c) not in ("&&", "and")]  # pragma: no cover
        return "(" + " and ".join(parts) + ")"  # pragma: no cover

    def logic_or(self, children):
        # filter out operators
        parts = [str(c) for c in children if str(c) not in ("||", "or")]  # pragma: no cover
        return "(" + " or ".join(parts) + ")"  # pragma: no cover

    def not_expr(self, children):
        return f"(not {children[0]})"  # pragma: no cover

    def ternary(self, children):
        return f"({children[1]} if {children[0]} else {children[2]})"  # pragma: no cover

    def parenthesized(self, children):
        return f"({children[0]})"  # pragma: no cover

    def expression(self, children):
        return str(children[0])  # pragma: no cover


def normalize_filter(filter_str: str) -> str:
    """
    Normalizes a WinDivert filter string by expanding aggregate fields.
    """
    try:
        parser = Lark(WINDIVERT_GRAMMAR, start="start", parser="lalr")
        tree = parser.parse(filter_str)
        return LegacyTransformer().transform(tree)
    except Exception as e:  # pragma: no cover
        logger.debug("Filter normalization failed: %s", e)  # pragma: no cover
        return filter_str  # pragma: no cover


transpile = normalize_filter


def transpile_to_python(filter_str: str) -> str:
    """
    Parses a WinDivert filter and returns a Python expression for evaluation.
    """
    try:
        parser = Lark(WINDIVERT_GRAMMAR, start="start", parser="lalr")
        tree = parser.parse(filter_str)
        return PythonEvalTransformer().transform(tree)
    except Exception as e:  # pragma: no cover
        logger.debug("Transpilation to Python failed: %s", e)
        return "True"


def transpile_to_rules(filter_str):
    """
    Parses a WinDivert filter and returns a list of rule components for backends.
    """
    try:
        parser = Lark(WINDIVERT_GRAMMAR, start="start", parser="lalr")
        tree = parser.parse(filter_str)
        transformer = WinDivertTransformer()
        rules = transformer.transform(tree)
        if not isinstance(rules, list):
            rules = [rules]
        return rules
    except UnexpectedInput as e:
        raise FilterSyntaxError(str(e)) from e


def transpile_to_ebpf(filter_str: str, sniff: bool = False, drop: bool = False) -> list[dict[str, Any]]:  # noqa: C901
    """
    Parses a WinDivert filter and returns a list of dictionaries compatible with BpfFilterRule.
    """
    import socket
    import struct

    # Protocol mapping
    PROTO_MAP = {
        "tcp": 6,
        "udp": 17,
        "icmp": 1,
    }

    # Match mask mapping (matching pydivert.bpf.c)
    MATCH_SRC_IP = 1 << 0
    MATCH_DST_IP = 1 << 1
    MATCH_SRC_PORT = 1 << 2
    MATCH_DST_PORT = 1 << 3
    MATCH_PROTO = 1 << 4
    MATCH_DIRECTION = 1 << 5
    MATCH_LOOPBACK = 1 << 6
    MATCH_FALSE = 1 << 7
    MATCH_ENABLED = 1 << 8
    MATCH_SNIFF = 1 << 9
    MATCH_DROP = 1 << 10
    MATCH_TTL = 1 << 11
    MATCH_TCP_FLAGS = 1 << 12

    rules = transpile_to_rules(filter_str)
    ebpf_rules = []

    for rule in rules:
        if not isinstance(rule, dict):
            continue

        # Check for contradictions (e.g. proto == tcp and !proto == tcp)
        contradiction = False
        for k, v in rule.items():
            if not k.startswith("!"):
                if f"!{k}" in rule and rule[f"!{k}"] == v:
                    contradiction = True
                    break
        if contradiction:
            continue

        ebpf_rule = {
            "src_ip": 0,
            "dst_ip": 0,
            "src_port": 0,
            "dst_port": 0,
            "proto": 0,
            "direction": 0,
            "loopback": 0,
            "ttl": 0,
            "tcp_flags": 0,
            "tcp_flags_mask": 0,
            "match_mask": MATCH_ENABLED,
            "invert_mask": 0,
        }

        if sniff:
            ebpf_rule["match_mask"] |= MATCH_SNIFF
        if drop:
            ebpf_rule["match_mask"] |= MATCH_DROP

        if "false" in rule:
            ebpf_rule["match_mask"] |= MATCH_FALSE

        # srcaddr
        val = rule.get("srcaddr")
        not_val = rule.get("!srcaddr")
        if val is not None or not_val is not None:
            addr = val if val is not None else not_val
            if ":" not in addr:
                ebpf_rule["src_ip"] = struct.unpack("!I", socket.inet_aton(addr))[0]
                ebpf_rule["match_mask"] |= MATCH_SRC_IP
                if val is None:
                    ebpf_rule["invert_mask"] |= MATCH_SRC_IP

        # dstaddr
        val = rule.get("dstaddr")
        not_val = rule.get("!dstaddr")
        if val is not None or not_val is not None:
            addr = val if val is not None else not_val
            if ":" not in addr:
                ebpf_rule["dst_ip"] = struct.unpack("!I", socket.inet_aton(addr))[0]
                ebpf_rule["match_mask"] |= MATCH_DST_IP
                if val is None:
                    ebpf_rule["invert_mask"] |= MATCH_DST_IP  # pragma: no cover

        # proto
        val = rule.get("proto")
        not_val = rule.get("!proto")
        if val is not None or not_val is not None:
            proto = (val if val is not None else not_val).lower()
            ebpf_rule["proto"] = PROTO_MAP.get(proto, 0)
            if ebpf_rule["proto"] != 0:
                ebpf_rule["match_mask"] |= MATCH_PROTO
                if val is None:
                    ebpf_rule["invert_mask"] |= MATCH_PROTO

        # sport
        val = rule.get("sport")
        not_val = rule.get("!sport")
        if val is not None or not_val is not None:
            ebpf_rule["src_port"] = int(val if val is not None else not_val)
            ebpf_rule["match_mask"] |= MATCH_SRC_PORT
            if val is None:
                ebpf_rule["invert_mask"] |= MATCH_SRC_PORT  # pragma: no cover

        # dport
        val = rule.get("dport")
        not_val = rule.get("!dport")
        if val is not None or not_val is not None:
            ebpf_rule["dst_port"] = int(val if val is not None else not_val)
            ebpf_rule["match_mask"] |= MATCH_DST_PORT
            if val is None:
                ebpf_rule["invert_mask"] |= MATCH_DST_PORT

        # direction
        val = rule.get("direction")
        not_val = rule.get("!direction")
        if val is not None or not_val is not None:
            direction = val if val is not None else not_val
            if direction == "inbound":
                ebpf_rule["direction"] = 1
            elif direction == "outbound":
                ebpf_rule["direction"] = 2
            ebpf_rule["match_mask"] |= MATCH_DIRECTION
            if val is None:
                ebpf_rule["invert_mask"] |= MATCH_DIRECTION  # pragma: no cover

        # loopback
        val = rule.get("loopback")
        not_val = rule.get("!loopback")
        if val is not None or not_val is not None:
            if val is not None:
                ebpf_rule["loopback"] = 1 if val else 0
            else:
                ebpf_rule["loopback"] = 0 if not_val else 1
            ebpf_rule["match_mask"] |= MATCH_LOOPBACK

        # ttl
        val = rule.get("ttl")
        not_val = rule.get("!ttl")
        if val is not None or not_val is not None:
            ebpf_rule["ttl"] = int(val if val is not None else not_val)
            ebpf_rule["match_mask"] |= MATCH_TTL
            if val is None:
                ebpf_rule["invert_mask"] |= MATCH_TTL  # pragma: no cover

        # TCP Flags
        tcp_flags = 0
        tcp_mask = 0
        for flag in ["syn", "ack", "fin", "rst", "psh", "urg"]:
            flag_bit = {"fin": 0x01, "syn": 0x02, "rst": 0x04, "psh": 0x08, "ack": 0x10, "urg": 0x20}[flag]
            if flag in rule:
                tcp_mask |= flag_bit
                if rule[flag]:
                    tcp_flags |= flag_bit
            elif f"!{flag}" in rule:
                tcp_mask |= flag_bit
                if not rule[f"!{flag}"]:
                    tcp_flags |= flag_bit  # pragma: no cover

        if tcp_mask:
            ebpf_rule["tcp_flags"] = tcp_flags
            ebpf_rule["tcp_flags_mask"] = tcp_mask
            ebpf_rule["match_mask"] |= MATCH_TCP_FLAGS

        ebpf_rules.append(ebpf_rule)

    return ebpf_rules
