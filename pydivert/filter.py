# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import logging
from typing import Any

from lark import Lark, Transformer

logger = logging.getLogger(__name__)


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

    def expression(self, children):
        return children[0]  # pragma: no cover

    def logic_or(self, children):
        # children is [list_of_dicts, operator, list_of_dicts, ...]
        rules = []
        for child in children:
            if isinstance(child, list):
                rules.extend(child)
        return rules

    def logic_and(self, children):
        # We want the Cartesian product of all lists of rules
        result_rules = [{}]
        for child in children:
            if not isinstance(child, list) or not child:
                continue
            new_result = []
            for existing_rule in result_rules:
                for new_rule_part in child:
                    merged = existing_rule.copy()
                    merged.update(new_rule_part)
                    new_result.append(merged)
            result_rules = new_result
        return result_rules

    def comparison(self, children):
        left, op, right = children
        # field_access for simple names might return a list of rules
        if isinstance(left, list):
            # This is unusual (e.g. "loopback == true") but we should handle it
            # For simplicity, we just extract the field name if it was a string
            return [{}]

        field = self._normalize_field_name(str(left).lower())
        val = str(right)

        # Basic equality transpilation for iptables
        if op == "==":
            rules = self._handle_port_comparison(field, val)
            if rules:
                return rules

            rules = self._handle_addr_comparison(field, val)
            if rules:
                return rules

        # For other operators, we return an empty dict to allow user-space filtering
        # while still having a basic hook if other AND conditions match.
        return [{}]

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
            res = [{"dstaddr": val}]
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
        # Other names are just strings to be used in comparisons
        return name

    def value(self, children):
        return str(children[0])

    def true_val(self, _):
        return {}  # pragma: no cover

    def false_val(self, _):
        return {"false": True}  # pragma: no cover

    def parenthesized(self, children):
        return children[0]

    def not_expr(self, children):
        # 'NOT' is hard to transpile to simple firewall rules for complex cases
        return {}  # pragma: no cover


class LegacyTransformer(Transformer):
    """
    Converts AST back to WinDivert filter string (used for testing/legacy).
    """

    def true_val(self, _):
        return "true"

    def false_val(self, _):
        return "false"

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
        return "".join(map(str, children))

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
                proto = field.split(".")[0]
                return f"({proto}.SrcAddr == {val} || {proto}.DstAddr == {val})"
            if field in ("tcp.port", "udp.port"):
                proto = field.split(".")[0]
                return f"({proto}.SrcPort == {val} || {proto}.DstPort == {val})"

        if " " in val:
            val = f'"{val}"'
        return f"{left} {op} {val}"

    def logic_and(self, children):
        return " && ".join(map(str, children))

    def logic_or(self, children):
        return " || ".join(map(str, children))

    def not_expr(self, children):
        return f"!({children[0]})"

    def ternary(self, children):
        return f"({children[0]} ? {children[1]} : {children[2]})"

    def parenthesized(self, children):
        return f"({children[0]})"

    def expression(self, children):
        return str(children[0])


class PythonEvalTransformer(Transformer):
    """
    Converts AST to a Python expression that can be evaluated with a packet.
    """

    def true_val(self, _):
        return "True"

    def false_val(self, _):
        return "False"

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
        if "." in field_name:
            header, field = field_name.split(".", 1)
            # Many WinDivert fields are lowercase in pydivert
            return f"packet.{header}.{field}"

        return f"packet.{field_name}"

    def value(self, children):
        val = str(children[0])
        # If it looks like an IP address, quote it.
        # Numbers should not be quoted.
        if "." in val or ":" in val:
            # Don't quote if already quoted or if it's a number
            try:
                float(val)
                return val
            except ValueError:
                return f"'{val}'"
        return val

    def comparison(self, children):
        return f"({children[0]} {children[1]} {children[2]})"

    def logic_and(self, children):
        # filter out operators
        parts = [str(c) for c in children if str(c) not in ("&&", "and")]
        return "(" + " and ".join(parts) + ")"

    def logic_or(self, children):
        # filter out operators
        parts = [str(c) for c in children if str(c) not in ("||", "or")]
        return "(" + " or ".join(parts) + ")"

    def not_expr(self, children):
        return f"(not {children[0]})"

    def ternary(self, children):
        return f"({children[1]} if {children[0]} else {children[2]})"

    def parenthesized(self, children):
        return f"({children[0]})"

    def expression(self, children):
        return str(children[0])


def normalize_filter(filter_str: str) -> str:
    """
    Normalizes a WinDivert filter string by expanding aggregate fields.
    """
    try:
        parser = Lark(WINDIVERT_GRAMMAR, start="start", parser="lalr")
        tree = parser.parse(filter_str)
        return LegacyTransformer().transform(tree)
    except Exception as e:
        logger.debug("Filter normalization failed: %s", e)
        return filter_str


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
    except Exception as e:  # pragma: no cover
        # Fallback to broad interception if parsing fails or filter is too complex
        logger.debug("Transpilation to rules failed: %s", e)
        return [{}]


def transpile_to_ebpf(filter_str: str) -> list[dict[str, Any]]:
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

    try:
        rules = transpile_to_rules(filter_str)
        ebpf_rules = []

        for rule in rules:
            ebpf_rule = {
                "src_ip": 0,
                "dst_ip": 0,
                "src_port": 0,
                "dst_port": 0,
                "proto": 0,
                "match_mask": 0,
            }

            if "srcaddr" in rule:
                ebpf_rule["src_ip"] = struct.unpack("I", socket.inet_aton(rule["srcaddr"]))[0]
                ebpf_rule["match_mask"] |= MATCH_SRC_IP
            if "dstaddr" in rule:
                ebpf_rule["dst_ip"] = struct.unpack("I", socket.inet_aton(rule["dstaddr"]))[0]
                ebpf_rule["match_mask"] |= MATCH_DST_IP
            if "sport" in rule:
                ebpf_rule["src_port"] = int(rule["sport"])
                ebpf_rule["match_mask"] |= MATCH_SRC_PORT
            if "dport" in rule:
                ebpf_rule["dst_port"] = int(rule["dport"])
                ebpf_rule["match_mask"] |= MATCH_DST_PORT
            if "proto" in rule:
                ebpf_rule["proto"] = PROTO_MAP.get(rule["proto"].lower(), 0)
                if ebpf_rule["proto"] != 0:
                    ebpf_rule["match_mask"] |= MATCH_PROTO

            ebpf_rules.append(ebpf_rule)

        return ebpf_rules
    except Exception as e:
        logger.debug("Transpilation to eBPF failed: %s", e)
        return []
