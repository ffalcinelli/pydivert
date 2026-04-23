# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from lark import Lark, Transformer

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
        field = str(left).lower()
        val = str(right)

        # Basic equality transpilation for iptables
        if op == "==":
            # Ports
            if field in ("tcp.dstport", "udp.dstport"):
                return [{"proto": field.split(".")[0], "dport": val}]
            if field in ("tcp.srcport", "udp.srcport"):
                return [{"proto": field.split(".")[0], "sport": val}]
            if field in ("tcp.port", "udp.port"):
                # Matches both source and destination
                proto = field.split(".")[0]
                return [{"proto": proto, "dport": val}, {"proto": proto, "sport": val}]

            # IP Addresses
            if field in ("ip.srcaddr", "ip.src", "ipv6.srcaddr", "ipv6.src"):
                return [{"srcaddr": val}]
            if field in ("ip.dstaddr", "ip.dst", "ipv6.dstaddr", "ipv6.dst"):
                return [{"dstaddr": val}]
            if field in ("ip.addr", "ipv6.addr"):
                # Matches both source and destination
                return [{"srcaddr": val}, {"dstaddr": val}]

        # For other operators, we return an empty dict to allow user-space filtering
        # while still having a basic hook if other AND conditions match.
        return [{}]

    def field_access(self, children):
        name = str(children[0]).lower()
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
        field_name = str(children[0])
        if len(children) > 1:  # pragma: no cover
            index = children[1]  # pragma: no cover
            return f"{field_name}[{index}]"  # pragma: no cover
        return field_name

    def index(self, children):
        return "".join(map(str, children))

    def value(self, children):
        return str(children[0])

    def comparison(self, children):
        return f"{children[0]} {children[1]} {children[2]}"

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
            "tcp": "packet.tcp",
            "udp": "packet.udp",
            "icmp": "packet.icmp",
            "ipv4": "packet.ipv4",
            "ipv6": "packet.ipv6",
            "inbound": "packet.is_inbound",
            "outbound": "packet.is_outbound",
            "loopback": "packet.is_loopback",
        }
        return mapping.get(field_name, "None")

    def value(self, children):
        val = str(children[0])
        # If it looks like an IP address, quote it
        if "." in val or ":" in val:
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


def transpile(filter_str):
    """
    Legacy transpile function that returns the filter string representation.
    """
    parser = Lark(WINDIVERT_GRAMMAR, start="start", parser="lalr")
    tree = parser.parse(filter_str)
    return LegacyTransformer().transform(tree)


def transpile_to_python(filter_str: str) -> str:
    """
    Parses a WinDivert filter and returns a Python expression for evaluation.
    """
    try:
        parser = Lark(WINDIVERT_GRAMMAR, start="start", parser="lalr")
        tree = parser.parse(filter_str)
        return PythonEvalTransformer().transform(tree)
    except Exception:  # pragma: no cover
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
    except Exception:  # pragma: no cover
        # Fallback to broad interception if parsing fails or filter is too complex
        return [{}]
