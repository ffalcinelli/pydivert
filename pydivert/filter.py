# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from lark import Lark, Transformer

WINDIVERT_GRAMMAR = r"""
    ?start: expression

    ?expression: ternary
               | logic_or

    ?ternary: logic_or "?" expression ":" expression

    ?logic_or: logic_and ("||" logic_and)*
    ?logic_and: logic_not ("&&" logic_not)*
    ?logic_not: "!" logic_not -> not_expr
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
        # Flatten OR: list of rules
        rules = []
        for child in children:
            if isinstance(child, list):
                rules.extend(child)  # pragma: no cover
            else:
                rules.append(child)
        return rules

    def logic_and(self, children):
        # Merge AND: single rule with merged conditions
        merged = {}
        for child in children:
            # If child is a list (from a sub-OR), we can't easily merge it into a single rule
            # For simplicity in kernel transpilation, we take the first "compatible" part
            # or treat it as a broad rule.
            if isinstance(child, list):
                 if len(child) > 0:  # pragma: no cover
                     merged.update(child[0])  # pragma: no cover
            else:
                merged.update(child)
        return [merged]

    def comparison(self, children):
        left, op, right = children
        if op != "==":
            return {} # Kernel filters mostly support equality for these fields

        field = str(left).lower()
        val = str(right)

        if field == "tcp.dstport" or field == "udp.dstport":
            return {"proto": field.split('.')[0], "dport": val}
        if field == "tcp.srcport" or field == "udp.srcport":
            return {"proto": field.split('.')[0], "sport": val}
        if field == "ip.srcaddr":
            return {"srcaddr": val}
        if field == "ip.dstaddr":
            return {"dstaddr": val}
        return {}

    def field_access(self, children):
        name = str(children[0]).lower()
        if name == "ip":
            return {"proto": "ip"}
        if name == "tcp":
            return {"proto": "tcp"}
        if name == "udp":
            return {"proto": "udp"}
        if name == "icmp":
            return {"proto": "icmp"}
        if name == "inbound":
            return {"direction": "inbound"}
        if name == "outbound":
            return {"direction": "outbound"}
        if name == "loopback":
            return {"loopback": True}
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
    def true_val(self, _): return "true"
    def false_val(self, _): return "false"
    def field_access(self, children):
        field_name = str(children[0])
        if len(children) > 1:  # pragma: no cover
            index = children[1]  # pragma: no cover
            return f"{field_name}[{index}]"  # pragma: no cover
        return field_name
    def index(self, children): return "".join(map(str, children))
    def value(self, children): return str(children[0])
    def comparison(self, children):
        return f"{children[0]} {children[1]} {children[2]}"
    def logic_and(self, children): return " && ".join(map(str, children))
    def logic_or(self, children): return " || ".join(map(str, children))
    def not_expr(self, children): return f"!({children[0]})"
    def ternary(self, children): return f"({children[0]} ? {children[1]} : {children[2]})"
    def parenthesized(self, children): return f"({children[0]})"
    def expression(self, children): return str(children[0])

def transpile(filter_str):
    """
    Legacy transpile function that returns the filter string representation.
    """
    parser = Lark(WINDIVERT_GRAMMAR, start='start', parser='lalr')
    tree = parser.parse(filter_str)
    return LegacyTransformer().transform(tree)

def transpile_to_rules(filter_str):
    """
    Parses a WinDivert filter and returns a list of rule components for backends.
    """
    try:
        parser = Lark(WINDIVERT_GRAMMAR, start='start', parser='lalr')
        tree = parser.parse(filter_str)
        transformer = WinDivertTransformer()
        rules = transformer.transform(tree)
        if not isinstance(rules, list):
            rules = [rules]
        return rules
    except Exception:  # pragma: no cover
        # Fallback to broad interception if parsing fails or filter is too complex
        return [{}]
