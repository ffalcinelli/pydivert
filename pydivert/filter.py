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
    A transformer that converts the WinDivert filter to a specific backend representation.
    """
    def __init__(self, backend="bpf"):
        self.backend = backend

    def true_val(self, _):
        return "true"
    def false_val(self, _):
        return "false"
    def field_access(self, children):
        field_name = str(children[0])
        if len(children) > 1:
            index = children[1]
            return f"{field_name}[{index}]"
        return field_name
    def index(self, children):
        # Handle index nodes
        return "".join(map(str, children))
    def value(self, children):
        return str(children[0])
    def comparison(self, children):
        # children are [left, operator, right]
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

def transpile(filter_str, backend="bpf"):
    parser = Lark(WINDIVERT_GRAMMAR, start='start', parser='lalr')
    tree = parser.parse(filter_str)
    transformer = WinDivertTransformer(backend=backend)
    return transformer.transform(tree)
