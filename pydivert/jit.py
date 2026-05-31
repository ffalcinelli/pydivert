# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import ast
import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class SafeEvaluator(ast.NodeVisitor):
    """
    A safe AST-based evaluator for packet filter expressions.
    This replaces the unsafe eval() and exec() calls.
    """

    def __init__(self, packet):
        self.packet = packet
        self.functions = {
            "AggregateField": lambda a, b: a or b,
            "len": len,
        }

    def eval(self, node):
        return self.visit(node)

    def visit_Expression(self, node):
        return self.visit(node.body)

    def visit_BinOp(self, node):
        left = self.visit(node.left)
        right = self.visit(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Div):
            return left / right
        if isinstance(node.op, ast.Mod):
            return left % right
        if isinstance(node.op, ast.BitAnd):
            return left & right
        if isinstance(node.op, ast.BitOr):
            return left | right
        if isinstance(node.op, ast.BitXor):
            return left ^ right
        if isinstance(node.op, ast.LShift):
            return left << right
        if isinstance(node.op, ast.RShift):
            return left >> right
        raise ValueError(f"Unsupported binary operator: {type(node.op)}")

    def visit_BoolOp(self, node):
        if isinstance(node.op, ast.And):
            res = None
            for v in node.values:
                res = self.visit(v)
                if not res:
                    return res
            return res
        if isinstance(node.op, ast.Or):
            res = None
            for v in node.values:
                res = self.visit(v)
                if res:
                    return res
            return res
        raise ValueError(f"Unsupported boolean operator: {type(node.op)}")

    def visit_Compare(self, node):
        import operator

        ops_map = {
            ast.Eq: operator.eq,
            ast.NotEq: operator.ne,
            ast.Lt: operator.lt,
            ast.LtE: operator.le,
            ast.Gt: operator.gt,
            ast.GtE: operator.ge,
            ast.Is: operator.is_,
            ast.IsNot: operator.is_not,
            ast.In: lambda a, b: a in b,
            ast.NotIn: lambda a, b: a not in b,
        }
        left = self.visit(node.left)
        for op, right_node in zip(node.ops, node.comparators, strict=True):
            right = self.visit(right_node)
            op_func = None
            for ast_type, func in ops_map.items():
                if isinstance(op, ast_type):
                    op_func = func
                    break

            if op_func is None:
                raise ValueError(f"Unsupported comparison operator: {type(op)}")

            if not op_func(left, right):
                return False
            left = right
        return True

    def visit_UnaryOp(self, node):
        operand = self.visit(node.operand)
        if isinstance(node.op, ast.Not):
            return not operand
        if isinstance(node.op, ast.USub):
            return -operand
        raise ValueError(f"Unsupported unary operator: {type(node.op)}")

    def visit_IfExp(self, node):
        test = self.visit(node.test)
        if test:
            return self.visit(node.body)
        else:
            return self.visit(node.orelse)

    def visit_Attribute(self, node):
        value = self.visit(node.value)
        if value is None:
            return None
        try:
            return getattr(value, node.attr)
        except AttributeError:
            return None

    def visit_Name(self, node):
        if node.id == "packet":
            return self.packet
        if node.id in self.functions:
            return self.functions[node.id]
        if node.id == "True":
            return True
        if node.id == "False":
            return False
        if node.id == "None":
            return None
        raise ValueError(f"Unsupported name: {node.id}")

    def visit_Constant(self, node):
        return node.value

    def visit_List(self, node):
        return [self.visit(elt) for elt in node.elts]

    def visit_Tuple(self, node):
        return tuple(self.visit(elt) for elt in node.elts)

    def visit_Set(self, node):
        return {self.visit(elt) for elt in node.elts}

    def visit_Subscript(self, node):
        value = self.visit(node.value)
        sl = self.visit(node.slice)
        return value[sl]

    def visit_Call(self, node):
        func = self.visit(node.func)
        args = [self.visit(arg) for arg in node.args]
        return func(*args)

    def generic_visit(self, node):
        raise ValueError(f"Unsupported node type: {type(node)}")


def compile_filter(python_expr: str) -> Callable[[Any], bool]:
    """
    Compiles a Python filter expression into a safe evaluator function.
    """
    try:
        parsed = ast.parse(python_expr, mode="eval")
    except SyntaxError as e:
        logger.error("Failed to parse filter expression: %s", e)
        return lambda packet: False

    def filter_func(packet):
        try:
            return bool(SafeEvaluator(packet).eval(parsed))
        except Exception as e:
            logger.debug("Filter evaluation failed: %s", e)
            return False

    return filter_func
