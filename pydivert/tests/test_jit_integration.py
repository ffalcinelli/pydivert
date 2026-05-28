# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import pydivert.jit
from pydivert import Packet


def test_jit_comprehensive_evaluation():
    """
    Test all AST node visitors in jit.py to reach 100% coverage.
    """
    raw = (
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
        + b"\x00\x50\x1f\x90\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\x91\x7c\x00\x00"
    )
    packet = Packet(raw)

    # Constant, Name, and basic bool
    assert pydivert.jit.compile_filter("True")(packet) is True
    assert pydivert.jit.compile_filter("False")(packet) is False
    assert pydivert.jit.compile_filter("None")(packet) is False  # bool(None) is False

    # Attribute access
    assert pydivert.jit.compile_filter("packet.ipv4.src_addr == '127.0.0.1'")(packet) is True
    assert pydivert.jit.compile_filter("packet.tcp.src_port == 80")(packet) is True
    assert pydivert.jit.compile_filter("packet.tcp.dst_port == 8080")(packet) is True
    assert pydivert.jit.compile_filter("packet.non_existent_attr")(packet) is False

    # BinOp (Add, Sub, Mult, Div)
    assert pydivert.jit.compile_filter("1 + 2 == 3")(packet) is True
    assert pydivert.jit.compile_filter("10 - 4 == 6")(packet) is True
    assert pydivert.jit.compile_filter("3 * 4 == 12")(packet) is True
    assert pydivert.jit.compile_filter("20 / 5 == 4")(packet) is True

    # BoolOp (And, Or)
    assert pydivert.jit.compile_filter("True and True")(packet) is True
    assert pydivert.jit.compile_filter("True and False")(packet) is False
    assert pydivert.jit.compile_filter("False or True")(packet) is True
    assert pydivert.jit.compile_filter("False or False")(packet) is False

    # Compare (including chained comparisons)
    assert pydivert.jit.compile_filter("1 < 2 < 3")(packet) is True
    assert pydivert.jit.compile_filter("10 > 5 >= 5")(packet) is True
    assert pydivert.jit.compile_filter("100 >= 100")(packet) is True
    assert pydivert.jit.compile_filter("1 != 2")(packet) is True

    # UnaryOp (Not, USub)
    assert pydivert.jit.compile_filter("not False")(packet) is True
    assert pydivert.jit.compile_filter("-10 == 0 - 10")(packet) is True

    # IfExp
    assert pydivert.jit.compile_filter("'yes' if True else 'no' == 'yes'")(packet) is True
    assert pydivert.jit.compile_filter("'yes' if False else 'no' == 'no'")(packet) is True

    # Call and builtin-like functions
    assert pydivert.jit.compile_filter("len(packet.raw) == 40")(packet) is True
    assert pydivert.jit.compile_filter("AggregateField(True, False)")(packet) is True
    assert pydivert.jit.compile_filter("AggregateField(False, False)")(packet) is False

    # Error handling and unsupported nodes
    assert pydivert.jit.compile_filter("invalid + syntax")(packet) is False  # SyntaxError handled

    # Test that evaluation failures (like unsupported ops) return False
    # (SafeEvaluator.generic_visit raises ValueError, compile_filter catches it)
    assert pydivert.jit.compile_filter("1 ** 2")(packet) is False
    assert pydivert.jit.compile_filter("unknown_name")(packet) is False


def test_jit_malformed_attribute():
    packet = Packet(b"too short")
    # packet.ipv4 will be None because it's too short
    assert pydivert.jit.compile_filter("packet.ipv4.src_addr")(packet) is False
