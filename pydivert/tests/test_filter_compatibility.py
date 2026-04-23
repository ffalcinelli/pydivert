# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import sys

import pytest

from pydivert import PyDivert

FILTERS = [
    "true",
    "tcp",
    "udp",
    "ip",
    "icmp",
    "tcp.DstPort == 80",
    "tcp.SrcPort == 443",
    "udp.DstPort == 53",
    "udp.SrcPort == 123",
    "ip.SrcAddr == 1.2.3.4",
    "ip.DstAddr == 8.8.8.8",
    "inbound",
    "outbound",
    "tcp.DstPort == 80 or tcp.DstPort == 8080",
    "tcp.DstPort == 80 || tcp.DstPort == 443",
    "tcp.SrcPort == 1024 or tcp.SrcPort == 2048",
    "udp.DstPort == 53 or udp.DstPort == 5353",
    # Mixes
    "tcp.DstPort == 80 or udp.DstPort == 53",
    "tcp.SrcPort == 80 || udp.SrcPort == 53",
    # Spaces and Case
    "  tcp.DstPort  ==  80  ",
    "TCP.DSTPORT == 80",
    "udp.srcport == 53",
    # Parentheses (stripped by transpiler)
    "(tcp.DstPort == 80)",
    "(tcp.DstPort == 80) or (tcp.DstPort == 443)",
    "loopback",
]
UNSUPPORTED_FILTERS = [
    "tcp.PayloadLength > 0",
    "ip.Protocol == 17",  # Protocol comparison not supported yet
]


@pytest.mark.parametrize("filter_str", FILTERS)
def test_filter_compatibility_supported(filter_str):
    """
    Test that supported filters are correctly accepted by PyDivert
    on the current platform.
    """
    try:
        w = PyDivert(filter_str)
        assert w.filter == filter_str.strip()

        # Check if transpilation produced something (Linux/BSD specific)
        if sys.platform.startswith("linux"):
            rules = w._impl._parse_filter_to_iptables()
            if filter_str.lower() != "true":
                assert len(rules) > 0
        elif sys.platform.startswith("freebsd"):
            rules = w._impl._parse_filter_to_ipfw()
            assert len(rules) > 0

    except Exception as e:
        pytest.fail(f"Filter '{filter_str}' failed on {sys.platform}: {e}")


@pytest.mark.parametrize("filter_str", UNSUPPORTED_FILTERS)
def test_filter_compatibility_unsupported(filter_str):
    """
    On Linux/BSD, some filters are known to be unsupported by the transpiler.
    They should currently not raise an error during construction (they'll just
    produce no firewall rules, relying on user-space filtering), but we
    document this behavior here.
    """
    w = PyDivert(filter_str)

    if sys.platform.startswith("linux") or sys.platform.startswith("freebsd"):
        if sys.platform.startswith("linux"):
            rules = w._impl._parse_filter_to_iptables()
            # These filters should result in 0 rules currently (or at least no specific matches)
            assert len(rules) == 0 or (len(rules) == 1 and not rules[0][1])
        else:
            rules = w._impl._parse_filter_to_ipfw()
            # On FreeBSD, unsupported filter produces generic rules that protect SSH
            assert any("not dst-port 22 not src-port 22" in rule for rule in rules)
    else:
        # On Windows, WinDivert might accept some of these
        pass


if __name__ == "__main__":
    pytest.main([__file__])
