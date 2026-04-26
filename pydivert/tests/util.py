# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import logging
import os
import socket
import sys

import pytest

import pydivert


def check_availability():
    """Skip the calling test if PyDivert cannot be initialized on the current platform."""
    try:
        with pydivert.PyDivert("true"):
            pass
    except (ImportError, PermissionError, OSError, RuntimeError) as e:
        if os.environ.get("GITHUB_ACTIONS") or os.environ.get("VAGRANT_VM"):
            if sys.platform == "darwin" and getattr(e, "errno", None) == 22:
                pytest.skip(f"Divert sockets are not supported on this macOS version: {e}")
            else:
                pytest.fail(f"PyDivert integration tests must run in CI, but initialization failed: {e}")
        pytest.skip(f"PyDivert not available: {e}")


def get_free_port(proto=socket.SOCK_STREAM):
    """Returns a free port on localhost for the given protocol."""
    with socket.socket(socket.AF_INET, proto) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get_scapy():
    """
    Safely imports Scapy components while suppressing warnings.
    Returns a tuple of (available, components) or skips the test if not available.
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    try:
        import scapy.all as scapy
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6

        return True, {
            "all": scapy,
            "IP": IP,
            "IPv6": IPv6,
            "TCP": TCP,
            "UDP": UDP,
            "ICMP": ICMP,
            "ICMPv6EchoRequest": ICMPv6EchoRequest,
            "Raw": scapy.Raw,
            "conf": scapy.conf,
            "sr1": scapy.sr1,
        }
    except ImportError:
        return False, {}


def require_scapy():
    """Skips the test if Scapy is not installed."""
    available, scapy_components = get_scapy()
    if not available:
        pytest.skip("Scapy not installed")
    return scapy_components
