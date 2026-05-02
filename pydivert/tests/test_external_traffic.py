# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import socket
import sys
import pytest
import pydivert
from pydivert.consts import Flag

def test_external_traffic_capture():
    """
    Verifies that PyDivert can capture real external traffic.
    This test makes a DNS query to 8.8.8.8 and ensures it's intercepted.
    """
    # Filter for DNS traffic to Google's public DNS
    # Note: We use Flag.SNIFF so we don't break the system's DNS resolution
    try:
        with pydivert.Divert("udp.DstPort == 53 and ip.DstAddr == 8.8.8.8", flags=Flag.SNIFF) as w:
            # Perform a DNS lookup to trigger external traffic
            # We use a short timeout for the socket operation
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1.0)
                # DNS query for example.com (simplified)
                dns_query = b'\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
                try:
                    s.sendto(dns_query, ("8.8.8.8", 53))
                except OSError as e:
                    pytest.skip(f"Could not send external traffic: {e}")

            # Capture the packet
            try:
                packet = w.recv(timeout=5.0)
                assert packet.dst_addr == "8.8.8.8"
                assert packet.dst_port == 53
            except TimeoutError:
                pytest.fail("Failed to capture external DNS traffic. Ensure the environment has internet access.")
                
    except (PermissionError, OSError) as e:
        if "WinError 10042" in str(e) or "privileges" in str(e).lower() or "root" in str(e).lower():
             pytest.skip(f"Test requires administrator/root privileges: {e}")
        raise
    except ImportError:
        pytest.skip("Required dependencies missing.")
