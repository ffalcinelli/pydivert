# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import socket
import threading
import time

from pydivert import PyDivert


def test_scenario_dns_blocking():
    """
    Scenario: Intercept DNS queries and drop those for a specific domain.
    """
    blocked_domain = b"blocked.example.com"
    captured_count = 0

    def dns_diverter():
        nonlocal captured_count
        try:
            with PyDivert("udp.DstPort == 53") as w:
                for packet in w:
                    if packet.payload and blocked_domain in packet.payload:
                        captured_count += 1
                        # We drop the packet by NOT sending it back
                        continue
                    w.send(packet)
        except Exception:
            pass

    t = threading.Thread(target=dns_diverter, daemon=True)
    t.start()
    time.sleep(1)

    # Try to resolve a normal domain (should work if we had a real DNS server,
    # but here we just check if the packet was forwarded or dropped).
    # Since we don't have a real DNS server, we just send a packet and check if it's captured.

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(0.5)
        # Send a "blocked" query
        s.sendto(b"query for " + blocked_domain, ("127.0.0.1", 53))

    time.sleep(1)
    # On loopback Linux, the packet might not reach the socket if no one is listening,
    # but NFQUEUE should still capture it.
    assert captured_count > 0
