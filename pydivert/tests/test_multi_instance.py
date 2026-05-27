# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import socket
import sys
import threading
import time

import pytest

import pydivert

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="eBPF only supported on Linux")


def test_multi_instance_chaining():
    # Instance A: High Priority (TC priority will be e.g. 100)
    # Instance B: Low Priority (TC priority will be e.g. 101)

    # We use explicit priorities to be sure of the order.
    # WinDivert: higher integer = higher execution priority.
    # Our mapping: TC priority = 30001 - WinDivert priority.
    # A: priority 1000 -> TC: 29001
    # B: priority 0    -> TC: 30001 (or higher if 30001 is taken)

    try:
        with pydivert.Divert("icmp", priority=1000) as w_a:
            with pydivert.Divert("icmp", priority=0) as w_b:
                assert w_a._impl._tc_priority < w_b._impl._tc_priority  # type: ignore

                # Send a ping to trigger capture
                # We need to send from another thread or just use a short timeout
                def send_ping():
                    time.sleep(0.5)
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                        s.sendto(b"\x08\x00\xf7\xff\x00\x00\x00\x00", ("127.0.0.1", 0))
                    except PermissionError:
                        pass  # Should have root in VM

                t = threading.Thread(target=send_ping)
                t.start()

                # Instance A should capture first
                packet_a = w_a.recv(timeout=5)
                assert packet_a is not None
                print(f"DEBUG: Instance A captured {packet_a}")

                # Instance A reinjects
                w_a.send(packet_a)
                print("DEBUG: Instance A reinjected")

                # Instance B should capture the REINJECTED packet from A
                packet_b = w_b.recv(timeout=5)

                assert packet_b is not None
                assert packet_b.raw == packet_a.raw

                # Cleanup
                t.join()
    except PermissionError:
        pytest.skip("Root privileges required")


def test_surgical_unregister():
    try:
        w = pydivert.Divert("false")
        w.open()
        assert w.is_open

        # Manually verify filter exists
        import subprocess

        output = subprocess.check_output(["sudo", "tc", "filter", "show", "dev", "lo", "ingress"]).decode()
        assert "tc_divert_ingre" in output

        # Open another unrelated filter (simulated by another Divert)
        w2 = pydivert.Divert("false", priority=-100)
        w2.open()

        # Close first handle
        w.close()

        # Unrelated filter should still exist
        output = subprocess.check_output(["sudo", "tc", "filter", "show", "dev", "lo", "ingress"]).decode()
        assert "tc_divert_ingre" in output

        # Call unregister
        pydivert.Divert.unregister()

        # ALL PyDivert filters should be gone
        output = subprocess.check_output(["sudo", "tc", "filter", "show", "dev", "lo", "ingress"]).decode()
        assert "tc_divert_ingre" not in output

        w2.close()
    except PermissionError:
        pytest.skip("Root privileges required")
