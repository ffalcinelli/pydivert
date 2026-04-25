# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of either:
#
# 1) The GNU Lesser General Public License as published by the Free
#    Software Foundation, either version 3 of the License, or (at your
#    option) any later version.
#
# 2) The GNU General Public License as published by the Free Software
#    Foundation, either version 2 of the License, or (at your option)
#    any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License and the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# and the GNU General Public License along with this program.  If not,
# see <https://www.gnu.org/licenses/>.

import socket
import threading
import time

import pytest

import pydivert


def test_ipv6_traffic_class_flow_label_integration():
    """
    Integration test for IPv6 traffic_class and flow_label.
    This test sends an IPv6 UDP packet, intercepts it, modifies the header fields,
    and verifies the changes.
    """
    # This test requires Windows and admin privileges.
    # We skip it if we're not on Windows.
    import platform

    if platform.system() != "Windows":
        pytest.skip("This test requires Windows.")

    # Find a free port for UDP
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
        s.bind(("::1", 0))
        port = s.getsockname()[1]

    # Filter to capture our test packet
    filt = f"ipv6 and udp and udp.DstPort == {port}"

    captured_packets = []
    stop_event = threading.Event()

    def divert_thread_func():
        with pydivert.PyDivert(filt) as w:
            for packet in w:
                if stop_event.is_set():
                    break

                # Verify initial state (should be 0 for most OSes by default)
                # Modify traffic class and flow label
                assert packet.ipv6
                packet.ipv6.traffic_class = 0xAB
                packet.ipv6.flow_label = 0x12345

                # Store a copy for verification
                captured_packets.append(
                    {
                        "traffic_class": packet.ipv6.traffic_class,
                        "flow_label": packet.ipv6.flow_label,
                        "diff_serv": packet.ipv6.diff_serv,
                        "ecn": packet.ipv6.ecn,
                    }
                )

                # Re-inject (though we don't have a listener, this tests the setter/getter consistency)
                w.send(packet)
                break

    thread = threading.Thread(target=divert_thread_func)
    thread.start()

    # Give WinDivert a moment to start
    time.sleep(0.5)

    # Send an IPv6 UDP packet to localhost
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"test", ("::1", port))

    thread.join(timeout=2)
    stop_event.set()

    assert len(captured_packets) == 1
    cp = captured_packets[0]
    assert cp["traffic_class"] == 0xAB
    assert cp["flow_label"] == 0x12345
    assert cp["diff_serv"] == 0x2A  # 0xAB >> 2 = 10101011 >> 2 = 00101010 = 0x2A
    assert cp["ecn"] == 0x03  # 0xAB & 0x03 = 10101011 & 00000011 = 0x00000011 = 0x03
