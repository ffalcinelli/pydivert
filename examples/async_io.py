# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import ctypes

import pydivert
from pydivert.windivert_dll import Overlapped, windll

# Windows API constants
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0


def main():
    """
    Detailed example showing how to use WinDivert asynchronous functions
    with Windows Overlapped I/O.
    """

    # 1. Open a WinDivert handle. All handles in WinDivert 2.2+ are overlapped by default.
    # We use a filter that matches all traffic ("true").
    print("Opening WinDivert handle...")
    with pydivert.WinDivert("true") as w:
        # 2. Create a Windows event object.
        # This event will be signaled by the Windows kernel when the I/O operation completes.
        event = windll.kernel32.CreateEventW(None, False, False, None)
        if not event:
            raise ctypes.WinError()

        try:
            # 3. Initialize the Overlapped structure and link our event to it.
            overlapped = Overlapped()
            overlapped.hEvent = event

            print("Starting asynchronous receive operation...")

            # 4. Initiate an asynchronous receive operation using recv_ex().
            # If the operation cannot be completed immediately (which is usually the case),
            # it will return None, and ERROR_IO_PENDING will be handled internally.
            packet = w.recv_ex(overlapped=overlapped)

            if packet is None:
                print("Operation is pending. You can do other work here...")

                # 5. Wait for the operation to complete.
                # In a real application, you might use a loop or an event-driven framework (like asyncio).
                # Here we simply wait for the event to be signaled.
                result = windll.kernel32.WaitForSingleObject(event, INFINITE)

                if result == WAIT_OBJECT_0:
                    print("I/O completed! Extracting packet data...")

                    # 6. Once the event is signaled, the buffers provided to the kernel
                    # (which are stored inside our 'overlapped' object by PyDivert)
                    # now contain the captured packet data.
                    # We can manually reconstruct the Packet object:
                    captured_packet = pydivert.Packet(
                        memoryview(overlapped._packet_buffer)[: overlapped._recv_len.value],
                        (overlapped._address.Network.IfIdx, overlapped._address.Network.SubIfIdx),
                        pydivert.Direction.OUTBOUND if overlapped._address.Outbound else pydivert.Direction.INBOUND,
                        timestamp=overlapped._address.Timestamp,
                    )
                    print(f"Successfully captured packet: {captured_packet}")

                    # 7. Asynchronously send the packet back (inject it).
                    # We reuse the same overlapped structure and event.
                    print("Sending packet back asynchronously...")
                    send_result = w.send_ex(captured_packet, overlapped=overlapped)

                    if send_result is None:
                        print("Send operation pending...")
                        windll.kernel32.WaitForSingleObject(event, INFINITE)
                        print("Send completed!")
                    else:
                        print(f"Sent {send_result} bytes immediately.")

            else:
                print(f"Packet captured immediately: {packet}")

        finally:
            # Always close the event handle to avoid leaks.
            windll.kernel32.CloseHandle(event)


if __name__ == "__main__":
    # This example only works on Windows with Administrator privileges.
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
        print("Note: This example requires Windows and Administrator privileges.")
