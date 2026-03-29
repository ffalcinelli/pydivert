import pydivert


def modify_payload_example():
    """
    Example of how to modify the payload of a packet with a different length.
    """

    # Let's say we want to intercept TCP traffic on port 80
    # and replace "abc" with "defgh" in the payload.
    # Note: Many packets won't have "abc" at all, so we check for it.

    with pydivert.WinDivert("tcp.DstPort == 80 or tcp.SrcPort == 80") as w:
        for packet in w:
            if packet.payload and b"abc" in packet.payload:
                print(f"Original payload: {packet.payload}")

                # Replace content. This can change the length!
                # PyDivert will automatically update:
                # 1. packet.raw (resizing the bytearray)
                # 2. packet.ipv4.packet_len (IP header total length)
                # 3. packet.udp.payload_len (if it was a UDP packet)
                packet.payload = packet.payload.replace(b"abc", b"defgh")

                print(f"Modified payload: {packet.payload}")

                # IMPORTANT for TCP:
                # If you change the length of a TCP payload, you break the TCP stream.
                # All subsequent packets in this connection will have incorrect
                # sequence numbers or acknowledgment numbers.
                # To do this correctly for a full connection, you need to track
                # the sequence number offset and adjust all future packets.

                # IMPORTANT for MTU:
                # If the packet length exceeds the MTU (usually 1500 bytes),
                # you might need to fragment it manually, which is complex.
                # PyDivert's DEFAULT_PACKET_BUFFER_SIZE is now 65575 to handle
                # jumbo frames and large packets, but MTU limits still apply
                # to the physical network.
                if len(packet.raw) > 1500:
                    print("Warning: Packet exceeds standard MTU (1500 bytes)!")

            # w.send() will automatically call packet.recalculate_checksums()
            # so the IP/TCP/UDP checksums will be correct for the new length.
            w.send(packet)

if __name__ == "__main__":
    print("This example requires administrative privileges and WinDivert driver.")
    # modify_payload_example()
