import ctypes


class WinDivertAddress(ctypes.Structure):
    """
    Ctypes Structure for WINDIVERT_ADDRESS.
    The WINDIVERT_ADDRESS structure represents the "address" of a captured or injected packet.
    The address includes the packet's network interfaces and the packet direction.

    typedef struct
    {
        UINT32 IfIdx;
        UINT32 SubIfIdx;
        UINT8  Direction;
    } WINDIVERT_ADDRESS, *PWINDIVERT_ADDRESS;

    Fields:

        - IfIdx: The interface index on which the packet arrived (for inbound packets),
          or is to be sent (for outbound packets).
        - SubIfIdx: The sub-interface index for IfIdx.
        - Direction: The packet's direction. The possible values are
                    - WINDIVERT_DIRECTION_OUTBOUND with value 0 for outbound packets.
                    - WINDIVERT_DIRECTION_INBOUND with value 1 for inbound packets.
    """
    _fields_ = [
        ("IfIdx", ctypes.c_uint32),
        ("SubIfIdx", ctypes.c_uint32),
        ("Direction", ctypes.c_uint8),
    ]
