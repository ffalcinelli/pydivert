import subprocess
from ctypes import create_string_buffer, byref, c_uint64, c_uint

from pydivert import windivert_dll
from pydivert.consts import Layer, Direction
from pydivert.packet import Packet

DEFAULT_PACKET_BUFFER_SIZE = 1500


class WinDivert(object):
    """
    An handle object got from a WinDivert DLL.
    """

    def __init__(self, filter="true", layer=Layer.NETWORK, priority=0, flags=0):
        self._handle = None
        self._filter = filter.encode()
        self._layer = layer
        self._priority = priority
        self._flags = flags

    def __repr__(self):
        return '<WinDivert state="{}" filter="{}" layer="{}" priority="{}" flags="{}" />'.format(
            "open" if self._handle is not None else "closed",
            self._filter.decode(),
            self._layer,
            self._priority,
            self._flags
        )

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()

    def __iter__(self):
        return self

    def __next__(self):
        return self.recv()

    @classmethod
    def register(cls):
        """
        An utility method to register the driver the first time.
        It is usually not required to call this function, as WinDivert will register itself when opening a handle.
        """
        with cls("false"):
            pass

    @staticmethod
    def is_registered():
        """
        Check if an entry exist in windows registry.
        """
        return subprocess.call("sc query WinDivert1.1", stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

    @classmethod
    def unregister(self):
        """
        Unregisters the WinDivert service.
        It is usually not required to call this function as WinDivert will remove itself automatically after running.
        This function only requests a service stop, which may not be processed immediately if there are still open
        handles.
        """
        subprocess.check_call("sc stop WinDivert1.1", stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def open(self):
        """
        Opens a WinDivert handle for the given filter.
        Unless otherwise specified by flags, any packet that matches the filter will be diverted to the handle.
        Diverted packets can be read by the application with receive().

        The remapped function is WinDivertOpen:

        HANDLE WinDivertOpen(
            __in const char *filter,
            __in WINDIVERT_LAYER layer,
            __in INT16 priority,
            __in UINT64 flags
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_open
        """
        if self.is_open:
            raise RuntimeError("WinDivert handle is already open.")
        self._handle = windivert_dll.WinDivertOpen(self._filter, self._layer, self._priority, self._flags)

    @property
    def is_open(self):
        return bool(self._handle)

    def close(self):
        """
        Closes the handle opened by open().

        The remapped function is:

        BOOL WinDivertClose(
            __in HANDLE handle
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_close
        """
        if not self.is_open:
            raise RuntimeError("WinDivert handle is not open.")
        windivert_dll.WinDivertClose(self._handle)
        self._handle = None

    def recv(self, bufsize=DEFAULT_PACKET_BUFFER_SIZE):
        """
        Receives a diverted packet that matched the filter passed to the handle constructor.
        The return value is a pair (raw_packet, meta) where raw_packet is the data read by the handle, and meta contains
        the direction and interface indexes.
        The received packet is guaranteed to match the filter.

        The remapped function is WinDivertRecv:

        BOOL WinDivertRecv(
            __in HANDLE handle,
            __out PVOID pPacket,
            __in UINT packetLen,
            __out_opt PWINDIVERT_ADDRESS pAddr,
            __out_opt UINT *recvLen
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_recv
        """
        packet = create_string_buffer(bufsize)
        address = windivert_dll.WinDivertAddress()
        recv_len = c_uint(0)
        windivert_dll.WinDivertRecv(self._handle, packet, bufsize, byref(address), byref(recv_len))
        return Packet(
            packet[:recv_len.value],
            (address.IfIdx, address.SubIfIdx),
            Direction(address.Direction)
        )

    def send(self, packet):
        """
        Injects a packet into the network stack. Recalculates the checksum before sending.
        The return value is the number of bytes actually sent.

        The injected packet may be one received from receive(), or a modified version, or a completely new packet.
        Injected packets can be captured and diverted again by other WinDivert handles with lower priorities.

        The remapped function is DivertSend:

        BOOL WinDivertSend(
            __in HANDLE handle,
            __in PVOID pPacket,
            __in UINT packetLen,
            __in PWINDIVERT_ADDRESS pAddr,
            __out_opt UINT *sendLen
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_send
        """
        packet.recalculate_checksums()

        address = windivert_dll.WinDivertAddress()
        address.IfIdx, address.SubIfIdx = packet.interface
        address.Direction = packet.direction

        send_len = c_uint(0)
        windivert_dll.WinDivertSend(self._handle, packet.raw, len(packet.raw), byref(address), byref(send_len))
        return send_len

    def get_param(self, name):
        """
        Gets a WinDivert parameter. See WinDivert DivertSetParam() for the list of parameters.

        The remapped function is DivertGetParam:

        BOOL WinDivertGetParam(
            __in HANDLE handle,
            __in WINDIVERT_PARAM param,
            __out UINT64 *pValue
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_get_param
        """
        value = c_uint64(0)
        windivert_dll.WinDivertGetParam(self._handle, name, byref(value))
        return value.value

    def set_param(self, name, value):
        """
        Sets a WinDivert parameter.

        The remapped function is DivertSetParam:

        BOOL WinDivertSetParam(
            __in HANDLE handle,
            __in WINDIVERT_PARAM param,
            __in UINT64 value
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_set_param
        """
        return windivert_dll.WinDivertSetParam(self._handle, name, value)
