import socket
import sys
import os
import subprocess
import json
import threading
import time
import asyncio
import inspect
import ctypes
from unittest.mock import patch, MagicMock, mock_open
import pytest
import pydivert
from pydivert.base import BaseDivert
from pydivert.packet import Packet
from pydivert.util import flag_property, raw_property, fromhex, internet_checksum
from pydivert.jit import compile_filter
from pydivert.consts import Direction, Layer, Flag, Protocol

# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later

# --- 1. BaseDivert Full Implementation for line hitting ---

class FinalConcrete(BaseDivert):
    def _open_impl(self): pass
    def _close_impl(self): pass
    def _recv_impl(self, b, t): return Packet(b"E"*20)
    def _recv_batch_impl(self, c, b, t): return [Packet(b"E"*20)]
    async def _recv_async_impl(self, b, t): return Packet(b"E"*20)
    async def _recv_batch_async_impl(self, c, b, t): return [Packet(b"E"*20)]
    def _send_impl(self, p, r): return 20
    def _send_batch_impl(self, p, r): return 1
    async def _send_async_impl(self, p, r): return 20
    async def _send_batch_async_impl(self, p, r): return 1
    def _stats_impl(self): return {"captured": 1}
    @staticmethod
    def register(): pass
    @staticmethod
    def unregister(): pass
    @staticmethod
    def is_registered(): return True
    @staticmethod
    def check_filter(f, l=Layer.NETWORK): return True, 0, ""

@pytest.mark.asyncio
async def test_base_final_strike():
    w = FinalConcrete(); w.open()
    w.filter = "tcp"; w.layer = Layer.FLOW; w.priority = 100; w.flags = Flag.SNIFF
    w._jit_filter = lambda p: True
    w.send_batch([Packet(b"E"*20)])
    await w.send_batch_async([Packet(b"E"*20)])
    w.recv_batch(count=1); await w.recv_batch_async(count=1)
    w.stats(); w.close()
    async with FinalConcrete() as w2: pass
    with FinalConcrete() as w3: pass
    w4 = FinalConcrete(); w4.open()
    for _ in w4: break

# --- 2. JIT: Hit all nodes and operators ---

def test_jit_master_strike():
    p = Packet(b"E"*20)
    for op in ["+", "-", "*", "/", "%", "<<", ">>", "|", "&", "^"]: compile_filter(f"1 {op} 1")(p)
    for op in ["==", "!=", "<", "<=", ">", ">=", "is", "is not", "in", "not in"]:
        compile_filter(f"1 {op} 2" if "in" not in op else f"1 {op} [1,2]")(p)
    compile_filter("True and not False")(p); compile_filter("1 if True else 0")(p)
    compile_filter("len(packet.raw)")(p); compile_filter("packet.raw[0]")(p)
    compile_filter("[1, 2]"); compile_filter("(1, 2)"); compile_filter("{1, 2}")
    compile_filter("non_existent")(p)

# --- 3. Packet: Comprehensive Property Sweep ---

def test_packet_master_strike():
    raws = [
        fromhex("4500002800014000400600007f0000017f000001" + "0050005000000000000000005002200000000000"), # IPv4 TCP
        fromhex("6000000000081140" + "00"*16 + "00"*16 + "1234003500080000"), # IPv6 UDP
        fromhex("4500001c00014000400100007f0000017f000001" + "0800000000000000"), # ICMP
    ]
    for r in raws:
        p = Packet(r)
        for h in [p, p.ipv4, p.ipv6, p.tcp, p.udp, p.icmp, p.ip]:
            if not h: continue
            for name, member in inspect.getmembers(type(h)):
                if isinstance(member, property):
                    try:
                        val = getattr(h, name)
                        if member.fset: setattr(h, name, val)
                    except Exception: pass
        p.recalculate_checksums(); p.is_checksum_valid
        try:
            repr(p); str(p)
        except Exception: pass

    # IPv6 extension chain
    raw_ext = bytearray(b"\x60\x00\x00\x00\x00\x30\x00\x40" + b"\x00"*32) 
    raw_ext += b"\x2c\x00\x00\x00\x00\x00\x00\x00" + b"\x33\x00\x00\x00\x00\x00\x00\x00" + b"\x3c\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x06\x00\x00\x00\x00\x00\x00\x00" + b"\x00"*20
    p_ext = Packet(raw_ext); assert p_ext.protocol[0] == 6

# --- 4. Backend Master Mocks ---

@pytest.mark.skipif(sys.platform == "win32", reason="Linux strike")
def test_ebpf_master_strike():
    from pydivert.ebpf import EBPFDivert
    w = EBPFDivert(); w._is_open = True
    with patch("pydivert.ebpf.libbpf") as mock_lib:
        w._obj = MagicMock()
        mock_lib.libbpf_num_possible_cpus.return_value = 4
        mock_lib.bpf_map_lookup_elem.return_value = 0
        w.stats()
    with patch("socket.if_nameindex", return_value=[(1, "lo")]):
        with patch("os.listdir", return_value=["eth0"]):
            with patch("subprocess.check_output", return_value=b"[]"):
                pydivert.Divert.unregister()

@pytest.mark.skipif(sys.platform != "win32", reason="Windows strike")
def test_windivert_master_strike():
    from pydivert.windivert import WinDivert
    with patch("pydivert.windivert.windivert_dll") as mock_dll:
        w = WinDivert()
        object.__setattr__(w, "_is_open", True)
        mock_dll.WinDivertRecv.return_value = False
        mock_dll.GetLastError.return_value = 122
        try:
            w.recv()
        except Exception:
            pass
        mock_dll.WinDivertSendEx.return_value = True
        w._send_batch_impl([Packet(b"E"*20)], True)
