# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import pydivert.util

def test_util_properties():
    class Fake:
        def __init__(self):
            self.raw = bytearray(10)
        
        flag = pydivert.util.flag_property("test", 0, 0x01)
        value = pydivert.util.raw_property("!H", 2)

    f = Fake()
    assert f.flag is False
    f.flag = True
    assert f.flag is True
    assert f.raw[0] == 0x01
    f.flag = False
    assert f.flag is False
    assert f.raw[0] == 0x00

    f.value = 1234
    assert f.value == 1234
    assert f.raw[2:4] == b"\x04\xd2"

def test_util_fromhex():
    assert pydivert.util.fromhex("4142") == b"AB"
