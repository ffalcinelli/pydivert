import socket

import pydivert
from hypothesis import given, example
from hypothesis.strategies import binary
from pydivert import util

ipv4_hdr = util.fromhex("45200028fa8d40002906368b345ad4f0c0a856a4")
ipv6_hdr = util.fromhex("600d684a00280640fc000002000000020000000000000001fc000002000000010000000000000001")


def p(raw):
    return pydivert.Packet(raw, (0, 0), pydivert.Direction.OUTBOUND)


@given(raw=binary(0, 500, 1600))
@example(raw=b'`\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
def test_fuzz(raw):
    assert repr(p(raw))
    assert repr(p(ipv4_hdr + raw))
    assert repr(p(ipv6_hdr + raw))


def test_ipv6_tcp():
    raw = util.fromhex("600d684a007d0640fc000002000000020000000000000001fc000002000000010000000000000001a9a0"
                       "1f90021b638dba311e8e801800cfc92e00000101080a801da522801da522474554202f68656c6c6f2e74"
                       "787420485454502f312e310d0a557365722d4167656e743a206375726c2f372e33382e300d0a486f7374"
                       "3a205b666330303a323a303a313a3a315d3a383038300d0a4163636570743a202a2f2a0d0a0d0a")
    x = p(raw)
    assert x.address_family == socket.AF_INET6
    assert x.protocol[0] == pydivert.Protocol.TCP
    assert x.src_addr == "fc00:2:0:2::1"
    assert x.src_port == 43424
    assert x.dst_addr == "fc00:2:0:1::1"
    assert x.dst_port == 8080
    assert x.payload == (
        b"GET /hello.txt HTTP/1.1\r\n"
        b"User-Agent: curl/7.38.0\r\n"
        b"Host: [fc00:2:0:1::1]:8080\r\n"
        b"Accept: */*\r\n\r\n"
    )


def test_ipv4_udp():
    raw = util.fromhex("4500004281bf000040112191c0a82b09c0a82b01c9dd0035002ef268528e010000"
                       "01000000000000013801380138013807696e2d61646472046172706100000c0001")
    x = p(raw)
    assert x.address_family == socket.AF_INET
    assert x.protocol[0] == pydivert.Protocol.UDP
    assert x.src_addr == "192.168.43.9"
    assert x.src_port == 51677
    assert x.dst_addr == "192.168.43.1"
    assert x.dst_port == 53
    assert x.payload == util.fromhex("528e01000001000000000000013801380138013807696e2d61646472046172706100000c0001")
