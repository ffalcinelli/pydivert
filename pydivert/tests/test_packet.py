import socket

import pydivert
from hypothesis import given, example
from hypothesis.strategies import binary
from pydivert import util


def p(raw):
    return pydivert.Packet(raw, (0, 0), pydivert.Direction.OUTBOUND)


ipv4_hdr = util.fromhex("45200028fa8d40002906368b345ad4f0c0a856a4")
ipv6_hdr = util.fromhex("600d684a00280640fc000002000000020000000000000001fc000002000000010000000000000001")


@given(raw=binary(0, 500, 1600))
@example(raw=b'`\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
def test_fuzz(raw):
    assert repr(p(raw))
    assert repr(p(ipv4_hdr + raw))
    assert repr(p(ipv6_hdr + raw))


def test_ipv6_tcp():
    raw = util.fromhex("600d684a007d0640fc000002000000020000000000000001fc000002000000010000000000000001a9a01f90021b638"
                       "dba311e8e801800cfc92e00000101080a801da522801da522474554202f68656c6c6f2e74787420485454502f312e31"
                       "0d0a557365722d4167656e743a206375726c2f372e33382e300d0a486f73743a205b666330303a323a303a313a3a315"
                       "d3a383038300d0a4163636570743a202a2f2a0d0a0d0a")
    x = p(raw)
    assert x.address_family == socket.AF_INET6
    assert x.protocol[0] == pydivert.Protocol.TCP
    assert x.src_addr == "fc00:2:0:2::1"
    assert x.dst_addr == "fc00:2:0:1::1"
    assert x.src_port == 43424
    assert x.dst_port == 8080
    assert x.icmp_type is None
    assert x.icmp_code is None
    assert x.payload == (
        b"GET /hello.txt HTTP/1.1\r\n"
        b"User-Agent: curl/7.38.0\r\n"
        b"Host: [fc00:2:0:1::1]:8080\r\n"
        b"Accept: */*\r\n\r\n"
    )


def test_ipv4_udp():
    raw = util.fromhex("4500004281bf000040112191c0a82b09c0a82b01c9dd0035002ef268528e01000001000000000000013801380138013"
                       "807696e2d61646472046172706100000c0001")
    x = p(raw)
    assert x.address_family == socket.AF_INET
    assert x.protocol[0] == pydivert.Protocol.UDP
    assert x.src_addr == "192.168.43.9"
    assert x.dst_addr == "192.168.43.1"
    assert x.src_port == 51677
    assert x.dst_port == 53
    assert x.icmp_type is None
    assert x.icmp_code is None
    assert x.payload == util.fromhex("528e01000001000000000000013801380138013807696e2d61646472046172706100000c0001")


def test_icmp_ping():
    raw = util.fromhex("4500005426ef0000400157f9c0a82b09080808080800bbb3d73b000051a7d67d000451e408090a0b0c0d0e0f1011121"
                       "31415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
    x = p(raw)
    assert x.address_family == socket.AF_INET
    assert x.protocol[0] == pydivert.Protocol.ICMP
    assert x.src_addr == "192.168.43.9"
    assert x.dst_addr == "8.8.8.8"
    assert x.src_port is None
    assert x.dst_port is None
    assert x.icmp_type == 8
    assert x.icmp_code == 0
    assert x.payload == util.fromhex("d73b000051a7d67d000451e408090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232"
                                     "425262728292a2b2c2d2e2f3031323334353637")


def test_icmpv6_unreachable():
    raw = util.fromhex("6000000000443a3d3ffe05010410000002c0dffffe47033e3ffe050700000001020086fffe0580da010413520000000"
                       "060000000001411013ffe050700000001020086fffe0580da3ffe05010410000002c0dffffe47033ea07582a40014cf"
                       "470a040000f9c8e7369d250b00")
    x = p(raw)
    assert x.address_family == socket.AF_INET6
    assert x.protocol[0] == pydivert.Protocol.ICMPV6
    assert x.src_addr == "3ffe:501:410:0:2c0:dfff:fe47:33e"
    assert x.dst_addr == "3ffe:507:0:1:200:86ff:fe05:80da"
    assert x.src_port is None
    assert x.dst_port is None
    assert x.icmp_type == 1
    assert x.icmp_code == 4
    assert x.payload == util.fromhex("0000000060000000001411013ffe050700000001020086fffe0580da3ffe05010410000002c0dffff"
                                     "e47033ea07582a40014cf470a040000f9c8e7369d250b00")
