pydivert
^^^^^^^^

|appveyor| |codecov| |latest_release| |python_versions|

Python bindings for WinDivert_, a Windows driver that allows user-mode applications to
capture/modify/drop network packets sent to/from the Windows network stack.

Requirements
------------

- Python 2.7 or Python 3.4+ (32 or 64 bit)
- Windows Vista/7/8/10 or Windows Server 2008 (32 or 64 bit)
- Administrator Privileges

Installation
------------

You can install PyDivert by running

.. code-block:: text

    $ pip install pydivert

Starting with PyDivert 1.0.2, WinDivert_ is bundled with
PyDivert and does not need to be installed separately.


**WinDivert Version Compatibility**

=================================  ===============
PyDivert                           WinDivert
---------------------------------  ---------------
0.0.7                              1.0.x or 1.1.x
1.0.x (API-compatible with 0.0.7)  1.1.8 (bundled)
2.0.x                              1.1.8 (bundled)
2.1.x                              1.3 (bundled)
2.2.x                              2.2 (bundled)
=================================  ===============

Getting Started
---------------

PyDivert consists of two main classes: ``pydivert.WinDivert`` and ``pydivert.Packet``.
First, you usually want to create a ``WinDivert`` object to start capturing network traffic and then
call ``.recv()`` to receive the first ``Packet`` that was captured. By receiving packets, they are taken
out of the Windows network stack and will not be sent out unless you take action.
You can re-inject packets by calling ``.send(packet)``.
The following example opens a WinDivert handle, receives a single packet, prints it, re-injects it,
and then exits:

.. code-block:: python

    import pydivert

    # Capture only TCP packets to port 80, i.e. HTTP requests.
    w = pydivert.WinDivert("tcp.DstPort == 80 and tcp.PayloadLength > 0")

    w.open()  # packets will be captured from now on

    packet = w.recv()  # read a single packet
    print(packet)
    w.send(packet)  # re-inject the packet into the network stack

    w.close()  # stop capturing packets

Packets that are not matched by the ``"tcp.DstPort == 80 and tcp.PayloadLength > 0"`` filter will not be handled by WinDivert
and continue as usual. The syntax for the filter language is described in the `WinDivert documentation <https://reqrypt.org/windivert-doc.html#filter_language>`_.

Python Idioms
-------------

``pydivert.WinDivert`` instances can be used as *context managers* for capturing traffic and as (infinite) *iterators* over
packets. The following code is equivalent to the example above:

.. code-block:: python

    import pydivert

    with pydivert.WinDivert("tcp.DstPort == 80 and tcp.PayloadLength > 0") as w:
        for packet in w:
            print(packet)
            w.send(packet)
            break

Packet Modification
-------------------

``pydivert.Packet`` provides a variety of properties that can be used to access and modify the
packet's headers or payload. For example, you can browse the web on port 1234 with PyDivert:

.. code-block:: python

    import pydivert

    with pydivert.WinDivert("tcp.DstPort == 1234 or tcp.SrcPort == 80") as w:
        for packet in w:
            if packet.dst_port == 1234:
                print(">") # packet to the server
                packet.dst_port = 80
            if packet.src_port == 80:
                print("<") # reply from the server
                packet.src_port = 1234
            w.send(packet)

Try opening http://example.com:1234/ in your browser!

WinDivert supports access and modification of a variety of TCP/UDP/ICMP attributes out of the box.

.. code-block:: python

    >>> print(packet)
    Packet({'direction': <Direction.OUTBOUND: 0>,
     'dst_addr': '93.184.216.34',
     'dst_port': 443,
     'icmpv4': None,
     'icmpv6': None,
     'interface': (23, 0),
     'ipv4': {'src_addr': '192.168.86.169',
              'dst_addr': '93.184.216.34',
              'packet_len': 81},
     'ipv6': None,
     'is_inbound': False,
     'is_loopback': False,
     'is_outbound': True,
     'payload': '\x17\x03\x03\x00$\x00\x00\x00\x00\x00\x00\x02\x05\x19q\xbd\xcfD\x8a\xe3...',
     'raw': <memory at 0x028924E0>,
     'src_addr': '192.168.86.169',
     'src_port': 52387,
     'tcp': {'src_port': 52387,
             'dst_port': 443,
             'syn': False,
             'ack': True,
             'fin': False,
             'rst': False,
             'psh': True,
             'urg': False,
             'header_len': 20,
             'payload': '\x17\x03\x03\x00$\x00\x00\x00\x00\x00\x00\x02\x05\x19q\xbd\xcfD\x8a\xe3...'},
     'udp': None})

Uninstalling PyDivert
---------------------

You can uninstall PyDivert by running

.. code-block:: text

    $ pip uninstall pydivert

If the WinDivert driver is still running at that time, it will remove itself on the next reboot.

API Reference Documentation
---------------------------

The API Reference Documentation for PyDivert can be found `here <https://ffalcinelli.github.io/pydivert/>`_.

.. |appveyor| image:: https://img.shields.io/appveyor/ci/ffalcinelli/pydivert/master.svg
    :target: https://ci.appveyor.com/project/ffalcinelli/pydivert
    :alt: Appveyor Build Status

.. |codecov| image:: https://img.shields.io/codecov/c/github/ffalcinelli/pydivert/master.svg
    :target: https://codecov.io/gh/ffalcinelli/pydivert
    :alt: Coverage Status

.. |latest_release| image:: https://img.shields.io/pypi/v/pydivert.svg
    :target: https://pypi.python.org/pypi/pydivert
    :alt: Latest Version

.. |python_versions| image:: https://img.shields.io/pypi/pyversions/pydivert.svg
    :target: https://pypi.python.org/pypi/pydivert
    :alt: Supported Python versions

.. _WinDivert: https://reqrypt.org/windivert.html
