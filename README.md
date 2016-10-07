pydivert 
========

[![AppVeyor Status](https://img.shields.io/appveyor/ci/ffalcinelli/pydivert/master.svg)](https://ci.appveyor.com/project/ffalcinelli/pydivert)
[![Code Coverage](https://img.shields.io/codecov/c/github/ffalcinelli/pydivert/master.svg)](https://ci.appveyor.com/project/ffalcinelli/pydivert)
[![PyPI Version](https://img.shields.io/pypi/v/pydivert.svg)](https://pypi.python.org/pypi/pydivert)
[![Python Versions](https://img.shields.io/pypi/pyversions/pydivert.svg)](https://pypi.python.org/pypi/pydivert)


Python Bindings for [WinDivert](https://github.com/basil00/Divert).

Platform Support
----------------

Right now PyDivert supports Python 2.7/3.3/3.4 and should work on each platform supported by the driver itself.

It has been tested on a Windows 7 64bit machine with Python 2.7 and Python 3.3/3.4 interpreters (64bit).


Warnings
--------

* Administrator privileges are required to run the API
* Windows 64bit must be in **Test Mode** to load drivers signed with untrusted certificates
* The API is still under heavy development and could receive changes in near future without any notification

Quick Start
===========

Install PyDivert
----------------

To install `pydivert` simply run

```
$ pip install pydivert
```

or

```
$ python setup.py install
```

As of version `0.1` the [WinDivert](http://reqrypt.org/windivert.html) driver download is no more needed, while the latest version 1.1.8 is bundled to pydivert itself.


Uninstalling PyDivert
---------------------

Using `pip` you can uninstall the binding with
 
```
$ pip uninstall pydivert
```

WinDivert version 1.0.x
-------------------------------------------------------

The support for WinDivert 1.0.x has been dropped.


Registering the driver
----------------------

When you're done, the first call you do to `WinDivertOpen` (then calling to `open` on an `Handle` instance in this python api) will install the driver if not yet up and running

```python
handle = WinDivert( os.path.join(PROJECT_ROOT,"lib","WinDivert.dll")).open_handle(filter="false")
handle.close()
```

Once installed, you don't have to use anymore the path to your DLL and you can get an handle by constructing a driver with no parameters

```python
handle = WinDivert().open_handle(filter="true")
```

Using an Handle instance as a context manager
---------------------------------------------

You may access the driver from your python code by using the following example which intercept and resend the telnet traffic:

```python
driver = WinDivert(r"C:\PyDivert\WinDivert.dll")
with Handle(driver, filter="outbound and tcp.DstPort == 23", priority=1000) as handle:
    while True:
        raw_packet, metadata = handle.recv()
        captured_packet = driver.parse_packet(raw_packet)
        print(captured_packet)
        handle.send(raw_packet, metadata)
```

If the driver is already registered you can avoid the explicit instance of `WinDivert` class

```python
with Handle(filter="outbound and tcp.DstPort == 23", priority=1000) as handle:
    while True:
        raw_packet, metadata = handle.recv()
        captured_packet = handle.driver.parse_packet(raw_packet)
        print(captured_packet)
        handle.send(raw_packet, metadata)
```

There are a set of high level functions to avoid repeating common operations. The following snippet is perfectly equivalent to the above:

```python
with Handle(filter="outbound and tcp.DstPort == 23", priority=1000) as handle:
    while True:
        packet = handle.receive()
        print(packet)
        handle.send(packet)
```

Accessing TCP/IP header fields and modify them
----------------------------------------------

You can access the headers of a captured packet directly

```python
with Handle(filter="tcp.DstPort == 23") as handle:
    packet = handle.receive()
    if packet.tcp_hdr.Syn == 1:
        print("Captured a TCP Syn")
    handle.send(packet)
```

For address/port pairs, a `CapturedPacket` provides easy properties to translate the values into network byte order

```python
with Handle(filter="tcp.DstPort == 23") as handle:
    packet = handle.receive()
    print("{}:{}".format(packet.dst_addr,
                         packet.dst_port))
    print("{}:{}".format(packet.ipv4_hdr.DstAddr,
                         packet.tcp_hdr.DstPort))
```

will print somethig similar to

```
10.0.2.15:23
251789322:5888
```

And you can get/set those headers by simply changing the property value without worrying of underlying representation

```python
with Handle(filter="tcp.DstPort == 23 or tcp.SrcPort == 13131") as handle:
    while True:
        packet = handle.receive()
        if packet.meta.is_outbound():
            packet.dst_port = 13131
        else:
            packet.src_port = 23
        handle.send(packet)
```

Checkout the test suite for examples of usage.

Any feedback is more than welcome!

TODOs
-----

1. ~~Packet modification and reinjection~~
2. ~~Support for other platforms, at least OSX and linux~~ Discarded. These are out of scope for this binding.
3. ~~May be a good idea to delegate all the WinDivert methods to Handle instances~~
4. Clean test code. Tests should be more readable to use as usage example
5. Implement binding for Asynchronous I/O using WinDivertSendEx and WinDivertRecvEx
6. ~~Drop support for WinDivert 1.0.x~~


License
=======

LGPLv3

> This program is free software: you can redistribute it and/or modify
> it under the terms of the GNU Lesser General Public License as published by
> the Free Software Foundation, either version 3 of the License, or
> (at your option) any later version.
>
> This program is distributed in the hope that it will be useful,
> but WITHOUT ANY WARRANTY; without even the implied warranty of
> MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
> GNU Lesser General Public License for more details.
>
> You should have received a copy of the GNU Lesser General Public License
> along with this program.  If not, see <http://www.gnu.org/licenses/>.
