pydivert 
========
[![PyPI Version](https://pypip.in/v/pydivert/badge.png)](https://crate.io/packages/pydivert)

A python binding for [WinDivert](https://github.com/basil00/Divert) driver.

Platform Support
----------------

Right now PyDivert supports  Python 2.7/3.3 and should work on each platform supported by the driver itself.

It has been tested on a Windows 7 64bit machine with Python 2.7 and Python 3.3 interpreters (both 64bit).


Warnings
--------

* Administrator privileges are required to run the API
* Windows 64bit must be in **Test Mode** to load drivers signed with untrusted certificates
* The API is still under heavy development and could receive changes in near future without any notification

Quick Start
===========

Install Windivert
-----------------

First of all, you have to install the windivert driver. You can find instructions inside [WinDivert documentation](https://github.com/basil00/Divert/wiki/WinDivert-Documentation)

Basically, you have to download the driver (version 1.0 at the moment of writing this) and sign it with a test certificate.
Follow [these instructions](https://github.com/basil00/Divert/wiki/WinDivert-Documentation#wiki-driver_signing)

As of 1.0.4 version of WinDivert there's no more need to sign the driver if you decide to use one of the binary distributions provided.

Put the `WinDivert.dll`, `WinDivert.sys`, `WinDivert.inf` and `WdfCoInstaller*.dll` into the `lib/<your_python_architecture>` folder.

I'm running a 64bit python interpreter on a 64bit Windows 7 virtual machine, so I've just copied the `amd64` folder from the [WinDivert-1.0.4-WDDK.zip](http://www.reqrypt.org/download/WinDivert-1.0.4-WDDK.zip)
file inside the `lib` directory of the project.

Anyway, your lib directory tree should should contain at least these

```
.
├── amd64
│   ├── WdfCoInstaller01009.dll
│   ├── WinDivert.dll
│   ├── WinDivert.inf
│   ├── WinDivert.lib
│   └── WinDivert.sys
├── readme
└── x86
    ├── WdfCoInstaller01009.dll
    ├── WinDivert.dll
    ├── WinDivert.inf
    ├── WinDivert.lib
    └── WinDivert.sys
```

Last step, is to enable the *Test Mode* for Windows 64bit editions

```
bcdedit.exe -set TESTSIGNING ON
```

Run `bcdedit.exe` without any parameter and check the output to see the change had actually effect. Reboot.

If all went well, you see a "Test Mode" watermark in the right down corner.

Registering the driver
----------------------

When you're done, the first call you do to `DivertOpen` (then calling to `open` on an `Handle` instance in this python api) will install the driver if not yet up and running

```python
handle = WinDivert( os.path.join(PROJECT_ROOT,"lib","WinDivert.dll")).open_handle(filter="false")
handle.close()
```

You can use also the provided `register` method which will do just the same thing

```python
WinDivert(os.path.join(PROJECT_ROOT,"lib","WinDivert.dll")).register()
```

Once installed, you don't have to use anymore the path to your DLL. The position of the `WinDivert.sys` file gets registered into the windows registry
 and if you put the `WinDivert.dll` in same path, you can get an handle by constructing a driver with no parameters

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
