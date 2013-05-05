Intro
=====

PyDivert aims to be a python interface to [WinDivert](https://github.com/basil00/Divert) driver.

Platform Support
----------------

Right now PyDivert supports those platforms supported by the driver itself

It should work with Python 2.7/3.3 on Windows Vista, 7, 8. I've tested only on Windows7 64bit.
Plans are to support Divert Sockets on BSD-like systems (such as OSX) and similar for linux.

Warnings
--------

* Administrator privileges are required to run the API
* Windows 64bit must be in **Test Mode** to load drivers signed with untrusted certificates
* The API is still under heavy development and could receive changes in near future without any notification

Quick Start
===========

Install Windivert
-----------------

First of all, you have to install the windivert driver. You can find instruction at https://github.com/basil00/Divert/wiki/WinDivert-Documentation

Basically, you have to download the driver (version 1.0 at the moment of writing this) and sign it with a test certificate. Follow these instructions https://github.com/basil00/Divert/wiki/WinDivert-Documentation#wiki-driver_signing

Put the `WinDivert.dll`, `WinDivert.sys`, `WinDivert.inf` and `WdfCoInstaller*.dll` into the `lib/<your_python_architecture>` folder.

I'm running a 64bit python interpreter on a 64bit Windows 7 virtual machine, so I've copied my files into `lib/amd64`.

Anyway, your lib directory tree should be something similar to this

```
.
├── amd64
│   ├── readme
│   ├── WdfCoInstaller01009.dll
│   ├── WinDivert.dll
│   ├── WinDivert.inf
│   ├── WinDivert.lib
│   └── WinDivert.sys
├── readme
└── x86
    ├── readme
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
handle = WinDivert( os.path.join(PROJECT_ROOT,"lib","WinDivert.dll")).open_handle(filter="true")
```

Once installed, you don't have to use anymore the path to your DLL. The position of the `WinDivert.sys` file gets registered into the windows registry
 and if you put beside it the `WinDivert.dll` you can get an handle by constructing a driver with no parameters

```python
handle = WinDivert().open_handle(filter="true")
```

Using an Handle instance as a context manager
---------------------------------------------

You may access the driver for your python code by using the following example which intercept and resend the telnet traffic:

```python
driver = WinDivert("C:\PyDivert\WinDivert.dll")
with Handle(driver, filter="outbound and tcp.DstPort == 23", priority=1000) as handle:
    while True:
        raw_packet, metadata = handle.receive()
        captured_packet = driver.parse_packet(raw_packet)
        print(captured_packet)
        handle.send(raw_packet, metadata)
```

If the driver is already registered you can avoid the explicit instance of `WinDivert` class

```python
with Handle(filter="outbound and tcp.DstPort == 23", priority=1000) as handle:
    while True:
        raw_packet, metadata = handle.receive()
        captured_packet = handle.driver.parse_packet(raw_packet)
        print(captured_packet)
        handle.send(raw_packet, metadata)
```

Checkout the test suite for examples of usage.

Any feedback is more than welcome!

TODOs
-----

1. Packet modification and reinjection
2. Support for other platforms, at least OSX and linux
3. May be a good idea to delegate all the WinDivert methods to Handle instances


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
