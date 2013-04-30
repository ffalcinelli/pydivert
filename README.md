Intro
=====

PyDivert aims to be a python interface to [WinDivert](https://github.com/basil00/Divert) driver.

Platform Support
----------------

Right now PyDivert supports those platforms supported by the driver itself

It should work with Python 2.7/3.3 on Windows Vista, 7, 8. I've tested only on Windows7 64bit.
Plans are to support Divert Sockets on BSD-like systems (such as OSX) and similar for linux.

Caveats
-------

Administrator privileges are required to run the API.

Quick Start
===========

You may access the driver for your python code by using the following example which intercept and resend the telnet traffic:

```python
windivert = WinDivert("C:\PyDivert\WinDivert.dll"))
with Handle(windivert, filter="outbound and tcp.DstPort == 23", priority=1000) as handle:
    while True:
        raw_packet, metadata = handle.receive()
        captured_packet = windivert.parse_packet(raw_packet)
        print(captured_packet)
        handle.send( (raw_packet, metadata) )
```

Checkout the test suite for examples of usage.

Any feedback is more than welcome!

License
=======

LGPLv3

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

TODOs
=====

1. Packet modification and reinjection
2. Support for other platforms, at least OSX and linux
