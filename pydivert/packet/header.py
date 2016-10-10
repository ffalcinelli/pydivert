import struct


class Header(object):
    def __init__(self, raw, replace):
        self._raw = raw  # type: memoryview
        self._replace = replace

    @property
    def raw(self):
        return self._raw

    @raw.setter
    def raw(self, val):
        self._raw = self._replace(val)

    def __setattr__(self, key, value):
        if key in dir(self) or key in {"_raw", "_replace"}:
            return super(Header, self).__setattr__(key, value)
        raise ValueError("AttributeError: '{}' object has no attribute '{}'".format(
            type(self).__name__,
            key
        ))


class PayloadMixin(object):
    @property
    def header_len(self):
        raise NotImplementedError()  # pragma: no cover

    @property
    def payload(self):
        return self.raw[self.header_len:].tobytes()

    @payload.setter
    def payload(self, val):
        if len(val) == len(self.payload):
            self.raw[self.header_len:] = val
        else:
            self.raw = self.raw[:self.header_len].tobytes() + val


class PortMixin(object):
    @property
    def src_port(self):
        return struct.unpack_from("!H", self.raw, 0)[0]

    @property
    def dst_port(self):
        return struct.unpack_from("!H", self.raw, 2)[0]

    @src_port.setter
    def src_port(self, val):
        self.raw[0:2] = struct.pack("!H", val)

    @dst_port.setter
    def dst_port(self, val):
        self.raw[2:4] = struct.pack("!H", val)
