import sys


class cached_property(object):
    """
    A property that is only computed once per instance and then replaces itself
    with an ordinary attribute. Deleting the attribute resets the property.
    Source: https://github.com/bottlepy/bottle/commit/fa7733e075da0d790d809aa3d2f53071897e6f76
    """

    def __init__(self, func):
        self.__doc__ = getattr(func, '__doc__')
        self.func = func

    def __get__(self, obj, cls):
        if obj is None:  # pragma: no cover
            return self
        value = obj.__dict__[self.func.__name__] = self.func(obj)
        return value


if sys.version_info < (3, 0):
    # python 3's byte indexing: b"AAA"[1] == 65
    indexbyte = lambda x: chr(x) if isinstance(x, int) else ord(x)
    # python 3's bytes.fromhex()
    fromhex = lambda x: x.decode("hex")
    PY2 = True
else:
    indexbyte = lambda x: x
    fromhex = lambda x: bytes.fromhex(x)
    PY2 = False
