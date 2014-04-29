__author__ = 'fabio'


class DriverNotRegisteredException(Exception):
    def __init__(self, message="Driver is not registered"):
        super(DriverNotRegisteredException, self).__init__(self, message)


class MethodUnsupportedException(Exception):
    def __init__(self, message="The method is not supported in this driver version"):
        super(MethodUnsupportedException, self).__init__(self, message)


class AsyncCallFailedException(Exception):
    def __init__(self, message="AsyncCall could not be run"):
        super(AsyncCallFailedException, self).__init__(self, message)


class FutureConsumedException(Exception):
    def __init__(self, message="The future called has no more data"):
        super(FutureConsumedException, self).__init__(self, message)