__author__ = 'fabio'


class DriverNotRegisteredException(Exception):
    def __init__(self, message="Driver is not registered"):
        super(DriverNotRegisteredException, self).__init__(self, message)
