import unittest

from pydivert.models import format_structure


__author__ = 'fabio'


class ModelsTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_format_structure_raise_exc(self):
        """
        Tests the format_structure method
        """
        self.assertRaises(ValueError, format_structure, "some_obj")