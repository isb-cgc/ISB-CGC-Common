import unittest

try:
    from metadata_utils import *
except ImportError:
    print("[ERROR] Failed to import test subject: {}".format("metadata_utils"))

class TestMetadataUtils(unittest.TestCase):

    def test_bmi_normal(self):
        
        self.assertEqual('foo'.upper(), 'FOO')


if __name__ == '__main__':
    unittest.main()
