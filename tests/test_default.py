import os
import unittest
import cryptorito

OG_ENVIRON = os.environ.copy()

class HelperTest(unittest.TestCase):
    def tearDown(self):
        os.environ = OG_ENVIRON.copy()

    def test_without_passphrase_file(self):
        assert cryptorito.passphrase_file() == []

    def test_passphrase_file(self):
        os.environ['CRYPTORITO_PASSPHRASE_FILE'] = __file__
        assert cryptorito.passphrase_file()
