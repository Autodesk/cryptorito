import os
import unittest
import cryptorito


class HelperTest(unittest.TestCase):
    def setUp(self):
        self.og_environ = os.environ.copy()

    def tearDown(self):
        os.environ = self.og_environ

    def test_without_passphrase_file(self):
        assert cryptorito.passphrase_file() == []

    def test_passphrase_file(self):
        os.environ['CRYPTORITO_PASSPHRASE_FILE'] = __file__
        assert cryptorito.passphrase_file()
