import os
import unittest
import subprocess
from flexmock import flexmock
import cryptorito

def mock_gpg_vsn(_command, stderr=None):
    return 'blah blah 2.1.10 blah\nblah'

class HelperTest(unittest.TestCase):
    def setUp(self):
        self.og_environ = os.environ.copy()

    def tearDown(self):
        os.environ = self.og_environ

    def test_without_passphrase_file(self):
        assert cryptorito.passphrase_file() == []

    def test_passphrase_file(self):
        flexmock(subprocess) \
            .should_receive('check_output') \
            .replace_with(mock_gpg_vsn)
        
        os.environ['CRYPTORITO_PASSPHRASE_FILE'] = __file__
        assert cryptorito.passphrase_file()


class NotAStringHelperTest(unittest.TestCase):
    def test_happy_path(self):
        assert cryptorito.not_a_string(42)
        assert cryptorito.not_a_string(False)
        assert cryptorito.not_a_string(dict())
