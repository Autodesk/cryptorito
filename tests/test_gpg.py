import os
import unittest
from flexmock import flexmock
import subprocess
import cryptorito

TEST_KEY='AAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBB'
def key_resp(_command, stderr=None):
    testdir = os.path.dirname(__file__)
    path = "%s/fixtures/gpg/key_list" % (testdir)
    return open(path, 'r').read()

def key_blank(_command, stderr=None):
    return ''

class HasKeys(unittest.TestCase):
    def test_happypath(self):
        flexmock(subprocess) \
            .should_receive('check_output') \
            .replace_with(key_resp)

        assert(cryptorito.has_gpg_key(TEST_KEY))

    def test_unhappypath(self):
        flexmock(subprocess) \
            .should_receive('check_output') \
            .replace_with(key_blank)

        self.assertFalse(cryptorito.has_gpg_key(TEST_KEY))
