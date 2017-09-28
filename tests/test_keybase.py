import os
import unittest
import cryptorito
from flexmock import flexmock
import requests_mock

TEST_USER="otakup0pe"
TEST_FINGERPRINT="24dc892a65208cf24b173740c455af0097fc312e"

def mock_gpg_vsn(_command, stderr=None):
    return 'blah blah 2.1.10 blah\nblah'

def load_fixture(fix):
    testdir = os.path.dirname(__file__)
    path = "%s/fixtures/keybase/%s.json" % (testdir, fix)
    handle = open(path, 'r')
    data = handle.read()
    handle.close()
    return data

def mock_gpg_location(_command, stderr=None):
    return '/usr/local/bin/gpg2'

class KeybaseTest(unittest.TestCase):
    def test_happy_path(self):
        with requests_mock.Mocker() as m:
            m.get(cryptorito.keybase_lookup_url(TEST_USER),
                  text=load_fixture(TEST_USER))
            keys = cryptorito.key_from_keybase(TEST_USER)
            assert keys['fingerprint'] == TEST_FINGERPRINT
