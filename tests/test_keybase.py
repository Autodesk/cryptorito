import os
import unittest
import cryptorito
import requests_mock

TEST_USER="otakup0pe"
TEST_FINGERPRINT="24dc892a65208cf24b173740c455af0097fc312e"

def load_fixture(fix):
    testdir = os.path.dirname(__file__)
    path = "%s/fixtures/keybase/%s.json" % (testdir, fix)
    handle = open(path, 'r')
    data = handle.read()
    handle.close()
    return data

class KeybaseTest(unittest.TestCase):
    def test_happy_path(self):
        with requests_mock.Mocker() as m:
            m.get(cryptorito.keybase_lookup_url(TEST_USER),
                  text=load_fixture(TEST_USER))
            keys = cryptorito.key_from_keybase(TEST_USER)
            assert keys['fingerprint'] == TEST_FINGERPRINT
