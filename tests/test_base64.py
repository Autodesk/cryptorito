import unittest
from cryptorito import is_base64, portable_b64encode, \
    portable_b64decode, polite_string

class StringTests(unittest.TestCase):
    ghost_emoji = portable_b64decode('8J+Ruwo=')
    some_binary = portable_b64decode('uRo/OptvvkT790yaPjql5OItfFUBSM2tM42QJkPM7qvMTn4tQClPjB6mpdSFDtyzuqGVrMGaHRKv7XuzlZPpWGbVzlCjIvN0nOUiBXSQsockEJwCwIaiwm/xxWSE9+P2zWdqt1J/Iuwv6Rq60qpMRTqWNJD5dDzbw4VdDQhxzgK4zN2Er+JQQqQctsj1XuM8xJtzBQsozt5ZCJso4/jsUsWrFgHPp5nu4whuT7ZSgthsGz+NXo1f6v4njJ705ZMjLW0zdnkx/14E8qGJCsDs8pCkekDn+K4gTLfzZHga/du8xtN6e/X97K2BbdVC8Obz684wnqdHLWc+bNNso+5XFtQbFbK6vBtGtZNmBeiVBo594Zr5xRxFPSfOHIKz0jB4U5He7xgh2C7AFh2SCy4fW1fwC5XxQoz1pRSiFTRbUr/dMHMn0ZaspVYUNPdZccM4xj8ip5k4fXVRTKFF1qEiFGohcfLdabCBXAkckOmGogdN0swOpoiNEohYksW0bkof89q1aRJl6tM9E2spH62XZXDmQFHIdxFFHP6zAl2t7zGB2vxDCpLgQg3l8RytryMfDR7MXXXy2kbhtFpIl45gFl/8u+aOc7fP4dLxacCbJNz3cO3iMXIPytwiaq5HJbgQ6ZgeGjZBniTCRLwRpOv3l3GRsLstdRJSk2KP+kwY9Tk=')

    def test_is_base64(self):
        assert is_base64(portable_b64encode("foo"))
        assert is_base64(portable_b64encode(self.some_binary))
        assert is_base64(portable_b64encode(self.ghost_emoji))
        self.assertFalse(is_base64("foo"))
        self.assertFalse(is_base64("2454"))
        self.assertFalse(is_base64("1234"))

    def test_happy_path(self):
        print("AAAA %s" % portable_b64decode(portable_b64encode("foo")))
        assert polite_string(portable_b64decode(portable_b64encode("foo"))) == "foo"
