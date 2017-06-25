"""This module is a whitelist for vulture"""
from vulture.whitelist import Whitelist
from cryptorito import has_gpg_key, import_gpg_key, \
    encrypt, decrypt, key_from_keybase

# https://github.com/jendrikseipp/vulture/blob/master/vulture/whitelists/stdlib.py
whitelist_cryptorito = Whitelist()
whitelist_cryptorito.has_gpg_key = has_gpg_key
whitelist_cryptorito.import_gpg_key = import_gpg_key
whitelist_cryptorito.decrypt = decrypt
whitelist_cryptorito.encrypt = encrypt
whitelist_cryptorito.key_from_keybase = key_from_keybase
