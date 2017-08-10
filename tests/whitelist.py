"""This module is a whitelist for vulture"""
from vulture.whitelists.whitelist_utils import Whitelist
from cryptorito import has_gpg_key, import_gpg_key, \
    encrypt, decrypt, key_from_keybase, is_base64, \
    portable_b64encode, portable_b64decode, decrypt_var, \
    export_gpg_key

# https://github.com/jendrikseipp/vulture/blob/master/vulture/whitelists/stdlib.py
whitelist_cryptorito = Whitelist()
whitelist_cryptorito.has_gpg_key = has_gpg_key
whitelist_cryptorito.import_gpg_key = import_gpg_key
whitelist_cryptorito.decrypt = decrypt
whitelist_cryptorito.encrypt = encrypt
whitelist_cryptorito.key_from_keybase = key_from_keybase
whitelist_cryptorito.is_base64 = is_base64
whitelist_cryptorito.portable_b64encode = portable_b64encode
whitelist_cryptorito.portable_b64decode = portable_b64decode
whitelist_cryptorito.decrypt_var = decrypt_var
whitelist_cryptorito.export_gpg_key = export_gpg_key

# not sure why vulture whitelist aint working anymore
_foo = [whitelist_cryptorito.has_gpg_key,
        whitelist_cryptorito.import_gpg_key,
        whitelist_cryptorito.is_base64,
        whitelist_cryptorito.export_gpg_key]
