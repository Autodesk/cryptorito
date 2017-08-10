"""CLI Entrypoint"""
from __future__ import print_function
import sys
import cryptorito


def massage_keys(keys):
    """Goes through list of GPG/Keybase keys. For the keybase keys
    it will attempt to look up the GPG key"""
    m_keys = []
    for key in keys:
        if key.startswith('keybase:'):
            m_keys.append(cryptorito.key_from_keybase(key[8:])['fingerprint'])
        else:
            m_keys.append(key)

    return m_keys


def encrypt_file(src, dest, csv_keys):
    """Encrypt a file with the specific GPG keys and write out
    to the specified path"""
    keys = massage_keys(csv_keys.split(','))
    cryptorito.encrypt(src, dest, keys)


def decrypt_file(src, dest):
    """Decrypt a file and write it out to the specified path"""
    cryptorito.decrypt(src, dest)


def encrypt_var(csv_keys):
    """Encrypt what comes in from stdin and return base64
    encrypted against the specified keys, returning on stdout"""
    keys = massage_keys(csv_keys.split(','))
    data = sys.stdin.read()
    encrypted = cryptorito.encrypt_var(data, keys)
    print(cryptorito.portable_b64encode(encrypted))


def decrypt_var():
    """Decrypt what comes in from stdin (base64'd) and
    write it out to stdout"""
    encrypted = cryptorito.portable_b64decode(sys.stdin.read())
    print(cryptorito.decrypt_var(encrypted))


def has_key(key):
    """Checks to see if we actually have a key installed"""
    if not cryptorito.has_gpg_key(key):
        sys.exit(1)

    sys.exit(0)


def import_keybase(username):
    """Imports a public GPG key from Keybase"""
    public_key = cryptorito.key_from_keybase(username)
    if cryptorito.has_gpg_key(public_key['fingerprint']):
        sys.exit(2)

    cryptorito.import_gpg_key(public_key['bundle'].encode('ascii'))
    sys.exit(0)


def main():
    """My entrypoint, let me show it to you"""
    if len(sys.argv) == 5 and sys.argv[1] == "encrypt_file":
        encrypt_file(sys.argv[2], sys.argv[3], sys.argv[4])
    elif len(sys.argv) == 4 and sys.argv[1] == "decrypt_file":
        decrypt_file(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "encrypt":
        encrypt_var(sys.argv[2])
    elif len(sys.argv) == 2 and sys.argv[1] == "decrypt":
        decrypt_var()
    elif len(sys.argv) == 3 and sys.argv[1] == "has_key":
        has_key(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "import_keybase":
        import_keybase(sys.argv[2])
    else:
        sys.exit(1)
