"""CLI Entrypoint"""
from __future__ import print_function
import sys
import traceback
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


def decrypt_var(passphrase=None):
    """Decrypt what comes in from stdin (base64'd) and
    write it out to stdout"""
    encrypted = cryptorito.portable_b64decode(sys.stdin.read())
    print(cryptorito.decrypt_var(encrypted, passphrase))


def has_key(key):
    """Checks to see if we actually have a key installed"""
    if not cryptorito.has_gpg_key(key):
        sys.exit(1)

    sys.exit(0)


def import_keybase(useropt):
    """Imports a public GPG key from Keybase"""
    public_key = None
    u_bits = useropt.split(':')
    username = u_bits[0]
    if len(u_bits) == 1:
        public_key = cryptorito.key_from_keybase(username)
    else:
        fingerprint = u_bits[1]
        public_key = cryptorito.key_from_keybase(username, fingerprint)

    if cryptorito.has_gpg_key(public_key['fingerprint']):
        sys.exit(2)

    cryptorito.import_gpg_key(public_key['bundle'].encode('ascii'))
    sys.exit(0)


def export_key(key_id):
    """Export a GPG key. Note this will be binary."""
    print(cryptorito.export_gpg_key(key_id))
    sys.exit(0)


def do_thing():
    """Execute command line cryptorito actions"""
    if len(sys.argv) == 5 and sys.argv[1] == "encrypt_file":
        encrypt_file(sys.argv[2], sys.argv[3], sys.argv[4])
    elif len(sys.argv) == 4 and sys.argv[1] == "decrypt_file":
        decrypt_file(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "encrypt":
        encrypt_var(sys.argv[2])
    elif len(sys.argv) == 2 and sys.argv[1] == "decrypt":
        decrypt_var()
    elif len(sys.argv) == 3 and sys.argv[1] == "decrypt":
        decrypt_var(passphrase=sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "has_key":
        has_key(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "import_keybase":
        import_keybase(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "export":
        export_key(sys.argv[2])
    else:
        print("Cryptorito testing wrapper. Not suitable for routine use.",
              file=sys.stderr)
        sys.exit(1)


def main():
    """My entrypoint, let me show it to you"""
    try:
        do_thing()
    except Exception:  # pylint: disable=broad-except
        traceback.print_exc(sys.stderr)
        sys.exit(1)
