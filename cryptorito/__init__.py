"""Wrappers for GPG/Keybase functionality we need"""
from __future__ import print_function
import collections
import itertools as IT
import os
import logging
import json
from tempfile import mkstemp
import subprocess  # nosec
import requests
LOGGER = logging.getLogger()


class CryptoritoError(Exception):
    """We do not have complicated exceptions to be honest"""
    def __init__(self, message=None):
        """The only thing you can pass is a message, but
        even that is optional"""
        if message is not None:
            super(CryptoritoError, self).__init__(message)
        else:
            super(CryptoritoError, self).__init__()


def actually_flatten(iterable):
    """Flatten iterables"""
    remainder = iter(iterable)
    while True:
        first = next(remainder)
        # Python 2/3 compat
        try:
            basestring
        except NameError:
            # Python 2/3 compat
            basestring = str  # pylint: disable=W0622
        if isinstance(first, collections.Iterable) and \
           not isinstance(first, basestring):
            remainder = IT.chain(first, remainder)
        else:
            yield first


def flatten(iterable):
    """Ensure we are returning an actual list, as that's all we
    are ever going to flatten within our little domain"""
    return [x for x in actually_flatten(iterable)]


def passphrase_file():
    """Read passphrase from a file. This should only ever be
    used by our built in integration tests. At this time,
    during normal operation, only pinentry is supported for
    entry of passwords."""
    if 'CRYPTORITO_PASSPHRASE_FILE' in os.environ:
        pass_file = os.environ['CRYPTORITO_PASSPHRASE_FILE']
        if not os.path.isfile(pass_file):
            raise CryptoritoError('CRYPTORITO_PASSPHRASE_FILE is invalid')

        return ["--batch", "--passphrase-file", pass_file,
                "--pinentry-mode", "loopback"]
    else:
        return []


def gnupg_home():
    """Returns appropriate arguments if GNUPGHOME is set"""
    if 'GNUPGHOME' in os.environ:
        gnupghome = os.environ['GNUPGHOME']
        if not os.path.isdir(gnupghome):
            raise CryptoritoError("Invalid GNUPGHOME directory")

        return ["--homedir", gnupghome]
    else:
        return []


def gnupg_bin():
    """Return the path to the gpg binary"""
    cmd = ["which", "gpg2"]
    try:
        # We are OK from the perspective of B603
        output = subprocess.check_output(cmd)  # nosec
        return output.strip()
    except subprocess.CalledProcessError:
        raise CryptoritoError("gpg2 must be installed")


def massage_key(key):
    """Massage the keybase return for only what we care about"""
    return {
        'fingerprint': key['key_fingerprint'],
        'bundle': key['bundle']
    }


def keybase_lookup_url(username):
    """Returns the URL for looking up a user in Keybase"""
    return "https://keybase.io/_/api/1.0/user/lookup.json?usernames=%s" \
        % username


def key_from_keybase(username):
    """Look up a public key from a username"""
    url = keybase_lookup_url(username)
    resp = requests.get(url)
    if resp.status_code == 200:
        j_resp = json.loads(resp.content)
        if 'them' in j_resp and len(j_resp['them']) == 1 \
           and 'public_keys' in j_resp['them'][0] \
           and 'pgp_public_keys' in j_resp['them'][0]['public_keys']:
            key = j_resp['them'][0]['public_keys']['primary']
            return massage_key(key)

    return None


def has_gpg_key(fingerprint):
    """Checks to see if we have this gpg fingerprint"""
    if len(fingerprint) > 8:
        fingerprint = fingerprint[-8:]

    fingerprint = fingerprint.upper()
    cmd = flatten([gnupg_bin(), gnupg_home(), "--list-public-keys"])
    keys = subprocess.check_output(cmd)  # nosec
    lines = keys.split('\n')
    return len([key for key in lines if key.find(fingerprint) > -1]) == 1


def import_gpg_key(key):
    """Imports a GPG key"""
    key_fd, key_filename = mkstemp("cryptorito-gpg-import")
    key_handle = os.fdopen(key_fd, 'w')
    key_handle.write(key)
    key_handle.close()
    cmd = flatten([gnupg_bin(), gnupg_home(), "--import", key_filename])
    # we trust mkstep to be legit
    output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)  # nosec
    msg = 'gpg: Total number processed: 1'
    return len([line for line in output.split('\n') if line == msg]) == 1


def encrypt(source, dest, keys):
    """Encrypts a file using the given keys"""
    recipients = [["--recipient", key.encode('ASCII')] for key in keys]
    cmd = flatten([gnupg_bin(), "--armor", "--output", dest,
                   gnupg_home(), passphrase_file(), recipients,
                   "--encrypt", source])
    # gpg keys are validated in filez.grok_keys
    try:
        subprocess.check_output(cmd, stderr=subprocess.STDOUT)  # nosec
    except subprocess.CalledProcessError as exception:
        LOGGER.debug("GPG Command %s", ' '.join(exception.cmd))
        LOGGER.debug("GPG Output %s", exception.output)
        raise CryptoritoError('GPG encryption error')

    return True


def decrypt(source, dest):
    """Attempts to decrypt a file"""
    cmd = flatten([gnupg_bin(), "--output", dest, "--decrypt", "--verbose",
                   gnupg_home(), passphrase_file(), source])
    # we confirm the source file exists in filez.thaw
    try:
        subprocess.check_output(cmd, stderr=subprocess.STDOUT)  # nosec
    except subprocess.CalledProcessError as exception:
        LOGGER.debug("GPG Command %s", ' '.join(exception.cmd))
        LOGGER.debug("GPG Output %s", exception.output)
        raise CryptoritoError('GPG decryption error')

    return True
