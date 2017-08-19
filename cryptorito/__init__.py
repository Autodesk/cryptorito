"""Wrappers for GPG/Keybase functionality we need"""
from __future__ import print_function
import collections
import itertools as IT
import sys
import os
import re
from base64 import b64encode, b64decode
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


def gpg_version():
    """Returns the GPG version"""
    cmd = flatten([gnupg_bin(), "--version"])
    val = subprocess.check_output(cmd)  # nosec
    if sys.version_info >= (3, 0):
        val = val.decode('utf-8')

    return val.split("\n")[0] \
              .split(" ")[2]


def not_a_string(obj):
    """It's probably not a string, in the sense
    that Python2/3 get confused about these things"""
    my_type = str(type(obj))
    if sys.version_info >= (3, 0):
        is_str = my_type.find('bytes') < 0 and my_type.find('str') < 0
        return is_str

    return my_type.find('str') < 0 and \
        my_type.find('unicode') < 0


def actually_flatten(iterable):
    """Flatten iterables
    This is super ugly. There must be a cleaner py2/3 way
    of handling this."""
    remainder = iter(iterable)
    is_py3 = sys.version_info >= (3, 0)
    while True:
        first = next(remainder)
        # Python 2/3 compat
        is_iter = isinstance(first, collections.Iterable)
        try:
            basestring
        except NameError:
            basestring = str  # pylint: disable=W0622

        if is_py3 and is_iter and not_a_string(first):
            remainder = IT.chain(first, remainder)
        elif (not is_py3) and is_iter and not isinstance(first, basestring):
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
    cmd = []
    if 'CRYPTORITO_PASSPHRASE_FILE' in os.environ:
        pass_file = os.environ['CRYPTORITO_PASSPHRASE_FILE']
        if not os.path.isfile(pass_file):
            raise CryptoritoError('CRYPTORITO_PASSPHRASE_FILE is invalid')

        cmd = cmd + ["--batch", "--passphrase-file", pass_file]

        vsn = gpg_version()
        if int(vsn.split(".")[0]) == 2 and int(vsn.split(".")[1]) >= 1:
            cmd = cmd + ["--pinentry-mode", "loopback"]

    return cmd


def gnupg_home():
    """Returns appropriate arguments if GNUPGHOME is set"""
    if 'GNUPGHOME' in os.environ:
        gnupghome = os.environ['GNUPGHOME']
        if not os.path.isdir(gnupghome):
            raise CryptoritoError("Invalid GNUPGHOME directory")

        return ["--homedir", gnupghome]
    else:
        return []


def gnupg_verbose():
    """Maybe return the verbose option, maybe do not"""
    if LOGGER.getEffectiveLevel() == logging.DEBUG:
        return ["--verbose"]

    return ["-q"]


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
    keys = stderr_output(cmd)
    if sys.version_info >= (3, 0):
        keys = keys.decode('utf-8')

    lines = keys.split('\n')
    return len([key for key in lines if key.find(fingerprint) > -1]) == 1


def stderr_handle():
    """Generate debug-level appropriate stderr context for
    executing things through subprocess. Normally stderr gets
    sent to dev/null but when debugging it is sent to stdout."""
    gpg_stderr = None
    handle = None
    if LOGGER.getEffectiveLevel() < logging.DEBUG:
        handle = open(os.devnull, 'wb')
        gpg_stderr = handle

    return handle, gpg_stderr


def stderr_output(cmd):
    """Wraps the execution of check_output in a way that
    ignores stderr when not in debug mode"""

    handle, gpg_stderr = stderr_handle()
    try:
        output = subprocess.check_output(cmd, stderr=gpg_stderr)  # nosec
        if handle:
            handle.close()

        return output
    except subprocess.CalledProcessError as exception:
        LOGGER.debug("GPG Command %s", ' '.join(exception.cmd))
        LOGGER.debug("GPG Output %s", exception.output)
        raise CryptoritoError('GPG Execution')


def import_gpg_key(key):
    """Imports a GPG key"""
    if not key:
        raise CryptoritoError('Invalid GPG Key')

    key_fd, key_filename = mkstemp("cryptorito-gpg-import")
    key_handle = os.fdopen(key_fd, 'w')
    if sys.version_info >= (3, 0):
        key = key.decode('utf-8')

    key_handle.write(key)
    key_handle.close()
    cmd = flatten([gnupg_bin(), gnupg_home(), "--import", key_filename])
    output = stderr_output(cmd)
    msg = 'gpg: Total number processed: 1'
    if sys.version_info >= (3, 0):
        output = output.decode('utf-8')

    return len([line for line in output.split('\n') if line == msg]) == 1


def export_gpg_key(key):
    """Exports a GPG key and returns it"""
    cmd = flatten([gnupg_bin(), gnupg_verbose(), gnupg_home(),
                   "--export", key, "--armor"])
    handle, gpg_stderr = stderr_handle()
    try:
        gpg_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,  # nosec
                                    stderr=gpg_stderr)
        output, _err = gpg_proc.communicate()
        if handle:
            handle.close()

        return output
    except subprocess.CalledProcessError as exception:
        LOGGER.debug("GPG Command %s", ' '.join(exception.cmd))
        LOGGER.debug("GPG Output %s", exception.output)
        raise CryptoritoError('GPG encryption error')


def recipients_args(keys):
    """Returns the list representation of a set of GPG
    keys to be used as recipients when encrypting."""
    return [["--recipient", key.encode('ASCII')] for key in keys]


def encrypt(source, dest, keys):
    """Encrypts a file using the given keys"""
    cmd = flatten([gnupg_bin(), "--armor", "--output", dest, gnupg_verbose(),
                   gnupg_home(), recipients_args(keys),
                   "--encrypt", source])

    stderr_output(cmd)
    return True


def encrypt_var(source, keys):
    """Attempts to encrypt a variable"""
    cmd = flatten([gnupg_bin(), "--armor", "--encrypt", gnupg_verbose(),
                   recipients_args(keys)])
    handle, gpg_stderr = stderr_handle()
    try:
        gpg_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,  # nosec
                                    stdin=subprocess.PIPE, stderr=gpg_stderr)

        if sys.version_info >= (3, 0):
            source = bytes(source, 'utf-8')

        output, _err = gpg_proc.communicate(source)
        if handle:
            handle.close()

        gpg_proc.stdin.close()
        return output
    except subprocess.CalledProcessError as exception:
        return gpg_error(exception, 'GPG variable encryption error')


def gpg_error(exception, message):
    """Handles the output of subprocess errors
    in a way that is compatible with the log level"""
    LOGGER.debug("GPG Command %s", ' '.join(exception.cmd))
    LOGGER.debug("GPG Output %s", exception.output)
    raise CryptoritoError(message)


def decrypt_var(source):
    """Attempts to decrypt a variable"""
    cmd = flatten([gnupg_bin(), "--decrypt", gnupg_verbose(),
                   gnupg_home(), passphrase_file()])
    handle, gpg_stderr = stderr_handle()
    try:
        gpg_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,  # nosec
                                    stdin=subprocess.PIPE, stderr=gpg_stderr)
        if sys.version_info >= (3, 0):
            source = bytes(source, 'utf-8')

        output, _err = gpg_proc.communicate(source)
        if handle:
            handle.close()

        gpg_proc.stdin.close()
        return output
    except subprocess.CalledProcessError as exception:
        return gpg_error(exception, 'GPG variable decryption error')


def decrypt(source, dest=None):
    """Attempts to decrypt a file"""
    if not os.path.exists(source):
        raise CryptoritoError("Encrypted file %s not found" % source)

    cmd = [gnupg_bin(), gnupg_verbose(), "--decrypt",
           gnupg_home(), passphrase_file()]

    if dest:
        cmd.append(["--output", dest])

    cmd.append([source])

    stderr_output(flatten(cmd))
    return True


def is_base64(string):
    """Determines whether or not a string is likely to
    be base64 encoded binary nonsense"""
    return (not re.match('^[0-9]+$', string)) and \
        (len(string) % 4 == 0) and \
        re.match('^[A-Za-z0-9+/]+[=]{0,2}$', string)


def portable_b64encode(thing):
    """Wrap b64encode for Python 2 & 3"""
    if sys.version_info >= (3, 0):
        try:
            some_bits = bytes(thing, 'utf-8')
        except TypeError:
            some_bits = thing

        return b64encode(some_bits).decode('utf-8')

    return b64encode(thing)


def portable_b64decode(thing):
    """Consistent b64decode in Python 2 & 3"""
    if sys.version_info >= (3, 0):
        decoded = b64decode(thing)
        try:
            return decoded.decode('utf-8')
        except UnicodeDecodeError:
            return decoded

    return b64decode(thing)
