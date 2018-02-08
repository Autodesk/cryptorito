"""Wrappers for GPG/Keybase functionality we need"""
from __future__ import print_function
import collections
import itertools as IT
import sys
import atexit
import os
import re
from shutil import rmtree
from base64 import b64encode, b64decode
import logging
import json
from tempfile import mkstemp, mkdtemp
import subprocess  # nosec
import requests
LOGGER = logging.getLogger(__name__)

if os.environ.get('CRYPTORITO_LOG_LEVEL'):
    LOG_LEVEL = os.environ['CRYPTORITO_LOG_LEVEL'].lower()
    if LOG_LEVEL == 'debug':
        logging.basicConfig(level=logging.DEBUG)
    elif LOG_LEVEL == 'info':
        logging.basicConfig(level=logging.INFO)


class CryptoritoError(Exception):
    """We do not have complicated exceptions to be honest"""
    def __init__(self, message=None):
        """The only thing you can pass is a message, but
        even that is optional"""
        if message is not None:
            super(CryptoritoError, self).__init__(message)
        else:
            super(CryptoritoError, self).__init__()


def clean_tmpdir(path):
    """Invoked atexit, this removes our tmpdir"""
    if os.path.exists(path) and \
       os.path.isdir(path):
        rmtree(path)


def ensure_tmpdir():
    """Ensures a temporary directory exists"""
    path = mkdtemp('aomi')
    atexit.register(clean_tmpdir, path)
    return path


def gpg_version():
    """Returns the GPG version"""
    cmd = flatten([gnupg_bin(), "--version"])
    output = stderr_output(cmd)
    output = output \
        .split('\n')[0] \
        .split(" ")[2] \
        .split('.')
    return tuple([int(x) for x in output])


def is_py3():
    """Returns true if this is actually in the future that will
    be running entierly on Python 3"""
    return sys.version_info >= (3, 0)


def polite_string(a_string):
    """Returns a "proper" string that should work in both Py3/Py2"""
    if is_py3() and hasattr(a_string, 'decode'):
        try:
            return a_string.decode('utf-8')
        except UnicodeDecodeError:
            return a_string

    return a_string


def polite_bytes(a_string):
    """Returns "proper" utf-8 bytestring that should work as expected in Py3.
    In Py2 it's just gonna be a string because that's all that's needed."""
    if is_py3():
        try:
            return bytes(a_string, 'utf-8')
        except TypeError:
            return a_string

    return a_string


def not_a_string(obj):
    """It's probably not a string, in the sense
    that Python2/3 get confused about these things"""
    my_type = str(type(obj))
    if is_py3():
        is_str = my_type.find('bytes') < 0 and my_type.find('str') < 0
        return is_str

    return my_type.find('str') < 0 and \
        my_type.find('unicode') < 0


def actually_flatten(iterable):
    """Flatten iterables
    This is super ugly. There must be a cleaner py2/3 way
    of handling this."""
    remainder = iter(iterable)
    while True:
        first = next(remainder)  # pylint: disable=R1708
        # Python 2/3 compat
        is_iter = isinstance(first, collections.Iterable)
        try:
            basestring
        except NameError:
            basestring = str  # pylint: disable=W0622

        if is_py3() and is_iter and not_a_string(first):
            remainder = IT.chain(first, remainder)
        elif (not is_py3()) and is_iter and not isinstance(first, basestring):
            remainder = IT.chain(first, remainder)
        else:
            yield polite_string(first)


def flatten(iterable):
    """Ensure we are returning an actual list, as that's all we
    are ever going to flatten within our little domain"""
    return [x for x in actually_flatten(iterable)]


def passphrase_file(passphrase=None):
    """Read passphrase from a file. This should only ever be
    used by our built in integration tests. At this time,
    during normal operation, only pinentry is supported for
    entry of passwords."""
    cmd = []
    pass_file = None
    if not passphrase and 'CRYPTORITO_PASSPHRASE_FILE' in os.environ:
        pass_file = os.environ['CRYPTORITO_PASSPHRASE_FILE']
        if not os.path.isfile(pass_file):
            raise CryptoritoError('CRYPTORITO_PASSPHRASE_FILE is invalid')
    elif passphrase:
        tmpdir = ensure_tmpdir()
        pass_file = "%s/p_pass" % tmpdir
        p_handle = open(pass_file, 'w')
        p_handle.write(passphrase)
        p_handle.close()

    if pass_file:
        cmd = cmd + ["--batch", "--passphrase-file", pass_file]

        vsn = gpg_version()
        if vsn[0] >= 2 and vsn[1] >= 1:
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


def which_bin(cmd):
    """Returns the path to a thing, or None"""
    cmd = ["which", cmd]
    try:
        return stderr_output(cmd).strip().split('\n')[0]
    except CryptoritoError:
        return None


def gnupg_bin():
    """Return the path to the gpg binary.
    Note that on some systems this is gpg, and others gpg2. We
    try to support both."""
    for a_bin in ["gpg2", "gpg"]:
        gpg_output = which_bin(a_bin)
        if gpg_output:
            return gpg_output

    raise CryptoritoError("gpg or gpg2 must be installed")


def massage_key(key):
    """Massage the keybase return for only what we care about"""
    return {
        'fingerprint': key['key_fingerprint'].lower(),
        'bundle': key['bundle']
    }


def keybase_lookup_url(username):
    """Returns the URL for looking up a user in Keybase"""
    return "https://keybase.io/_/api/1.0/user/lookup.json?usernames=%s" \
        % username


def fingerprint_from_keybase(fingerprint, kb_obj):
    """Extracts a key matching a specific fingerprint from a
    Keybase API response"""
    if 'public_keys' in kb_obj and \
       'pgp_public_keys' in kb_obj['public_keys']:
        for key in kb_obj['public_keys']['pgp_public_keys']:
            keyprint = fingerprint_from_var(key).lower()
            fingerprint = fingerprint.lower()
            if fingerprint == keyprint or \
               keyprint.startswith(fingerprint) or \
               keyprint.endswith(fingerprint):
                return {
                    'fingerprint': keyprint,
                    'bundle': key
                }

    return None


def key_from_keybase(username, fingerprint=None):
    """Look up a public key from a username"""
    url = keybase_lookup_url(username)
    resp = requests.get(url)
    if resp.status_code == 200:
        j_resp = json.loads(polite_string(resp.content))
        if 'them' in j_resp and len(j_resp['them']) == 1:
            kb_obj = j_resp['them'][0]
            if fingerprint:
                return fingerprint_from_keybase(fingerprint, kb_obj)
            else:
                if 'public_keys' in kb_obj \
                   and 'pgp_public_keys' in kb_obj['public_keys']:
                    key = kb_obj['public_keys']['primary']
                    return massage_key(key)

    return None


def has_gpg_key(fingerprint):
    """Checks to see if we have this gpg fingerprint"""
    if len(fingerprint) > 8:
        fingerprint = fingerprint[-8:]

    fingerprint = fingerprint.upper()
    cmd = flatten([gnupg_bin(), gnupg_home(), "--list-public-keys"])
    lines = stderr_output(cmd).split('\n')
    return len([key for key in lines if key.find(fingerprint) > -1]) == 1


def fingerprint_from_var(var):
    """Extract a fingerprint from a GPG public key"""
    vsn = gpg_version()
    cmd = flatten([gnupg_bin(), gnupg_home()])
    if vsn[0] >= 2 and vsn[1] < 1:
        cmd.append("--with-fingerprint")

    output = polite_string(stderr_with_input(cmd, var)).split('\n')
    if not output[0].startswith('pub'):
        raise CryptoritoError('probably an invalid gpg key')

    if vsn[0] >= 2 and vsn[1] < 1:
        return output[1] \
            .split('=')[1] \
            .replace(' ', '')

    return output[1].strip()


def fingerprint_from_file(filename):
    """Extract a fingerprint from a GPG public key file"""
    cmd = flatten([gnupg_bin(), gnupg_home(), filename])
    outp = stderr_output(cmd).split('\n')
    if not outp[0].startswith('pub'):
        raise CryptoritoError('probably an invalid gpg key')

    return outp[1].strip()


def stderr_handle():
    """Generate debug-level appropriate stderr context for
    executing things through subprocess. Normally stderr gets
    sent to dev/null but when debugging it is sent to stdout."""
    gpg_stderr = None
    handle = None
    if LOGGER.getEffectiveLevel() > logging.DEBUG:
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

        return str(polite_string(output))
    except subprocess.CalledProcessError as exception:
        LOGGER.debug("GPG Command %s", ' '.join(exception.cmd))
        LOGGER.debug("GPG Output %s", exception.output)
        raise CryptoritoError('GPG Execution')


def stderr_with_input(cmd, stdin):
    """Runs a command, passing something in stdin, and returning
    whatever came out from stdout"""
    handle, gpg_stderr = stderr_handle()
    LOGGER.debug("GPG command %s", ' '.join(cmd))
    try:
        gpg_proc = subprocess.Popen(cmd,  # nosec
                                    stdout=subprocess.PIPE,
                                    stdin=subprocess.PIPE,
                                    stderr=gpg_stderr)

        output, _err = gpg_proc.communicate(polite_bytes(stdin))

        if handle:
            handle.close()

        return output
    except subprocess.CalledProcessError as exception:
        return gpg_error(exception, 'GPG variable encryption error')
    except OSError as exception:
        raise CryptoritoError("File %s not found" % exception.filename)


def import_gpg_key(key):
    """Imports a GPG key"""
    if not key:
        raise CryptoritoError('Invalid GPG Key')

    key_fd, key_filename = mkstemp("cryptorito-gpg-import")
    key_handle = os.fdopen(key_fd, 'w')

    key_handle.write(polite_string(key))
    key_handle.close()
    cmd = flatten([gnupg_bin(), gnupg_home(), "--import", key_filename])
    output = stderr_output(cmd)
    msg = 'gpg: Total number processed: 1'
    output_bits = polite_string(output).split('\n')
    return len([line for line in output_bits if line == msg]) == 1


def export_gpg_key(key):
    """Exports a GPG key and returns it"""
    cmd = flatten([gnupg_bin(), gnupg_verbose(), gnupg_home(),
                   "--export", key])
    handle, gpg_stderr = stderr_handle()
    try:
        gpg_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,  # nosec
                                    stderr=gpg_stderr)
        output, _err = gpg_proc.communicate()
        if handle:
            handle.close()

        return portable_b64encode(output)
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
    output = stderr_with_input(cmd, source)
    return output


def gpg_error(exception, message):
    """Handles the output of subprocess errors
    in a way that is compatible with the log level"""
    LOGGER.debug("GPG Command %s", ' '.join([str(x) for x in exception.cmd]))
    LOGGER.debug("GPG Output %s", exception.output)
    raise CryptoritoError(message)


def decrypt_var(source, passphrase=None):
    """Attempts to decrypt a variable"""
    cmd = [gnupg_bin(), "--decrypt", gnupg_home(), gnupg_verbose(),
           passphrase_file(passphrase)]

    return stderr_with_input(flatten(cmd), source)


def decrypt(source, dest=None, passphrase=None):
    """Attempts to decrypt a file"""
    if not os.path.exists(source):
        raise CryptoritoError("Encrypted file %s not found" % source)

    cmd = [gnupg_bin(), gnupg_verbose(), "--decrypt", gnupg_home(),
           passphrase_file(passphrase)]

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
    if is_py3():
        try:
            some_bits = bytes(thing, 'utf-8')
        except TypeError:
            some_bits = thing

        return polite_string(b64encode(some_bits).decode('utf-8'))

    return polite_string(b64encode(thing))


def portable_b64decode(thing):
    """Consistent b64decode in Python 2 & 3"""
    return b64decode(polite_string(thing))
