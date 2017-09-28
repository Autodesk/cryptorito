# -*- mode: Shell-script;bash -*-
OS=$(uname -s)
function gpg_fixture() {
    FIXTURE_DIR="${BATS_TMPDIR}/fixtures"    
    export GNUPGHOME="${FIXTURE_DIR}/.gnupg"
    if [ -d "$GNUPGHOME" ] ; then
        rm -rf "${GNUPGHOME}"
    fi
    mkdir -p "$GNUPGHOME"
    echo "use-agent
verbose
" > "${GNUPGHOME}/gpg.conf"
    #
    GPG_VSN=$(gpg --version | head -n 1 | cut -f 3 -d ' ')
    GV_MAJ=$(cut -f 1 -d '.' <<< "$GPG_VSN")
    GV_MIN=$(cut -f 2 -d '.' <<< "$GPG_VSN")
    if [ "$GV_MAJ" == "2" ] && [ "$GV_MIN" -lt 1 ] ; then
       echo "always-trust" >> "${GNUPGHOME}/gpg.conf"
    fi
    PINENTRY="${CIDIR}/scripts/pinentry-dummy.sh"
    echo "pinentry-program ${PINENTRY}" > "${GNUPGHOME}/gpg-agent.conf"
    chmod -R og-rwx "$GNUPGHOME"    
    # https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html
    export GPG_PASS="somegpgpass${RANDOM}"
    export CRYPTORITO_PASSPHRASE_FILE="${FIXTURE_DIR}/pass"
    echo "$GPG_PASS" > "$CRYPTORITO_PASSPHRASE_FILE"
    gpg --gen-key --verbose --batch <<< "
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: cryptorito test
Expire-Date: 300
Passphrase: ${GPG_PASS}
%commit
"
    gpg --list-keys
    if [ "$OS" == "Darwin" ] ; then
        GPGID=$(gpg --list-keys 2> /dev/null | grep -A1 -e 'pub   rsa2048'  | tail -n 1 | sed -e 's! !!g')
    elif [ "$OS" == "Linux" ] ; then
        GPGID=$(gpg --list-keys 2> /dev/null | grep -e 'pub   2048R' | awk '{print $2}' | cut -f 2 -d '/')
    fi
    [ ! -z "$GPGID" ]
}

run_cryptorito() {
    RC="$1"
    shift
    echo "cryptorito $*"
    run coverage run -a --source "${CIDIR}/cryptorito/" "${CIDIR}/cryptorito.py" "$@" 2> /dev/null
    echo "[received ${status}, expected ${RC}] $output"
    [ $status -eq "$RC" ]
    gpgconf --reload gpg-agent
}

scan_lines() {
    local STRING="$1"
    shift
    while [ ! -z "$1" ] ; do
        if grep -qE "$STRING" <<< "$1" ; then
            return 0
        fi
        shift
    done
    return 1
}
