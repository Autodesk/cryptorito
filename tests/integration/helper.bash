# -*- mode: Shell-script;bash -*-

function gpg_fixture() {
    FIXTURE_DIR="${BATS_TMPDIR}/fixtures"    
    export GNUPGHOME="${FIXTURE_DIR}/.gnupg"
    if [ -d "$GNUPGHOME" ] ; then
        rm -rf "${GNUPGHOME}"
    fi
    mkdir -p "$GNUPGHOME"
    echo "use-agent
always-trust
verbose
" > "${GNUPGHOME}/gpg.conf"
    PINENTRY="${CIDIR}/scripts/pinentry-dummy.sh"
    echo "pinentry-program ${PINENTRY}" > "${GNUPGHOME}/gpg-agent.conf"
    chmod -R og-rwx "$GNUPGHOME"    
    # https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html
    PASS="somegpgpass${RANDOM}"
    export CRYPTORITO_PASSPHRASE_FILE="${FIXTURE_DIR}/pass"
    echo "$PASS" > "$CRYPTORITO_PASSPHRASE_FILE"
    gpg --gen-key --verbose --batch <<< "
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: cryptorito test
Expire-Date: 300
Passphrase: ${PASS}
%commit
"
    GPGID=$(gpg --list-keys 2>/dev/null | grep -A1 -e 'pub   rsa2048'  | tail -n 1 | sed -e 's! !!g')
    [ ! -z "$GPGID" ]
}

run_cryptorito() {
    RC="$1"
    shift
    run coverage run -a --source "${CIDIR}/cryptorito/" "${CIDIR}/cryptorito.py" $@
    echo "${lines[@]}"
    [ $status -eq "$RC" ]
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
