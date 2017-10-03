#!/usr/bin/env bats
# -*- mode: Shell-script;bash -*-
# happy path tests
load helper

setup() {
    gpg_fixture
}

@test "keybase minimal" {
    run_cryptorito 0 import_keybase "otakup0pe"
    run_cryptorito 2 import_keybase "otakup0pe"
    run_cryptorito 0 import_keybase "otakup0pe:077342F6"
    VAR="beep-boop-${RANDOM}"
}

@test "a happy path" {
    run_cryptorito 1 help
    VAR="bla-blah-blah${RANDOM}"
    RECP="${GPGID}"
    run_cryptorito 0 encrypt "$RECP" <<< "$VAR"
    # for some reason the output is prefixed by all this "gpg:" stuff in
    # test contexts. not when running otherwise :(    
    grep -v -E "^gpg:.+$" <<< "$output" > "${FIXTURE_DIR}/enc"
    run_cryptorito 0 decrypt < "${FIXTURE_DIR}/enc"
    scan_lines "$VAR" "${lines[@]}"
    unset CRYPTORITO_PASSPHRASE_FILE
    run_cryptorito 0 decrypt "$GPG_PASS" < "${FIXTURE_DIR}/enc"
    scan_lines "$VAR" "${lines[@]}"
    run_cryptorito 0 has_key "$GPGID"
    run_cryptorito 1 has_key "nope"
    run_cryptorito 0 export "$GPGID" > /dev/null
}

@test "a happy path but with files" {
    FILE1="${FIXTURE_DIR}/ayyy${RANDOM}"
    FILE2="${FIXTURE_DIR}/ayyyenc${RANDOM}"
    FILE3="${FIXTURE_DIR}/ayyydec${RANDOM}"
    echo "$RANDOM" > "$FILE1"
    run_cryptorito 0 encrypt_file "$FILE1" "$FILE2" "$GPGID"
    run_cryptorito 0 decrypt_file "$FILE2" "$FILE3"
    [ "$(cat $FILE1)" == "$(cat $FILE3)" ]
}

@test "a happy path but with binary files" {
    FILE1="${FIXTURE_DIR}/binayy${RANDOM}"
    FILE2="${FIXTURE_DIR}/binayy${RANDOM}.enc"
    FILE3="${FIXTURE_DIR}/binayy${RANDOM}.dec"
    dd if=/dev/urandom of="$FILE1" bs=1 count=512
    run_cryptorito 0 encrypt_file "$FILE1" "$FILE2" "$GPGID"
    run_cryptorito 0 decrypt_file "$FILE2" "$FILE3"
    [ "$(cat "$FILE1")" == "$(cat "$FILE3")" ]
}
