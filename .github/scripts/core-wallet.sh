#!/usr/bin/env bash
set -euo pipefail

miner=${1:?usage: core-wallet.sh PATH_TO_MINER}
release=https://github.com/tidecoin/tidecoin/releases/download/v1.0.0rc3
archive=tidecoin-1.0.0rc3-x86_64-linux-gnu.tar.gz
builder_key=https://raw.githubusercontent.com/tidecoin/guix.sigs/84ef414307e7e3b44d7152f7c0e3bb85813f7da9/builder-keys/yarsawyer.gpg
fingerprint=1D1263BE881FF85C5F2947DF291A524038955927

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export GNUPGHOME="$work/gnupg"
mkdir -m 700 "$GNUPGHOME"

download() {
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --retry 2 --connect-timeout 10 --max-time 120 --output "$work/$2" "$1"
}

download "$builder_key" builder.gpg
download "$release/SHA256SUMS" SHA256SUMS
download "$release/SHA256SUMS.asc" SHA256SUMS.asc
gpg --batch --import "$work/builder.gpg"
gpg --batch --status-fd 1 --verify "$work/SHA256SUMS.asc" "$work/SHA256SUMS" |
    awk -v fingerprint="$fingerprint" '
        $1 == "[GNUPG:]" && $2 == "NEWSIG" { good = 0 }
        $1 == "[GNUPG:]" && $2 == "GOODSIG" { good = 1 }
        $1 == "[GNUPG:]" && $2 == "VALIDSIG" && good && $12 == fingerprint { valid = 1 }
        END { exit !valid }
    '

download "$release/$archive" "$archive"
(
    cd "$work"
    awk -v archive="$archive" '
        $2 == archive || $2 == "*" archive { print; count++ }
        END { exit count != 1 }
    ' SHA256SUMS | sha256sum --strict --check
    mkdir bin
    tar --extract --gzip --file "$archive" --directory bin --wildcards \
        --strip-components=2 '*/bin/tidecoind' '*/bin/tidecoin-cli'
)
printf 'PASS verified Tidecoin Core v1.0.0rc3 release archive (ffed4e92e60ff2de30361648a71cba64531f9077)\n'

TMPDIR="$work" python3 tests/core_descriptor.py --miner "$miner" \
    --daemon "$work/bin/tidecoind" --cli "$work/bin/tidecoin-cli"
