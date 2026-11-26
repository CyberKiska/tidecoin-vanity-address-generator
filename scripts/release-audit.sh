#!/usr/bin/env bash
set -euo pipefail

version=0.19.5
revision=b9b8a3c2cb1f2a3c76ab17a551193568c9f8b7a4
url=https://github.com/RustSec/advisory-db
if [[ ${1:-} == --version ]]; then
    printf '%s\n' "$version"
    exit 0
fi
output=${1:?usage: release-audit.sh OUTPUT_JSON [LOCAL_RUSTSEC_GIT_MIRROR]}
mirror=${2:-$url}
tool=${CARGO_DENY:-cargo-deny}
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
rust=$(python3 "$root/scripts/release.py" rust-version)
bin=$(dirname "$(rustup which --toolchain "$rust" cargo)")
export PATH="$bin:$PATH"
scanner=$("$tool" --version)
test "$scanner" = "cargo-deny $version"

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
# Directory name derived by cargo-deny 0.19.5 for the canonical database URL.
db="$work/advisory-db-3157b0e258782691"
git init --quiet "$db"
git -C "$db" fetch --quiet --depth 1 "$mirror" "$revision"
git -C "$db" checkout --quiet --detach FETCH_HEAD
actual=$(git -C "$db" rev-parse HEAD)
test "$actual" = "$revision"
printf '[advisories]\ndb-path = "%s"\ndb-urls = ["%s"]\n' "$work" "$url" > "$work/deny.toml"
printf 'Auditing Cargo.lock with %s at RustSec revision %s\n' "$scanner" "$actual"
status=0
"$tool" --manifest-path "$root/Cargo.toml" --offline --locked --format json check \
    --disable-fetch --audit-compatible-output --config "$work/deny.toml" advisories \
    > "$work/audit.json" || status=$?
python3 - "$work/audit.json" "$output" "$actual" "$scanner" "$status" "$root/Cargo.lock" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

raw, output, revision, scanner, status, lock = sys.argv[1:]
report = {
    "advisory_database_revision": revision,
    "scanner": scanner,
    "exit_status": int(status),
    "cargo_lock_sha256": hashlib.sha256(Path(lock).read_bytes()).hexdigest(),
    "rustsec": json.loads(Path(raw).read_text()) if Path(raw).stat().st_size else None,
}
if status == "0" and report["rustsec"] is None:
    raise SystemExit("Scanner returned no advisory report")
with Path(output).open("x", encoding="utf-8", newline="\n") as file:
    json.dump(report, file, indent=2, sort_keys=True)
    file.write("\n")
PY
exit "$status"
