# Release builds and verification

## Verify a download

Obtain the official repository owner, repository name, and release tag from a trusted project channel. The signing identity is the exact workflow URI for that repository and tag. Download `SHA256SUMS`, `SHA256SUMS.sigstore.json`, and the target ZIP into one directory. Install Cosign 3.x and substitute the official values below.

```sh
repository=OWNER/REPOSITORY
tag=vX.Y.Z
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/$repository/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

After signature verification, compare the SHA-256 of your ZIP against the entry with its exact basename in `SHA256SUMS`. Linux users who downloaded all the assets can run `sha256sum --strict --check SHA256SUMS`. For a single ZIP, calculate its digest with `sha256sum <file>` on Linux, `shasum -a 256 <file>` on macOS, or `Get-FileHash -Algorithm SHA256 <file>` in PowerShell.

Extract the verified archive and see `README.md` for usage, key handling, and Tidecoin wallet recovery. The executable is under `bin/`. The manifest signature authenticates the archived executable bytes. Releases are not notarized or Authenticode-signed. The macOS executable carries only an ad-hoc signature.

On macOS, Gatekeeper blocks a quarantined executable from a browser download. Verify the Sigstore bundle and the ZIP's SHA-256 first, exactly as above. Then remove the quarantine attribute from the single extracted executable only:

```sh
xattr -d com.apple.quarantine bin/tdc-vanity
```

Do not remove it recursively from a downloads folder, and do not disable Gatekeeper with `spctl --master-disable`. Files fetched with `curl` are not quarantined and need no change.

The Linux executable is statically linked against musl libc and needs no particular glibc version.

Corresponding source: every release publishes `tdc-vanity-vX.Y.Z-source.zip` on the same release page as the binary ZIPs, listed in the same signed `SHA256SUMS`. It contains the project sources, build scripts, `Cargo.lock`, the complete locked crates.io sources under `source/vendor` and the offline Cargo configuration. Each binary ZIP carries the license texts of the crates in its own dependency graph under `licenses/`.

## Rehearse locally

Install Python 3.12 or later and Rust 1.100.0 using rustup. The hosted workflow pins Python 3.15.2. ZIP bytes depend on the Python build's zlib, which `build-info.json` records, so use the same Python build to reproduce an archive byte for byte. On macOS select Xcode and have `unzip` available. The Linux builder runs on an x86-64 GNU host with GCC 13, GNU binutils and Ubuntu 24.04 development headers, and builds the static `x86_64-unknown-linux-musl` executable with Rust's bundled musl; run `rustup target add --toolchain 1.100.0 x86_64-unknown-linux-musl` first. It checks that the extracted executable has no program interpreter and needs no shared libraries. On Windows use an x64 MSVC developer shell. Use a new, empty output directory. The build uses two fresh source, Cargo home and target directories, then compares the executables byte for byte. It independently packs both results, compares the ZIPs, and unpacks and runs one on its native target.

```sh
rustup toolchain install 1.100.0 --profile minimal
python3 scripts/release.py build --source-archive --output /tmp/tdc-release-rehearsal
rustup run 1.100.0 cargo install --locked --version '=0.19.5' cargo-deny
bash scripts/release-audit.sh /tmp/tdc-release-rehearsal/dependency-audit.json
python3 scripts/release.py checksums --target aarch64-apple-darwin --directory /tmp/tdc-release-rehearsal
```

Replace the target in the checksum command if rehearsing on Linux or Windows. `--source-archive` also packs the corresponding source from the inputs the build used; the hosted workflow passes it only on Linux, and the manifest expects one source ZIP. Pass `--offline` to the build when the locked crate packages are already cached. For an offline advisory check, pass a local Git mirror containing the pinned RustSec commit as the second argument to `release-audit.sh`. The report records the database revision, scanner version and lockfile SHA-256. Review and update the pinned advisory revision before a future release.

The archive's `build-info.json` records the image label and actual image revision where available, OS, toolchain, native SDK and linker, input hashes and executable digest. The hosted OS images receive updates under fixed labels. Each comparison measures reproducibility within one runner image and SDK. On macOS the linker emits an unsigned Mach-O. The script replaces its path-dependent UUID with one derived from the image bytes and compares the entire unsigned images. It then applies a timestamp-free ad-hoc signature for native execution and compares the full executable bytes again. The source ZIP is packed twice, from each build's copy of the inputs, and the two are compared. Its `source/` tree includes the build scripts, lockfile, complete locked dependency sources, and offline Cargo configuration. An ordinary `cargo build --locked --offline --release` works there with the specified Rust and native SDK. The target SBOM lists normal and build dependencies from Cargo's target-filtered graph, plus the statically linked musl for Linux. It excludes dev-only edges and other system libraries.

## Prepare a tagged release

Configure a tag ruleset that restricts creation, update and deletion of `v*` tags to release maintainers. Select the release version in `Cargo.toml` and use the matching `v<version>` tag on the reviewed commit. A manual workflow run only produces rehearsal artifacts. Both modes run the full native test suite on the same commit, build the three targets, check RustSec advisories, and run the Tidecoin Core wallet round trip against the executable extracted from the Linux archive. Assembly requires all of them to pass. An unexplained binary or archive mismatch fails the build and leaves comparison diagnostics as a separate workflow artifact.

Review the build, audit, wallet and native CI results before enabling signing. To authorize keyless signing, configure the `release-signing` GitHub environment with required reviewers, prevent self-review, and restrict it to protected release tags. Set its environment variable `TDC_SIGNING_REPOSITORY` to the exact `OWNER/REPOSITORY` spelling. Set the repository variable `TDC_ENABLE_RELEASE_SIGNING` to `true` only when ready. The signing job receives OIDC permission, downloads the assembled assets for the same run, verifies their hashes, signs the manifest, and verifies the resulting bundle with the expected tag workflow identity. Publication is a separate maintainer action. The workflow provides the assets as workflow artifacts.

Publish the three binary ZIPs, the source ZIP, `dependency-audit.json`, `SHA256SUMS`, and `SHA256SUMS.sigstore.json` from the same reviewed run and on the same release page. The manifest lists the final ZIPs and audit report. Any modification to an executable changes its bytes. Apply it after comparing the clean builds, then repackage, repeat the native smoke tests on those final archives, regenerate the manifest, and sign that manifest before publication.
