# tdc-vanity

A parallel Rust CLI for mining Tidecoin mainnet `T…` addresses. It searches for a Falcon-512 key whose P2SH-wrapped witness-v0 key-hash address matches the requested text. Each invocation stops after saving one match.

## Build and run

Use a stable Rust toolchain and Cargo. The first build downloads the dependencies pinned in `Cargo.lock`. The executable works offline.

```sh
cargo build --release --locked
./target/release/tdc-vanity --prefix=TD --postfix=7 --out=match.wif
```

For a source build on Windows, the executable is `target\release\tdc-vanity.exe`. When signed release archives are published, choose the ZIP for your OS and architecture and look for the executable under `bin/`. Follow the [release verification instructions](RELEASING.md) before running a downloaded binary. Choose an existing private directory and a new filename for each run.

| Option | Behavior |
| --- | --- |
| `--prefix=<PREFIX>` | Exact, case-sensitive start of the displayed address, including the initial `T`. |
| `--postfix=<POSTFIX>` | Exact, case-sensitive end of the address, including its checksum characters. |
| `--workers=<NUMBER_OF_THREADS>` | Positive integer. Defaults to the logical CPU count available to the process. |
| `--out=<DESTINATION>` | Required. Saves one line in the historical `address:WIF` format. The path must name a new file and cannot end with a directory separator or a `.` component. |

Supply at least one pattern. When both are present, the same address must satisfy both. For a quick key-generation or wallet-recovery test, use `--prefix=T`. Before searching, stderr shows the estimated address trials per match. The 2^64 work limit applies to that estimate and also rejects patterns that no checksummed address can match. Progress on stderr reports candidates previewed and previews/s across all workers, with an average time per match at the current rate. After the key file is saved, stdout receives only the public address followed by a newline. Ctrl+C interrupts the search.

## Protocol and wallet recovery

| Object | Bytes |
| --- | --- |
| Raw Falcon-512 public key | 897 bytes including the Falcon header `09` |
| Tidecoin public-key identity | `07` followed by the complete raw public key |
| HASH160(x) | RIPEMD-160(SHA-256(x)) |
| Redeem script | `00 14` followed by HASH160 of the Tidecoin public-key identity |
| Mainnet P2SH address | Base58Check of `41` followed by HASH160 of the redeem script |
| Output script | `a9 14` followed by HASH160 of the redeem script, then `87` |
| Mainnet legacy WIF | Base58Check of `7d` + 1,281-byte raw Falcon secret (starts with `59`) + `01` + 897-byte raw public key |

Hex bytes above are in serialized order. Base58Check appends the first four bytes of double SHA-256. The `07` participates in the key ID. The public key inside the legacy WIF starts with `09`. Changing either encoding breaks the wallet identity.

The text after the colon is the plaintext spending key. For a descriptor wallet the receiving policy is `sh(wpkh(<WIF>))`. Core's `getdescriptorinfo` can parse the private descriptor and return a checksummed public descriptor. Running `deriveaddresses` on that public descriptor should yield the address before the colon. For a spending-wallet import, use the original private descriptor with its input checksum. An unrelated wallet seed cannot recreate these independently generated keys. Back up the key file privately.

The export implements v0.18.3's WIF and modern Core's `EncodeSecretLegacy`. Newer Core also supports a shorter scheme-prefixed private-key export. The program targets the historical script's mainnet address and key format. Recovery in the v0.18.3 wallet remains unverified. Its legacy `importprivkey` path still needs a test that discovers an output paying the wrapped script and spends it after reopening the wallet. [v0.18.3 key I/O](https://github.com/tidecoin/tidecoin/blob/7b525367e9ea1b614aa380a52394f0e3d3878aa9/src/key_io.cpp) · [v0.18.3 wallet import](https://github.com/tidecoin/tidecoin/blob/7b525367e9ea1b614aa380a52394f0e3d3878aa9/src/wallet/rpcdump.cpp#L104) · [Modern key I/O](https://github.com/tidecoin/tidecoin/blob/ffed4e92e60ff2de30361648a71cba64531f9077/src/key_io.cpp) · [Mainnet parameters](https://github.com/tidecoin/tidecoin/blob/ffed4e92e60ff2de30361648a71cba64531f9077/src/kernel/chainparams.cpp) · [Descriptor expansion](https://github.com/tidecoin/tidecoin/blob/ffed4e92e60ff2de30361648a71cba64531f9077/src/script/descriptor.cpp)

## Search and key handling

Each CPU worker draws a fresh 48-byte seed from the OS for each preview. Core's PQClean key generation samples (f, g) from SHAKE256 of the seed until a pair passes its coefficient, norm, orthogonalized-norm and invertibility checks. It then computes the public key h = g/f mod q and solves the NTRU equation. The solver dominates key generation time, and the address depends on h alone. Workers replay the sampling and stop at h. When a preview matches the pattern, the worker runs full key generation with Tidecoin's Rust backend and keeps the match only if both public keys are identical. The solver can reject the previewed pair and retry, yielding a different public key for the same seed.

The preview uses native floating point and Parseval's identity for the orthogonalized norm. Rounding near the acceptance bound can change which pair passes. The full Rust backend also groups each pair of squared terms before adding them to the norm accumulator, while Core adds each square separately. This can change which pair passes near the bound even if the preview agrees with the full Rust backend. Deterministic equality with Core is verified for the published test vectors. Universal seed parity remains unverified. [Rust norm calculation](https://github.com/tidecoin/tide-fn-dsa/blob/6d4c86d4a275bcd813fedd83a603d601232302d5/tide-fn-dsa-kgen/src/pqclean_compat.rs#L166) · [Core Falcon key generation](https://github.com/tidecoin/tidecoin/blob/ffed4e92e60ff2de30361648a71cba64531f9077/src/pq/falcon-512/keygen.c)

The preview squeezes SHAKE256 one Keccak lane at a time with RustCrypto's `keccak` crate, which uses ARMv8 SHA3 instructions when the CPU has them. Each worker previews two seeds side by side. With ARMv8 SHA3, a two-state version of that crate's assembly advances both streams in each permutation, and each stream queues the lanes it has not read yet. Other CPUs keep one state per seed. The Gaussian sampler counts the table entries above each random value instead of scanning for the first entry below it. Because the table strictly decreases, the result is the same, and the count is constant time. Workers reuse their buffers. A precomputed numeric prefix range filters script hashes before Base58 conversion. Exact text matching handles range endpoints, suffixes and overlapping patterns.

Before exporting, the miner decodes the winning secret, re-derives its public key and checks the address again. It also checks the NTRU equation fG − gF = q over the integers, as Core's key generation does. Secret buffers owned by the miner are cleared on normal drop.

The miner writes and syncs a staging file named `.tdc-vanity-*.wif` in the destination directory, then publishes it with overwrite protection. If another process creates the destination first, both records are preserved. The miner exits with an error and reports the path of the retained staging file on stderr. On Unix, it syncs the directory after publishing a file or retaining it for recovery.

Unix file creation requests mode `0600` subject to the process umask. The miner checks the open preflight and staging files for ownership, owner read permission, and absence of group or other permissions. An umask such as `0777` that removes owner read permission causes preflight to fail. macOS also refuses new files with inherited ACL entries and fails if it cannot inspect the ACL. It refuses volumes mounted with ownership ignored, such as external drives with "Ignore ownership on this volume", where other local users could read a `0600` file. Windows creates the file with a protected owner-only DACL and requires a volume with persistent ACL support. Use a directory under your control. The WIF is unencrypted on disk, and OS swap and crash dumps may contain process memory.

On an eight-core Apple M1 (four performance and four efficiency cores), 15-second release-mode samples with a long prefix measured 2,867 candidates/s with one worker and 14,024/s with eight. Running full key generation for every candidate measured 590/s with eight workers. The measurements include seed generation, hashing and matching. Keccak still takes over half the time: each candidate needs about 2,550 permutations, now shared in pairs. A build forced onto the separate-state path measured 1,913/s and 9,451/s. As a rough estimate, a four-character suffix alone takes about 58⁴ attempts on average, or about 14 minutes at 14,000/s. Individual runs vary. Prefix probabilities also depend on the mainnet version byte.

## Verification

```sh
cargo fmt --all -- --check
cargo test --locked
cargo test --release --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked --no-default-features --features portable -- --show-output
cargo test --release --locked -- --include-ignored --show-output
```

The last command also runs the ignored fixed-work benchmark: 8,192 previews from fixed seeds, checked against a recorded digest, reporting elapsed time and previews/s on one thread. A fast test checks the first 256 of those records on both lane sources.

The [native CI workflow](.github/workflows/native-tests.yml) pins Rust 1.100.0 and runs these checks on macOS arm64, Linux x86-64 GNU and Windows x64 MSVC. The default build tests runtime dispatch, including ARMv8 SHA3 Keccak on supported Macs and AVX2 Falcon decoding on supported x86-64 hosts. The portable build disables those implementations and SHA-2 hardware acceleration. Test output reports the Keccak and Falcon paths exercised.

The access tests reopen both files from a publication race. On macOS they also check that an inheritable read ACL, and a disk image attached with ownership ignored, cause rejection before mining. On Linux CI uses `setfacl` and `getfacl` to check that the default ACL's inherited read grant is masked on both files. The Unix suite also checks rejection with umask `0777`. On Windows the tests inspect the protected NTFS DACL and its sole `OWNER RIGHTS` full-access entry. The hosted jobs try a second unprivileged identity and report a pass or a skip with the reason. A pass requires that identity to read a control file in the same directory and receive access denied opening both key files.

For local runs, `TDC_TEST_DEFAULT_ACL=1` enables the Linux ACL fixture and `TDC_TEST_SECOND_IDENTITY=1` attempts the Unix second-user check via noninteractive `sudo` as `nobody`.

The export tests verify the complete legacy WIF against Core's public fixture, check a published P2SH script/address vector, and reject a forged secret that decodes but fails the NTRU equation. The seeded key-generation tests compare the raw public and secret key digests with Core's Falcon C implementation for three fixed seeds. The preview test requires agreement with full Rust key generation for those three seeds and for at least 22 of 24 fixed seeds overall. The worker regression uses a Core rc3 fixture whose first and final public keys differ after a solver retry. Both digests are checked, and the worker must discard the matching preview and return the key and address independently derived from a later seed. In a separate run on 2,000 random seeds, the preview agreed on all 2,000 with a reference built from the backend's own internal checks. [Core wallet fixture](https://github.com/tidecoin/tidecoin/blob/ffed4e92e60ff2de30361648a71cba64531f9077/src/test/data/falcon512_legacy_wif.json) · [Core address vectors](https://github.com/tidecoin/tidecoin/blob/ffed4e92e60ff2de30361648a71cba64531f9077/src/test/data/key_io_valid.json)

Further tests compare the counting sampler with Falcon's scan at every table boundary and on 200,000 stream values. They also compare the two-state permutation with the scalar one, both lane sources with the backend's SHAKE256 through uneven reads, a full queue and a reseed, and the two pipelines' candidates with each other. They cover matching, difficulty limits, concurrent publication that keeps the losing record, private output including inherited macOS ACLs, and rejection of existing files.

The locked dependency versions were compared with the advisory ranges in the [RustSec database snapshot](https://github.com/RustSec/advisory-db/tree/f291af9b1cc0d21dfcea1709d6b037963cef262b). None of the published ranges in that snapshot applied.

The wallet integration check uses wallet-enabled `tidecoind` and `tidecoin-cli` from `tidecoin/tidecoin` commit `ffed4e92e60ff2de30361648a71cba64531f9077`. Use a build from that commit or the verified upstream `v1.0.0rc3` release. The harness checks both executables' reported version. It requires Python 3 with RIPEMD-160 support in `hashlib` and permission to bind a local IPv4 loopback RPC port. [Core v1.0.0rc3 release and verification instructions](https://github.com/tidecoin/tidecoin/releases/tag/v1.0.0rc3)

The workflow's manual `wallet` option runs a separate Linux job. It verifies the release checksum manifest against the pinned builder fingerprint, checks the Linux archive against that manifest, and then runs the wallet harness. Routine pull requests run only the native matrix.

```sh
cargo build --release --locked
python3 tests/core_descriptor.py --miner ./target/release/tdc-vanity \
  --daemon /path/to/tidecoind --cli /path/to/tidecoin-cli
```

The harness generates a fresh key and derives the miner's exact address on an isolated mainnet-parameter node using the unmodified WIF. Its test-only adapter changes the WIF version and checksum for regtest, then verifies the same redeem script and scriptPubKey. On regtest with AuxPoW disabled, the harness imports the private descriptor with its input checksum into a blank wallet, matures a coinbase paying the script, and restarts the node and reloads the wallet. It signs a spend of that exact output and checks mempool acceptance and block confirmation. Both nodes use temporary datadirs and have P2P and diagnostic logging disabled. The harness sends WIFs and private descriptors over stdin and reports stage results without printing RPC payloads or replies. Run it with disposable keys only and exclude its temporary files and wallet databases from artifacts.

The harness runs both version probes with a private temporary datadir, `-noconf` and, for the daemon, `-nosettings`, with `HOME` set to an unwritable empty directory, so it never touches the default Core data directory. An external review recorded an end-to-end pass on 22 November 2026 on macOS arm64 with the same three probe flags, before the unwritable `HOME` was added. Core was the verified upstream `v1.0.0rc3` arm64 archive (SHA-256 `af7e0eeb6c60123751a462af2ed0f5bd2f20e471f3cd728aff7739566e001e7d`), checked against `SHA256SUMS` signed by builder key fingerprint `1D1263BE881FF85C5F2947DF291A524038955927`. The miner came from a local macOS rehearsal ZIP. All eight stages passed, and the regtest spend was accepted to the mempool and confirmed in a block. This covers Core rc3 descriptor-wallet recovery for that run; v0.18.3 legacy-wallet recovery remains unverified.

Native debug and release tests ran on macOS arm64. The program and tests were also type-checked for Windows x86-64, Windows arm64, and Linux i686. In a separate native interoperability run, Core's C routines recovered public keys and signed and verified test messages in both strict and legacy modes using newly mined WIFs.
