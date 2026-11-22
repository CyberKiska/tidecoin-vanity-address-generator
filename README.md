# tdc-vanity

A parallel Rust CLI for mining Tidecoin mainnet `T…` addresses. It searches for a Falcon-512 key whose P2SH-wrapped witness-v0 key-hash address matches the requested text. Each invocation stops after saving one match.

## Build and run

Use a stable Rust toolchain and Cargo. The first build downloads the dependencies pinned in `Cargo.lock`. The executable works offline.

```sh
cargo build --release --locked
./target/release/tdc-vanity --prefix=TD --postfix=7 --out=match.wif
```

The downloadable archive includes the tested Apple Silicon release binary at `bin/macos-arm64/tdc-vanity`. On Windows the Cargo-built executable is `target\release\tdc-vanity.exe`. Choose an existing private directory and a new filename for each run.

| Option | Behavior |
| --- | --- |
| `--prefix=<PREFIX>` | Exact, case-sensitive start of the displayed address, including the initial `T`. |
| `--postfix=<POSTFIX>` | Exact, case-sensitive end of the address, including its checksum characters. |
| `--workers=<NUMBER_OF_THREADS>` | Positive integer. Defaults to the logical CPU count available to the process. |
| `--out=<DESTINATION>` | Required. Saves one line in the historical `address:WIF` format. The path must name a new file and cannot end with a directory separator. |

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

The export implements v0.18.3's WIF and modern Core's `EncodeSecretLegacy`. Newer Core also supports a shorter scheme-prefixed private-key export. The program targets the historical script's mainnet address and key format. [v0.18.3 key I/O](https://github.com/tidecoin/tidecoin/blob/7b525367e9ea1b614aa380a52394f0e3d3878aa9/src/key_io.cpp) · [Modern key I/O](https://github.com/tidecoin/tidecoin/blob/ffed4e92e60ff2de30361648a71cba64531f9077/src/key_io.cpp) · [Mainnet parameters](https://github.com/tidecoin/tidecoin/blob/ffed4e92e60ff2de30361648a71cba64531f9077/src/kernel/chainparams.cpp) · [Descriptor expansion](https://github.com/tidecoin/tidecoin/blob/ffed4e92e60ff2de30361648a71cba64531f9077/src/script/descriptor.cpp)

## Search and key handling

Each CPU worker uses an independent 48-byte OS-random seed for each candidate keypair. Core's PQClean key generation samples (f, g) from SHAKE256 of the seed until a pair passes its coefficient, norm, orthogonalized-norm and invertibility checks. It then computes the public key h = g/f mod q, and only after that solves the NTRU equation, which dominates key generation time. The address depends on h alone. Workers therefore repeat the sampling byte for byte, stop at h and hash it. Only a matching seed goes through the full key generation of Tidecoin's Rust backend, whose PQClean-compatible mapping reproduces Core's raw public and secret key bytes for the same seed. The match is kept only if that yields the same public key. For about 2% of seeds it does not: solving fails for the first passing pair, and Core moves on to a later pair. Every exported key is therefore exactly Core's key for its seed. The orthogonalized-norm check uses native floating point and Parseval's identity. Its rounding can differ from Core's only at the bound, and the full key generation settles such cases. The preview squeezes SHAKE256 one Keccak lane at a time with RustCrypto's `keccak` crate, which uses ARMv8 SHA3 instructions when the CPU has them. Each worker previews two seeds side by side. With ARMv8 SHA3, a two-state version of that crate's assembly advances both streams in each permutation, and each stream queues the lanes it has not read yet. Other CPUs keep one state per seed. The Gaussian sampler counts the table entries above each random value instead of scanning for the first entry below it. Because the table strictly decreases, the result is the same, and the count is constant time. Workers reuse their buffers. A precomputed numeric prefix range filters script hashes before Base58 conversion. Exact text matching handles range endpoints, suffixes and overlapping patterns. [Tidecoin Falcon implementation](https://github.com/tidecoin/tide-fn-dsa) · [Core Falcon key generation](https://github.com/tidecoin/tidecoin/blob/ffed4e92e60ff2de30361648a71cba64531f9077/src/pq/falcon-512/pqclean.c)

Before exporting, the miner decodes the winning secret, re-derives its public key and checks the address again. It also checks the NTRU equation fG − gF = q over the integers, as Core's key generation does. Secret buffers owned by the miner are cleared on normal drop.

The miner writes and syncs a staging file named `.tdc-vanity-*.wif` in the destination directory, then publishes it with overwrite protection. If another process creates the destination first, both records are preserved. The miner exits with an error and reports the path of the retained staging file on stderr. On Unix, it syncs the directory after publishing a file or retaining it for recovery.

Unix file creation requests mode `0600` subject to the process umask. The miner checks the open preflight and staging files for ownership, owner read permission, and absence of group or other permissions. An umask such as `0777` that removes owner read permission causes preflight to fail. macOS also refuses new files with inherited ACL entries and fails if it cannot inspect the ACL. Windows creates the file with a protected owner-only DACL and requires a volume with persistent ACL support. Use a directory under your control. The WIF is unencrypted on disk, and OS swap and crash dumps may contain process memory.

On an eight-core Apple M1 (four performance and four efficiency cores), 15-second release-mode samples with a long prefix measured 2,867 candidates/s with one worker and 14,024/s with eight. Running full key generation for every candidate measured 590/s with eight workers. The measurements include seed generation, hashing and matching. Keccak still takes over half the time: each candidate needs about 2,550 permutations, now shared in pairs. A build forced onto the separate-state path measured 1,913/s and 9,451/s. As a rough estimate, a four-character suffix alone takes about 58⁴ attempts on average, or about 14 minutes at 14,000/s. Individual runs vary. Prefix probabilities also depend on the mainnet version byte.

## Verification

```sh
cargo test --locked
cargo test --release --locked
cargo clippy --all-targets --locked -- -D warnings
```

The regression tests compare the complete legacy WIF with Core's public fixture, compare seeded key digests with Core's Falcon C implementation, and check a published P2SH script/address vector. A preview test requires the public-key preview to equal full key generation for Core's seeded vectors and for nearly all of 24 fixed seeds. In a separate run on 2,000 random seeds, the preview agreed on all 2,000 with a reference built from the backend's own internal checks. Further tests compare the counting sampler with Falcon's scan at every table boundary and on 200,000 stream values. They also compare the two-state permutation with the scalar one, both lane sources with the backend's SHAKE256 through uneven reads, a full queue and a reseed, and the two pipelines' candidates with each other. They also cover matching, difficulty limits, a forged key that passes decoding but fails the NTRU equation, concurrent publication that keeps the losing record, private output including inherited macOS ACLs, and rejection of existing files. The published fixture key is public test data. [Core wallet fixture](https://github.com/tidecoin/tidecoin/blob/ffed4e92e60ff2de30361648a71cba64531f9077/src/test/data/falcon512_legacy_wif.json) · [Core address vectors](https://github.com/tidecoin/tidecoin/blob/ffed4e92e60ff2de30361648a71cba64531f9077/src/test/data/key_io_valid.json)

The locked dependency versions were compared with the advisory ranges in the [RustSec database snapshot](https://github.com/RustSec/advisory-db/tree/f291af9b1cc0d21dfcea1709d6b037963cef262b). None of the published ranges in that snapshot applied.

A separate local integration check exercises a running mainnet Tidecoin Core with descriptor RPCs. It creates a disposable key, supplies it to the local CLI via stdin, and compares Core's derived address to the miner's output. It makes read-only RPC calls and discards the disposable key.

```sh
python3 tests/core_descriptor.py --miner ./target/release/tdc-vanity --cli tidecoin-cli
```

Native debug and release tests ran on macOS arm64. The program and tests were also type-checked for Windows x86-64, Windows arm64, and Linux i686. In a separate native interoperability run, Core's C routines recovered public keys and signed and verified test messages in both strict and legacy modes using newly mined WIFs. The local node descriptor RPC check still needs a run against a node.
