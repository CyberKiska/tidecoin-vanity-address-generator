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
| `--out=<DESTINATION>` | Required. Saves one line in the historical `address:WIF` format. An existing destination causes an error. |

Supply at least one pattern. When both are present, the same address must satisfy both. For a quick key-generation or wallet-recovery test, use `--prefix=T`. Progress on stderr reports completed keypairs across all workers. Stdout receives the public address after the key file is saved. Ctrl+C interrupts the search.

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

Each CPU worker uses an independent 48-byte OS-random seed for each Falcon keygen attempt. Tidecoin's Rust backend runs its PQClean-compatible seeded mapping, which reproduces Core's raw public and secret key bytes for the same seed. Workers reuse their buffers. A precomputed numeric prefix range filters script hashes before Base58 conversion. Exact text matching handles range endpoints, suffixes and overlapping patterns. [Tidecoin Falcon implementation](https://github.com/tidecoin/tide-fn-dsa) · [Core Falcon key generation](https://github.com/tidecoin/tidecoin/blob/ffed4e92e60ff2de30361648a71cba64531f9077/src/pq/falcon-512/pqclean.c)

Before exporting, the miner decodes the winning secret, re-derives its public key and checks the address again. Secret buffers owned by the miner are cleared on normal drop. The output file is staged in the destination directory, synced and published with overwrite protection. Unix creation requests mode `0600`. Windows creates the file with a protected owner-only DACL and requires a volume with persistent ACL support. Use a directory under your control. The WIF is unencrypted on disk, and OS swap and crash dumps may contain process memory.

On an eight-core Apple M1, 20-second release-mode samples with a long prefix measured 119 keypairs/s with one worker and 586/s with eight. The measurements include key generation, hashing and matching. As a rough estimate, a three-character suffix alone takes about 58³ attempts on average, or about 5½ minutes at 586/s. Individual runs vary. Prefix probabilities also depend on the mainnet version byte.

## Verification

```sh
cargo test --locked
cargo test --release --locked
cargo clippy --all-targets --locked -- -D warnings
```

The regression tests compare the complete legacy WIF with Core's public fixture, compare seeded key digests with Core's Falcon C implementation, and check a published P2SH script/address vector. They also cover matching, concurrent publication, private output, and rejection of existing files. The published fixture key is public test data. [Core wallet fixture](https://github.com/tidecoin/tidecoin/blob/ffed4e92e60ff2de30361648a71cba64531f9077/src/test/data/falcon512_legacy_wif.json) · [Core address vectors](https://github.com/tidecoin/tidecoin/blob/ffed4e92e60ff2de30361648a71cba64531f9077/src/test/data/key_io_valid.json)

The locked dependency versions were compared with the advisory ranges in the [RustSec database snapshot](https://github.com/RustSec/advisory-db/tree/f291af9b1cc0d21dfcea1709d6b037963cef262b). None of the published ranges in that snapshot applied.

A separate local integration check exercises a running mainnet Tidecoin Core with descriptor RPCs. It creates a disposable key, supplies it to the local CLI via stdin, and compares Core's derived address to the miner's output. It makes read-only RPC calls and discards the disposable key.

```sh
python3 tests/core_descriptor.py --miner ./target/release/tdc-vanity --cli tidecoin-cli
```

Native debug and release tests ran on macOS arm64. The program and tests were also type-checked for Windows x86-64, Windows arm64, and Linux i686. In a separate native interoperability run, Core's C routines recovered public keys and signed and verified test messages in both strict and legacy modes using newly mined WIFs. The local node descriptor RPC check still needs a run against a node.
