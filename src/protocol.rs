//! Mainnet sh(wpkh(Falcon-512)) and the v0.18.3 wallet import format.
use std::io;
use std::ops::RangeInclusive;

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use tide_fn_dsa_kgen::{
    DeterministicKeyGenError, FALCON_KEYGEN_SEED_SIZE, FN_DSA_LOGN_512, KeyPairGenerator512,
    SIGN_KEY_SIZE_512, VRFY_KEY_SIZE_512,
};
use tide_fn_dsa_sign::{SigningKey, SigningKey512};
use zeroize::Zeroizing;

pub const ADDRESS_LEN: usize = 34;
const SCRIPT_VERSION: u8 = 65;
const WIF_VERSION: u8 = 125;
const SCHEME: u8 = 7;
pub type ScriptHash = [u8; 20];
pub type Address = [u8; ADDRESS_LEN];
type Public = [u8; VRFY_KEY_SIZE_512];

pub struct KeyPair {
    // Keep one allocation at a stable address even when transferring a winning pair.
    secret: Zeroizing<Box<[u8]>>,
    public: Public,
}

impl KeyPair {
    pub fn empty() -> Self {
        Self {
            secret: Zeroizing::new(vec![0; SIGN_KEY_SIZE_512].into_boxed_slice()),
            public: [0; VRFY_KEY_SIZE_512],
        }
    }

    pub fn generate(&mut self, generator: &mut KeyPairGenerator512) -> io::Result<()> {
        let mut seed = Zeroizing::new([0; FALCON_KEYGEN_SEED_SIZE]);
        for _ in 0..10_000 {
            getrandom::fill(&mut *seed).map_err(io::Error::other)?;
            match generator.keygen_from_seed_pqclean(
                FN_DSA_LOGN_512,
                &*seed,
                &mut self.secret,
                &mut self.public,
            ) {
                Ok(()) => return Ok(()),
                Err(DeterministicKeyGenError::RejectedSeed) => continue,
                Err(e) => return Err(io::Error::other(e.to_string())),
            }
        }
        Err(io::Error::other(
            "Falcon key generation exhausted Core's retry limit",
        ))
    }

    pub fn script_hash(&self) -> ScriptHash {
        script_hash(&self.public)
    }

    pub fn verified_wif(&self, expected: &Address) -> io::Result<Zeroizing<Vec<u8>>> {
        let sk = SigningKey512::decode(&self.secret)
            .ok_or_else(|| io::Error::other("Falcon secret-key validation failed"))?;
        let mut derived = [0; VRFY_KEY_SIZE_512];
        sk.to_verifying_key(&mut derived)
            .map_err(|e| io::Error::other(e.to_string()))?;
        if self.public != derived || &address(&script_hash(&derived)) != expected {
            return Err(io::Error::other(
                "public key or address disagrees with the secret key",
            ));
        }
        // 0x7d || raw secret || 0x01 || raw public || checksum.
        let mut body = Zeroizing::new(Vec::with_capacity(
            SIGN_KEY_SIZE_512 + 1 + VRFY_KEY_SIZE_512,
        ));
        body.extend_from_slice(&self.secret);
        body.push(1);
        body.extend_from_slice(&derived);
        let mut out = Zeroizing::new(vec![0; (body.len() + 5) * 3 / 2 + 1]);
        let len = bs58::encode(&*body)
            .with_check_version(WIF_VERSION)
            .onto(out.as_mut_slice())
            .map_err(|e| io::Error::other(e.to_string()))?;
        out.truncate(len);
        Ok(out)
    }
}

fn script_hash(public: &Public) -> ScriptHash {
    // CPubKey::GetID hashes all 898 bytes, including both the scheme and Falcon headers.
    let sha = Sha256::new()
        .chain_update([SCHEME])
        .chain_update(public)
        .finalize();
    let mut redeem = [0; 22];
    redeem[1] = 20;
    redeem[2..].copy_from_slice(&Ripemd160::digest(sha));
    Ripemd160::digest(Sha256::digest(redeem)).into()
}

pub fn address(hash: &ScriptHash) -> Address {
    let mut bytes = [0; ADDRESS_LEN];
    let len = bs58::encode(hash)
        .with_check_version(SCRIPT_VERSION)
        .onto(&mut bytes[..])
        .expect("a version-65 address occupies 34 Base58 digits");
    debug_assert_eq!(len, bytes.len());
    bytes
}

/// Conservative script-hash bounds for a literal prefix. Only the two boundary
/// hash values can depend on the checksum. Always check the final text on a hit.
pub fn prefix_bounds(prefix: &[u8]) -> Option<RangeInclusive<ScriptHash>> {
    fn endpoint(prefix: &[u8], fill: u8) -> Option<[u8; 25]> {
        let mut text = [fill; ADDRESS_LEN];
        text[..prefix.len()].copy_from_slice(prefix);
        let mut bytes = [0; 25];
        (bs58::decode(text).onto(&mut bytes[..]).ok()? == bytes.len()).then_some(bytes)
    }
    let lo = endpoint(prefix, b'1')?;
    let hi = endpoint(prefix, b'z')?;
    if hi[0] < SCRIPT_VERSION || lo[0] > SCRIPT_VERSION {
        return None;
    }
    let first = if lo[0] == SCRIPT_VERSION {
        lo[1..21].try_into().ok()?
    } else {
        [0; 20]
    };
    let last = if hi[0] == SCRIPT_VERSION {
        hi[1..21].try_into().ok()?
    } else {
        [255; 20]
    };
    Some(first..=last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_keys_match_core_c_keygen() {
        // SHA-256 of raw encoded keys from Core crypto_sign_keypair_deterministic.
        let vectors = [
            (
                0,
                "049a39503b551ae8695c1ff40a16f12e7a40df3a1b666dd25f2c95a182487440",
                "e18d9980ecd7dc95d2ef4c65be1101e7657433dd3ecaffb8b78e68935669581d",
            ),
            (
                1,
                "21d87d4443761e214c23ca99028081670b1656a789bfa955dcd0a4ecfc3754cc",
                "c24cb48c546579fe40bfe592a97beb442fd8a748dfa9b83523639ffc2d949dce",
            ),
            (
                2,
                "54a1e2ce62e64f685fda7da25652a2fef700f40581d43e27d2a8ee685a4b75a8",
                "f060912dedd19446e15a2f4acb835ff715030f7236e259f4de19752272a40cf5",
            ),
        ];
        let mut generator = KeyPairGenerator512::default();
        let mut pair = KeyPair::empty();
        for (byte, pk, sk) in vectors {
            generator
                .keygen_from_seed_pqclean(
                    FN_DSA_LOGN_512,
                    &[byte; 48],
                    &mut pair.secret,
                    &mut pair.public,
                )
                .unwrap();
            assert_eq!(hex::encode(Sha256::digest(pair.public)), pk);
            assert_eq!(hex::encode(Sha256::digest(&*pair.secret)), sk);
        }
    }

    #[test]
    fn core_script_destination_vector() {
        let hash = hex::decode("373b819a068f32b7a6b38b6b38729647cfde01c2").unwrap();
        assert_eq!(
            &address(&hash.try_into().unwrap()),
            b"TF1FTBDCgzZVe9wyCgqTMch7CgSMam5PbF"
        );
    }

    #[test]
    fn core_legacy_wif_and_wrapped_address() {
        let mut f = include_str!("../tests/data/core-legacy-falcon512.txt")
            .lines()
            .skip(1);
        let mut pair = KeyPair::empty();
        hex::decode_to_slice(f.next().unwrap(), &mut pair.secret).unwrap();
        let prefixed = hex::decode(f.next().unwrap()).unwrap();
        assert_eq!(prefixed[0], SCHEME);
        pair.public.copy_from_slice(&prefixed[1..]);
        let addr = address(&pair.script_hash());
        assert_eq!(&addr, b"TDGs8UFaMRu5Ru8hBAE7SNkwrtYXBaFXHU");
        assert_eq!(
            pair.verified_wif(&addr).unwrap().as_slice(),
            f.next().unwrap().as_bytes()
        );
        pair.public[20] ^= 1;
        assert!(pair.verified_wif(&address(&pair.script_hash())).is_err());
    }
}
