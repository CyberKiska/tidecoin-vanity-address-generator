use crate::protocol::{ADDRESS_LEN, Address, ScriptHash, address, prefix_bounds};
use std::ops::RangeInclusive;

const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub struct Pattern {
    prefix: Vec<u8>,
    postfix: Vec<u8>,
    range: RangeInclusive<ScriptHash>,
}

impl Pattern {
    pub fn new(prefix: &str, postfix: &str) -> Result<Self, &'static str> {
        if prefix.is_empty() && postfix.is_empty() {
            return Err("supply a nonempty --prefix or --postfix");
        }
        if prefix.len() > ADDRESS_LEN || postfix.len() > ADDRESS_LEN {
            return Err("a mainnet T address is 34 characters long");
        }
        if !prefix
            .bytes()
            .chain(postfix.bytes())
            .all(|b| ALPHABET.contains(&b))
        {
            return Err(
                "patterns must use case-sensitive Bitcoin Base58 characters (no 0, O, I, or l)",
            );
        }
        let prefix = if prefix.is_empty() {
            b"T".as_slice()
        } else {
            prefix.as_bytes()
        };
        if prefix[0] != b'T' {
            return Err("the literal mainnet address prefix must start with T");
        }
        let postfix = postfix.as_bytes();
        let mut mask = [0; ADDRESS_LEN];
        mask[..prefix.len()].copy_from_slice(prefix);
        for (slot, &ch) in mask[ADDRESS_LEN - postfix.len()..].iter_mut().zip(postfix) {
            if *slot != 0 && *slot != ch {
                return Err("prefix and postfix conflict where they overlap");
            }
            *slot = ch;
        }
        let prefix_len = mask.iter().position(|&b| b == 0).unwrap_or(ADDRESS_LEN);
        let gap = (ADDRESS_LEN - postfix.len()).saturating_sub(prefix_len);
        if gap <= 2 && !has_checksummed_completion(mask, prefix_len, gap) {
            return Err("no checksummed mainnet address matches this pattern");
        }
        let prefix = mask[..prefix_len].to_vec();
        let range =
            prefix_bounds(&prefix).ok_or("prefix is outside the mainnet T address range")?;
        let result = Self {
            prefix,
            postfix: postfix.to_vec(),
            range,
        };
        // When a long prefix spans only a few script hashes, check their actual
        // checksums up front. This includes fully specified addresses.
        let mut hash = *result.range.start();
        for _ in 0..128 {
            if result.candidate(&hash).is_some() {
                break;
            }
            if &hash == result.range.end() {
                return Err("no checksummed mainnet address matches this pattern");
            }
            for byte in hash.iter_mut().rev() {
                *byte = byte.wrapping_add(1);
                if *byte != 0 {
                    break;
                }
            }
        }
        Ok(result)
    }

    pub fn candidate(&self, hash: &ScriptHash) -> Option<Address> {
        if !self.range.contains(hash) {
            return None;
        }
        let text = address(hash);
        (text.starts_with(&self.prefix) && text.ends_with(&self.postfix)).then_some(text)
    }
}

// A prefix and a long postfix can leave only one or two free digits even if
// their numeric interval is wide. Check these cases without generating keys.
fn has_checksummed_completion(mut mask: Address, start: usize, gap: usize) -> bool {
    (0..58usize.pow(gap as u32)).any(|mut n| {
        for byte in &mut mask[start..start + gap] {
            *byte = ALPHABET[n % 58];
            n /= 58;
        }
        crate::protocol::is_address(&mask)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_preserve_prefixes_and_overlapping_suffixes() {
        for hash in [[0; 20], [0xff; 20], [42; 20], [0x80; 20]] {
            let encoded = address(&hash);
            let s = std::str::from_utf8(&encoded).unwrap();
            for n in 1..=ADDRESS_LEN {
                let pattern = Pattern::new(&s[..n], "").unwrap();
                assert_eq!(pattern.candidate(&hash), Some(encoded));
                let overlap = Pattern::new(&s[..n], &s[n - 1..]).unwrap();
                assert_eq!(overlap.candidate(&hash), Some(encoded));
            }
            let suffix = Pattern::new("", &s[2..]).unwrap();
            assert_eq!(suffix.candidate(&hash), Some(encoded));
        }
    }

    #[test]
    fn rejects_unreachable_patterns() {
        for (p, s) in [
            ("", ""),
            ("TE0", ""),
            ("", "l"),
            ("", "é"),
            ("TA", &"z".repeat(33)),
            ("T1", ""),
            ("Tz", ""),
            ("A", ""),
            ("", &"a".repeat(35)),
            ("TDGs8UFaMRu5Ru8hBAE7SNkwrtYXBaFXHV", ""),
            ("T", "Gs8UFaMRu5Ru8hBAE7SNkwrtYXBaFXHV"),
        ] {
            assert!(Pattern::new(p, s).is_err(), "accepted {p} / {s}");
        }
    }

    #[test]
    fn prefix_and_postfix_are_literal_and_anchored() {
        let hash = [42; 20];
        let addr = address(&hash);
        let s = std::str::from_utf8(&addr).unwrap();
        assert!(
            Pattern::new(&s[..3], &s[32..])
                .unwrap()
                .candidate(&hash)
                .is_some()
        );
        let middle = (2..32)
            .map(|i| &s[i..i + 2])
            .find(|part| !s.ends_with(part))
            .unwrap();
        assert!(Pattern::new("", middle).unwrap().candidate(&hash).is_none());
    }
}
