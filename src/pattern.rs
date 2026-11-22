use crate::protocol::{ADDRESS_LEN, Address, ScriptHash, address, prefix_bounds};
use std::ops::RangeInclusive;

const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Refuse patterns whose estimated address trials per match exceed this limit.
/// A pattern that no checksummed address matches has a much higher estimate.
pub const MAX_EXPECTED_ATTEMPTS: f64 = 18_446_744_073_709_551_616.0;

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
        let prefix = mask[..prefix_len].to_vec();
        let range =
            prefix_bounds(&prefix).ok_or("prefix is outside the mainnet T address range")?;
        Ok(Self {
            prefix,
            postfix: postfix.to_vec(),
            range,
        })
    }

    /// Estimated address trials per match. The prefix odds are the width of its
    /// script-hash interval. Trailing digits carry the checksum, so each free
    /// suffix digit is close to uniform.
    pub fn expected_attempts(&self) -> f64 {
        let (lo, hi) = (self.range.start(), self.range.end());
        let mut width = [0u8; 20];
        let mut borrow = 0;
        for i in (0..20).rev() {
            let d = hi[i] as i16 - lo[i] as i16 - borrow;
            borrow = (d < 0) as i16;
            width[i] = (d + 256 * borrow) as u8;
        }
        let width = width.iter().fold(0.0, |acc, &b| acc * 256.0 + b as f64) + 1.0;
        let free_suffix = self.postfix.len().min(ADDRESS_LEN - self.prefix.len());
        2f64.powi(160) / width * 58f64.powi(free_suffix as i32)
    }

    pub fn candidate(&self, hash: &ScriptHash) -> Option<Address> {
        if !self.range.contains(hash) {
            return None;
        }
        let text = address(hash);
        (text.starts_with(&self.prefix) && text.ends_with(&self.postfix)).then_some(text)
    }
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
    fn rejects_invalid_and_infeasible_patterns() {
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
            ("T", &"1".repeat(30)),
            ("TDGs8UFaMRu5Ru8hBAE7", ""),
        ] {
            let feasible = Pattern::new(p, s)
                .is_ok_and(|pattern| pattern.expected_attempts() <= MAX_EXPECTED_ATTEMPTS);
            assert!(!feasible, "accepted {p} / {s}");
        }
    }

    #[test]
    fn expected_attempts_match_pattern_odds() {
        let expected = |p, s| Pattern::new(p, s).unwrap().expected_attempts();
        assert_eq!(expected("T", ""), 1.0);
        assert_eq!(expected("", "zz"), 58.0 * 58.0);
        // Second digits '9' through 'Y' share the version-65 interval.
        assert!((23.0..23.7).contains(&expected("TD", "")));
        assert!((23.0 * 58.0..23.7 * 58.0).contains(&expected("TD", "7")));
        // Overlapping parts are scored once, as the merged address.
        let full = "TDGs8UFaMRu5Ru8hBAE7SNkwrtYXBaFXHU";
        assert_eq!(expected(&full[..20], &full[18..]), expected(full, ""));
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
