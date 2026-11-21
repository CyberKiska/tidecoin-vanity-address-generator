//! The public key that Core-compatible Falcon-512 keygen derives from a seed,
//! computed without solving the NTRU equation.
//!
//! PQClean keygen samples (f, g) from SHAKE256(seed) until a pair passes the
//! coefficient, norm, orthogonalized-norm and invertibility checks, computes
//! h = g/f mod q, and only then solves for (F, G). The address depends on h
//! alone, while the solver dominates keygen time. This module repeats the
//! sampling byte for byte and stops at h. If the solver then fails for that
//! pair, Core continues with a later pair, so a match must be regenerated with
//! the exact keygen and its public key compared before use.

use tide_fn_dsa_comm::{codec, mq, shake::SHAKE256};
use tide_fn_dsa_kgen::{FALCON_KEYGEN_SEED_SIZE, FN_DSA_LOGN_512, VRFY_KEY_SIZE_512};
use zeroize::{Zeroize, Zeroizing};

const LOGN: u32 = FN_DSA_LOGN_512;
const N: usize = 1 << LOGN;
const Q: f64 = 12289.0;

// Falcon's CDT for sigma = 1.17 * sqrt(q / 2048), as in Core and tide-fn-dsa.
const GAUSS: [u64; 27] = [
    1283868770400643928,
    6416574995475331444,
    4078260278032692663,
    2353523259288686585,
    1227179971273316331,
    575931623374121527,
    242543240509105209,
    91437049221049666,
    30799446349977173,
    9255276791179340,
    2478152334826140,
    590642893610164,
    125206034929641,
    23590435911403,
    3948334035941,
    586753615614,
    77391054539,
    9056793210,
    940121950,
    86539696,
    7062824,
    510971,
    32764,
    1862,
    94,
    4,
    0,
];

/// Unit roots for the orthogonalized-norm check, built once per worker.
pub struct Preview {
    /// exp(i pi k / N) maps the roots of x^N + 1 onto those of x^N - 1.
    twist: [(f64, f64); N],
    /// exp(2 i pi k / N) for the radix-2 butterflies.
    roots: [(f64, f64); N / 2],
}

impl Preview {
    pub fn new() -> Self {
        let unit = |turns: f64| {
            let (sin, cos) = (turns * std::f64::consts::TAU).sin_cos();
            (cos, sin)
        };
        Self {
            twist: std::array::from_fn(|k| unit(k as f64 / (2 * N) as f64)),
            roots: std::array::from_fn(|k| unit(k as f64 / N as f64)),
        }
    }

    pub fn public_key(
        &self,
        seed: &[u8; FALCON_KEYGEN_SEED_SIZE],
        public: &mut [u8; VRFY_KEY_SIZE_512],
    ) {
        let mut stream = Stream::new(seed);
        let mut fg = Zeroizing::new([[0i8; N]; 2]);
        let mut words = Zeroizing::new([0u16; 2 * N]);
        let [f, g] = &mut *fg;
        loop {
            sample(&mut stream, f);
            sample(&mut stream, g);
            // Rejected pairs are discarded, so these tests need not be constant time.
            let in_range = f.iter().chain(&*g).all(|&x| (-31..=31).contains(&x));
            let norm: i32 = f.iter().chain(&*g).map(|&x| x as i32 * x as i32).sum();
            if !in_range || norm >= 16823 || !self.orthogonal_norm_ok(f, g) {
                continue;
            }
            let (h, scratch) = words.split_at_mut(N);
            if !mq::mqpoly_small_is_invertible(LOGN, f, scratch) {
                continue;
            }
            mq::mqpoly_div_small(LOGN, f, g, h, scratch);
            public[0] = LOGN as u8;
            codec::modq_encode(h, &mut public[1..]).expect("h has N coefficients below q");
            return;
        }
    }

    /// PQClean requires ||q (adj f, adj g) / (f adj f + g adj g)||^2 < 1.17^2 q.
    /// By Parseval that squared norm equals q^2 / N times the sum, over the N
    /// roots of x^N + 1, of 1 / (|f|^2 + |g|^2). Rounding can differ from Core's
    /// FFT only at the bound, where the exact regeneration rejects the pair.
    fn orthogonal_norm_ok(&self, f: &[i8; N], g: &[i8; N]) -> bool {
        let mut values = Zeroizing::new([[0.0; N]; 4]);
        let [f_re, f_im, g_re, g_im] = &mut *values;
        self.evaluate(f, f_re, f_im);
        self.evaluate(g, g_re, g_im);
        let sum: f64 = (0..N)
            .map(|m| {
                1.0 / (f_re[m] * f_re[m]
                    + f_im[m] * f_im[m]
                    + g_re[m] * g_re[m]
                    + g_im[m] * g_im[m])
            })
            .sum();
        // Core's fpr_bnorm_max, 16822.4121.
        sum * Q * Q / (N as f64) < f64::from_bits(4670353323383631276)
    }

    /// Evaluates a at every root of x^N + 1: twist, then a radix-2 DFT.
    fn evaluate(&self, a: &[i8; N], re: &mut [f64; N], im: &mut [f64; N]) {
        for (k, &coef) in a.iter().enumerate() {
            let j = k.reverse_bits() >> (usize::BITS - LOGN);
            let (cos, sin) = self.twist[k];
            (re[j], im[j]) = (coef as f64 * cos, coef as f64 * sin);
        }
        let mut half = 1;
        while half < N {
            let step = N / (2 * half);
            for start in (0..N).step_by(2 * half) {
                for k in 0..half {
                    let (cos, sin) = self.roots[k * step];
                    let (top, bottom) = (start + k, start + k + half);
                    let x_re = re[bottom] * cos - im[bottom] * sin;
                    let x_im = re[bottom] * sin + im[bottom] * cos;
                    (re[bottom], im[bottom]) = (re[top] - x_re, im[top] - x_im);
                    re[top] += x_re;
                    im[top] += x_im;
                }
            }
            half *= 2;
        }
    }
}

/// SHAKE256 output read in blocks. Falcon's get_rng_u64 reads the same
/// stream eight little-endian bytes at a time, so values and order match.
struct Stream {
    shake: SHAKE256,
    buf: [u8; 8 * 136],
    pos: usize,
}

impl Stream {
    fn new(seed: &[u8]) -> Self {
        let mut shake = SHAKE256::new();
        shake.inject(seed).expect("inject precedes flip");
        shake.flip().expect("single flip");
        Self {
            shake,
            buf: [0; 8 * 136],
            pos: 8 * 136,
        }
    }

    fn next_u64(&mut self) -> u64 {
        if self.pos == self.buf.len() {
            self.shake
                .extract(&mut self.buf)
                .expect("extract follows flip");
            self.pos = 0;
        }
        let bytes = self.buf[self.pos..self.pos + 8]
            .try_into()
            .expect("eight bytes");
        self.pos += 8;
        u64::from_le_bytes(bytes)
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.shake.zeroize();
        self.buf.zeroize();
    }
}

/// Falcon's constant-time mkgauss for N = 512: the sum of two CDT samples.
fn mkgauss(stream: &mut Stream) -> i32 {
    let mut val = 0;
    for _ in 0..1 << (10 - LOGN) {
        let mut r = stream.next_u64();
        let neg = (r >> 63) as u32;
        r &= !(1u64 << 63);
        let mut f = (r.wrapping_sub(GAUSS[0]) >> 63) as u32;
        let mut v = 0u32;
        r = stream.next_u64() & !(1u64 << 63);
        for (k, &bound) in GAUSS.iter().enumerate().skip(1) {
            let t = ((r.wrapping_sub(bound) >> 63) ^ 1) as u32;
            v |= (k as u32) & (!(t & (f ^ 1))).wrapping_add(1);
            f |= t;
        }
        v = (v ^ (!neg).wrapping_add(1)).wrapping_add(neg);
        val += v as i32;
    }
    val
}

/// Falcon's poly_small_mkgauss: resample the last coefficient until the sum is
/// odd, which keeps the resultant with x^N + 1 odd.
fn sample(stream: &mut Stream, f: &mut [i8; N]) {
    let mut parity = 0;
    let mut u = 0;
    while u < N {
        let s = mkgauss(stream);
        if !(-127..=127).contains(&s) {
            continue;
        }
        if u == N - 1 {
            if parity ^ (s & 1) == 0 {
                continue;
            }
        } else {
            parity ^= s & 1;
        }
        f[u] = s as i8;
        u += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tide_fn_dsa_kgen::{KeyPairGenerator512, SIGN_KEY_SIZE_512};

    #[test]
    fn previews_match_exact_keygen() {
        let preview = Preview::new();
        let mut generator = KeyPairGenerator512::default();
        let mut secret = vec![0; SIGN_KEY_SIZE_512];
        let (mut exact, mut previewed) = ([0; VRFY_KEY_SIZE_512], [0; VRFY_KEY_SIZE_512]);
        let mut same = 0;
        // Seeds 0, 1 and 2 are the Core C keygen vectors in protocol.rs.
        for byte in 0..24 {
            let seed = [byte; FALCON_KEYGEN_SEED_SIZE];
            preview.public_key(&seed, &mut previewed);
            generator
                .keygen_from_seed_pqclean(LOGN, &seed, &mut secret, &mut exact)
                .unwrap();
            same += (previewed == exact) as u32;
            assert!(byte > 2 || previewed == exact, "Core vector seed {byte}");
        }
        // The solver fails for the first passing pair of roughly 1.5% of seeds.
        assert!(same >= 22, "{same}/24 previews matched");
    }
}
