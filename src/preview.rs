//! Preview a Falcon-512 public key from a seed without solving the NTRU equation.
//!
//! PQClean keygen samples (f, g) from SHAKE256(seed) until a pair passes the
//! coefficient, norm, orthogonalized-norm and invertibility checks, computes
//! h = g/f mod q, and only then solves for (F, G). The address depends on h
//! alone, while the solver dominates keygen time. This module repeats the
//! sampling byte for byte and stops at h. If the solver then fails for that
//! pair, full keygen continues with a later pair. Regenerate a match with the
//! full Rust generator and compare the public keys before using it.
//!
//! Keccak dominates the remaining work, so two seeds are previewed side by
//! side. With ARMv8 SHA3, every permutation advances both of their streams.

use std::io;

use tide_fn_dsa_comm::{codec, mq};
use tide_fn_dsa_kgen::{FALCON_KEYGEN_SEED_SIZE, FN_DSA_LOGN_512, VRFY_KEY_SIZE_512};
use zeroize::{Zeroize, Zeroizing};

use crate::keccak2::{self, State2};
use crate::protocol::Public;

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

pub type Seed = [u8; FALCON_KEYGEN_SEED_SIZE];

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    NeedsSeed,
    Sampling,
    Ready,
}

/// Previews seeds two at a time. With ARMv8 SHA3, each Keccak permutation
/// advances both SHAKE256 streams; otherwise each stream keeps its own state,
/// which avoids queueing lanes when there is no two-way permutation to share.
pub enum Preview {
    Shared(Pipeline<SharedLanes>),
    Separate(Pipeline<SeparateLanes>),
}

impl Preview {
    pub fn new() -> Self {
        if keccak2::two_way_available() {
            Self::Shared(Pipeline::new())
        } else {
            Self::Separate(Pipeline::new())
        }
    }

    /// Writes the next previewed seed and its public key. `fresh` supplies
    /// new seeds.
    pub fn next(
        &mut self,
        fresh: &mut impl FnMut(&mut Seed) -> io::Result<()>,
        seed: &mut Seed,
        public: &mut Public,
    ) -> io::Result<()> {
        match self {
            Self::Shared(pipeline) => pipeline.next(fresh, seed, public),
            Self::Separate(pipeline) => pipeline.next(fresh, seed, public),
        }
    }
}

pub struct Pipeline<L: Lanes> {
    /// exp(i pi k / N) maps the roots of x^N + 1 onto those of x^N - 1.
    twist: [(f64, f64); N],
    /// exp(2 i pi k / N) for the radix-2 butterflies.
    roots: [(f64, f64); N / 2],
    lanes: Box<L>,
    phase: [Phase; 2],
    seeds: [Seed; 2],
    f: [[i8; N]; 2],
    g: [[i8; N]; 2],
    public: [Public; 2],
}

impl<L: Lanes> Pipeline<L> {
    fn new() -> Self {
        let unit = |turns: f64| {
            let (sin, cos) = (turns * std::f64::consts::TAU).sin_cos();
            (cos, sin)
        };
        Self {
            twist: std::array::from_fn(|k| unit(k as f64 / (2 * N) as f64)),
            roots: std::array::from_fn(|k| unit(k as f64 / N as f64)),
            lanes: L::new(),
            phase: [Phase::NeedsSeed; 2],
            seeds: [[0; FALCON_KEYGEN_SEED_SIZE]; 2],
            f: [[0; N]; 2],
            g: [[0; N]; 2],
            public: [[0; VRFY_KEY_SIZE_512]; 2],
        }
    }

    fn next(
        &mut self,
        fresh: &mut impl FnMut(&mut Seed) -> io::Result<()>,
        seed: &mut Seed,
        public: &mut Public,
    ) -> io::Result<()> {
        loop {
            if let Some(slot) = self.phase.iter().position(|&p| p == Phase::Ready) {
                *seed = self.seeds[slot];
                *public = self.public[slot];
                self.phase[slot] = Phase::NeedsSeed;
                return Ok(());
            }
            for slot in 0..2 {
                if self.phase[slot] == Phase::NeedsSeed {
                    fresh(&mut self.seeds[slot])?;
                    self.lanes.reset(slot, &self.seeds[slot]);
                    self.phase[slot] = Phase::Sampling;
                }
            }
            // One (f, g) pair per slot. Sampling f for both before g for both
            // keeps each shared queue within about one polynomial of its partner.
            for slot in 0..2 {
                sample(&mut *self.lanes, slot, &mut self.f[slot]);
            }
            for slot in 0..2 {
                sample(&mut *self.lanes, slot, &mut self.g[slot]);
            }
            for slot in 0..2 {
                if self.passes(slot) {
                    self.phase[slot] = Phase::Ready;
                }
            }
        }
    }

    /// Core's checks on the slot's pair. On success, stores h as its public key.
    fn passes(&mut self, slot: usize) -> bool {
        let (f, g) = (&self.f[slot], &self.g[slot]);
        // Rejected pairs are discarded, so these tests need not be constant time.
        let in_range = f.iter().chain(g).all(|&x| (-31..=31).contains(&x));
        let norm: i32 = f.iter().chain(g).map(|&x| x as i32 * x as i32).sum();
        if !in_range || norm >= 16823 || !self.orthogonal_norm_ok(f, g) {
            return false;
        }
        let mut words = Zeroizing::new([0u16; 2 * N]);
        let (h, scratch) = words.split_at_mut(N);
        if !mq::mqpoly_small_is_invertible(LOGN, f, scratch) {
            return false;
        }
        mq::mqpoly_div_small(LOGN, f, g, h, scratch);
        let public = &mut self.public[slot];
        public[0] = LOGN as u8;
        codec::modq_encode(h, &mut public[1..]).expect("h has N coefficients below q");
        true
    }

    /// PQClean requires ||q (adj f, adj g) / (f adj f + g adj g)||^2 < 1.17^2 q.
    /// By Parseval that squared norm equals q^2 / N times the sum, over the N
    /// roots of x^N + 1, of 1 / (|f|^2 + |g|^2). Rounding differences can affect
    /// which pair passes near the bound. The worker discards a match if the
    /// full Rust generator returns a different public key.
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

impl<L: Lanes> Drop for Pipeline<L> {
    fn drop(&mut self) {
        self.seeds.zeroize();
        self.f.zeroize();
        self.g.zeroize();
    }
}

const RATE_LANES: usize = 136 / 8;
/// Lanes a slot can hold unread: room for two polynomials (2 * 2048 values).
const QUEUE: usize = 4096;

/// Two SHAKE256 streams squeezed one Keccak lane at a time. Falcon's
/// get_rng_u64 reads eight little-endian bytes at a time from offset 0, and the
/// 136-byte rate is 17 whole lanes, so every value it reads is one state lane.
pub trait Lanes {
    fn new() -> Box<Self>;
    /// Starts the slot's stream over from a 48-byte seed.
    fn reset(&mut self, slot: usize, seed: &Seed);
    fn next(&mut self, slot: usize) -> u64;
}

/// SHAKE256 state after absorbing a 48-byte seed: the suffix 1111 and the
/// first pad bit follow the seed, the last pad bit ends the 136-byte rate.
fn absorb(seed: &Seed) -> [u64; 25] {
    let mut state = [0; 25];
    for (lane, bytes) in state.iter_mut().zip(seed.as_chunks::<8>().0) {
        *lane = u64::from_le_bytes(*bytes);
    }
    state[FALCON_KEYGEN_SEED_SIZE / 8] ^= 0x1F;
    state[RATE_LANES - 1] ^= 0x80 << 56;
    state
}

/// Each stream keeps its own state and is read in place.
pub struct SeparateLanes {
    state: [[u64; 25]; 2],
    lane: [usize; 2],
}

impl Lanes for SeparateLanes {
    fn new() -> Box<Self> {
        Box::new(Self {
            state: [[0; 25]; 2],
            lane: [RATE_LANES; 2],
        })
    }

    fn reset(&mut self, slot: usize, seed: &Seed) {
        self.state[slot] = absorb(seed);
        self.lane[slot] = RATE_LANES;
    }

    #[inline(always)]
    fn next(&mut self, slot: usize) -> u64 {
        if self.lane[slot] == RATE_LANES {
            keccak::f1600(&mut self.state[slot]);
            self.lane[slot] = 0;
        }
        self.lane[slot] += 1;
        self.state[slot][self.lane[slot] - 1]
    }
}

impl Drop for SeparateLanes {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

/// Both streams share each two-way permutation, which also queues the new
/// block of each, so a slot never loses lanes it has not read.
pub struct SharedLanes {
    state: State2,
    queue: [[u64; QUEUE]; 2],
    /// Read and write counts; `tail - head` lanes are waiting.
    head: [usize; 2],
    tail: [usize; 2],
}

impl Lanes for SharedLanes {
    fn new() -> Box<Self> {
        Box::new(Self {
            state: [[0; 2]; 25],
            queue: [[0; QUEUE]; 2],
            head: [0; 2],
            tail: [0; 2],
        })
    }

    /// Also drops the slot's unread lanes, which belong to its previous seed.
    fn reset(&mut self, slot: usize, seed: &Seed) {
        let mut absorbed = absorb(seed);
        for (pair, &lane) in self.state.iter_mut().zip(&absorbed) {
            pair[slot] = lane;
        }
        absorbed.zeroize();
        self.head[slot] = self.tail[slot];
    }

    // Called for every lane: keep it inline, and the permutation out of line.
    #[inline(always)]
    fn next(&mut self, slot: usize) -> u64 {
        if self.head[slot] == self.tail[slot] {
            self.refill(slot);
        }
        let value = self.queue[slot][self.head[slot] % QUEUE];
        self.head[slot] += 1;
        value
    }
}

impl SharedLanes {
    #[inline(never)]
    fn refill(&mut self, slot: usize) {
        let other = 1 - slot;
        if self.tail[other] - self.head[other] + RATE_LANES <= QUEUE {
            keccak2::permute_both(&mut self.state);
            self.push(0);
            self.push(1);
        } else {
            // The partner has two polynomials waiting: advance this slot alone.
            keccak2::permute_one(&mut self.state, slot);
            self.push(slot);
        }
    }

    fn push(&mut self, slot: usize) {
        for pair in &self.state[..RATE_LANES] {
            self.queue[slot][self.tail[slot] % QUEUE] = pair[slot];
            self.tail[slot] += 1;
        }
    }
}

impl Drop for SharedLanes {
    fn drop(&mut self) {
        self.state.zeroize();
        self.queue.zeroize();
    }
}

/// Falcon's mkgauss for N = 512: the sum of two CDT samples.
fn mkgauss(lanes: &mut impl Lanes, slot: usize) -> i32 {
    let mut val = 0;
    for _ in 0..1 << (10 - LOGN) {
        let r0 = lanes.next(slot);
        val += cdt(r0, lanes.next(slot));
    }
    val
}

/// One signed CDT sample. Falcon scans the table for the first entry at or
/// below r1 and stops updating there. GAUSS[1..] strictly decreases, so that
/// index is one plus the number of entries above r1: a branch-free count the
/// compiler can vectorize. r0 supplies the sign and the zero test.
fn cdt(r0: u64, r1: u64) -> i32 {
    const LOW63: u64 = !(1 << 63);
    let neg = (r0 >> 63) as i32;
    let nonzero = ((r0 & LOW63).wrapping_sub(GAUSS[0]) >> 63) ^ 1;
    let r1 = r1 & LOW63;
    // For 63-bit values, the top bit of r1 - g is set exactly when r1 < g.
    let above: u64 = GAUSS[1..].iter().map(|&g| r1.wrapping_sub(g) >> 63).sum();
    let v = ((1 + above) & nonzero.wrapping_neg()) as i32;
    (v ^ -neg) + neg
}

/// Falcon's poly_small_mkgauss: resample the last coefficient until the sum is
/// odd, which keeps the resultant with x^N + 1 odd.
fn sample(lanes: &mut impl Lanes, slot: usize, f: &mut [i8; N]) {
    let mut parity = 0;
    let mut u = 0;
    while u < N {
        let s = mkgauss(lanes, slot);
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
    use tide_fn_dsa_comm::shake::SHAKE256;
    use tide_fn_dsa_kgen::{KeyPairGenerator512, SIGN_KEY_SIZE_512};

    /// Falcon's scan, as written in Core and tide-fn-dsa.
    fn reference_cdt(r0: u64, r1: u64) -> i32 {
        let neg = (r0 >> 63) as u32;
        let mut f = ((r0 & !(1u64 << 63)).wrapping_sub(GAUSS[0]) >> 63) as u32;
        let r = r1 & !(1u64 << 63);
        let mut v = 0u32;
        for (k, &bound) in GAUSS.iter().enumerate().skip(1) {
            let t = ((r.wrapping_sub(bound) >> 63) ^ 1) as u32;
            v |= (k as u32) & (!(t & (f ^ 1))).wrapping_add(1);
            f |= t;
        }
        (v ^ (!neg).wrapping_add(1)).wrapping_add(neg) as i32
    }

    #[test]
    fn counting_cdt_matches_falcons_scan() {
        // Every table boundary, with and without the sign and top bits.
        let mut values: Vec<u64> = GAUSS
            .iter()
            .flat_map(|&g| [g.wrapping_sub(1), g, g + 1])
            .chain([0, u64::MAX >> 1, u64::MAX])
            .collect();
        values.extend(values.clone().iter().map(|v| v | 1 << 63));
        for &r0 in &values {
            for &r1 in &values {
                assert_eq!(cdt(r0, r1), reference_cdt(r0, r1), "{r0:#x} {r1:#x}");
            }
        }
        let mut lanes = SeparateLanes::new();
        lanes.reset(0, &[7; FALCON_KEYGEN_SEED_SIZE]);
        for _ in 0..200_000 {
            let (r0, r1) = (lanes.next(0), lanes.next(0));
            assert_eq!(cdt(r0, r1), reference_cdt(r0, r1));
        }
    }

    fn reproduces_shake256<L: Lanes>() {
        let shake = |byte| {
            let mut shake = SHAKE256::new();
            shake.inject(&[byte; FALCON_KEYGEN_SEED_SIZE]).unwrap();
            shake.flip().unwrap();
            shake
        };
        let mut expected = [shake(0x5a), shake(0xa5)];
        let mut lanes = L::new();
        lanes.reset(0, &[0x5a; FALCON_KEYGEN_SEED_SIZE]);
        lanes.reset(1, &[0xa5; FALCON_KEYGEN_SEED_SIZE]);
        let read = |lanes: &mut L, expected: &mut [SHAKE256; 2], slot: usize, count| {
            for _ in 0..count {
                let mut bytes = [0; 8];
                expected[slot].extract(&mut bytes).unwrap();
                assert_eq!(lanes.next(slot), u64::from_le_bytes(bytes));
            }
        };
        // Uneven reads, then enough from one slot to fill a shared partner queue.
        read(&mut lanes, &mut expected, 0, 3);
        read(&mut lanes, &mut expected, 1, 50);
        read(&mut lanes, &mut expected, 0, 2 * QUEUE);
        read(&mut lanes, &mut expected, 1, QUEUE + 100);
        // Reseeding one slot mid-stream leaves the other intact.
        lanes.reset(0, &[0x00; FALCON_KEYGEN_SEED_SIZE]);
        expected[0] = shake(0x00);
        read(&mut lanes, &mut expected, 0, 300);
        read(&mut lanes, &mut expected, 1, 40);
    }

    #[test]
    fn both_lane_sources_reproduce_each_shake256_stream() {
        reproduces_shake256::<SharedLanes>();
        reproduces_shake256::<SeparateLanes>();
    }

    #[test]
    fn both_pipelines_yield_the_same_candidates() {
        let mut shared = Pipeline::<SharedLanes>::new();
        let mut separate = Pipeline::<SeparateLanes>::new();
        let counter = |mut next: u8| {
            move |seed: &mut Seed| {
                *seed = [next; FALCON_KEYGEN_SEED_SIZE];
                next = next.wrapping_add(1);
                Ok(())
            }
        };
        let (mut a, mut b) = (counter(100), counter(100));
        let (mut seed_a, mut seed_b) = ([0; FALCON_KEYGEN_SEED_SIZE], [0; FALCON_KEYGEN_SEED_SIZE]);
        let (mut public_a, mut public_b) = ([0; VRFY_KEY_SIZE_512], [0; VRFY_KEY_SIZE_512]);
        for _ in 0..8 {
            shared.next(&mut a, &mut seed_a, &mut public_a).unwrap();
            separate.next(&mut b, &mut seed_b, &mut public_b).unwrap();
            assert_eq!((seed_a, public_a), (seed_b, public_b));
        }
    }

    /// SHA-256 over `seed || public key` for the first `count` previews, in
    /// completion order, with seed i = SHA-384(LE64(i)) supplied in request order.
    fn mapping_digest(preview: &mut Preview, count: usize) -> String {
        use sha2::{Digest, Sha256, Sha384};
        let mut next = 0u64;
        let mut fresh = |seed: &mut Seed| {
            seed.copy_from_slice(&Sha384::digest(next.to_le_bytes()));
            next += 1;
            Ok(())
        };
        let (mut seed, mut public) = ([0; FALCON_KEYGEN_SEED_SIZE], [0; VRFY_KEY_SIZE_512]);
        let mut digest = Sha256::new();
        for _ in 0..count {
            preview.next(&mut fresh, &mut seed, &mut public).unwrap();
            digest.update(seed);
            digest.update(public);
        }
        hex::encode(digest.finalize())
    }

    #[test]
    fn preview_mapping_is_unchanged() {
        // The first 256 records of the anchored 8,192-record run below.
        for mut preview in [
            Preview::Shared(Pipeline::new()),
            Preview::Separate(Pipeline::new()),
        ] {
            assert_eq!(
                mapping_digest(&mut preview, 256),
                "25bddd84feaabc31a33f886662f99ef334db8e6b73374bb609df8bdb02592d29"
            );
        }
    }

    /// Fixed-work benchmark: `cargo test --release -- --ignored --show-output`.
    #[test]
    #[ignore = "release-mode benchmark"]
    fn preview_mapping_benchmark() {
        const RECORDS: usize = 8192;
        let start = std::time::Instant::now();
        let digest = mapping_digest(&mut Preview::new(), RECORDS);
        let elapsed = start.elapsed().as_secs_f64();
        // Measured on the two-slot pipeline at b058549.
        assert_eq!(
            digest,
            "2d5aedb6804ae1aea9a041266889c282c8a83c5f71ad6e66e5949d3b6d544205"
        );
        println!(
            "{RECORDS} previews in {elapsed:.3} s, {:.0} previews/s on one thread",
            RECORDS as f64 / elapsed
        );
    }

    #[test]
    fn previews_match_exact_keygen() {
        let mut preview = Preview::new();
        let mut generator = KeyPairGenerator512::default();
        let mut secret = vec![0; SIGN_KEY_SIZE_512];
        let (mut exact, mut previewed) = ([0; VRFY_KEY_SIZE_512], [0; VRFY_KEY_SIZE_512]);
        let mut seed = [0; FALCON_KEYGEN_SEED_SIZE];
        let mut next_byte = 0;
        let mut fresh = |seed: &mut Seed| {
            *seed = [next_byte; FALCON_KEYGEN_SEED_SIZE];
            next_byte += 1;
            Ok(())
        };
        let (mut same, mut vectors) = (0, 0);
        for _ in 0..24 {
            preview.next(&mut fresh, &mut seed, &mut previewed).unwrap();
            generator
                .keygen_from_seed_pqclean(LOGN, &seed, &mut secret, &mut exact)
                .unwrap();
            same += (previewed == exact) as u32;
            // Seeds 0, 1 and 2 are the Core C keygen vectors in protocol.rs.
            if seed[0] <= 2 {
                assert_eq!(previewed, exact, "Core vector seed {}", seed[0]);
                vectors += 1;
            }
        }
        assert_eq!(vectors, 3);
        // The solver fails for the first passing pair of roughly 2% of seeds.
        assert!(same >= 22, "{same}/24 previews matched");
    }
}
