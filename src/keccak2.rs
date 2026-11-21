//! Keccak-f[1600] on two states at once.
//!
//! The ARMv8 SHA3 code below is RustCrypto's `keccak` 0.1.6 `armv8.rs`, itself
//! adapted from XKCP's K12 `KeccakP-1600-ARMv8Asha3.S`. Its round body already
//! computes in both 64-bit halves of every vector register and broadcasts the
//! round constant to both. Only the loads and stores change here: they move
//! both halves, so lane i of the two states sits together in `state[i]`.
//!
//! Copyright (c) 2018-2022 RustCrypto Developers. Used under the MIT license:
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to
//! deal in the Software without restriction, including without limitation the
//! rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
//! sell copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions: The above copyright
//! notice and this permission notice shall be included in all copies or
//! substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS",
//! WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
//! TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//! NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
//! FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
//! TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
//! THE USE OR OTHER DEALINGS IN THE SOFTWARE.

use zeroize::Zeroize;

/// Two Keccak states, interleaved: `state[i] = [first[i], second[i]]`.
pub type State2 = [[u64; 2]; 25];

/// Whether `permute_both` handles both states in one pass (ARMv8 SHA3).
pub fn two_way_available() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("sha3")
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

/// Permutes both states, in one pass when `two_way_available()`.
pub fn permute_both(state: &mut State2) {
    #[cfg(target_arch = "aarch64")]
    if two_way_available() {
        // SAFETY: two_way_available() just confirmed FEAT_SHA3.
        unsafe { f1600x2_armv8_sha3(state) };
        return;
    }
    permute_one(state, 0);
    permute_one(state, 1);
}

/// Permutes one of the two states and leaves the other untouched.
pub fn permute_one(state: &mut State2, slot: usize) {
    let mut lanes: [u64; 25] = std::array::from_fn(|i| state[i][slot]);
    keccak::f1600(&mut lanes);
    for (pair, lane) in state.iter_mut().zip(lanes) {
        pair[slot] = lane;
    }
    lanes.zeroize();
}

#[cfg(target_arch = "aarch64")]
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// # Safety
/// The CPU must implement FEAT_SHA3.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha3")]
unsafe fn f1600x2_armv8_sha3(state: &mut State2) {
    // SAFETY: x0 points at 25 * 16 readable and writable bytes and is restored
    // before the stores; x1 walks the 24 round constants; x8 counts rounds.
    // clobber_abi("C") covers v0-v31 on AArch64.
    unsafe {
        core::arch::asm!("
            // Read both states: lane i of each into the two halves of v<i>.
            ld1.2d {{ v0- v3}}, [x0], #64
            ld1.2d {{ v4- v7}}, [x0], #64
            ld1.2d {{ v8-v11}}, [x0], #64
            ld1.2d {{v12-v15}}, [x0], #64
            ld1.2d {{v16-v19}}, [x0], #64
            ld1.2d {{v20-v23}}, [x0], #64
            ld1.2d {{v24}},     [x0]
            sub x0, x0, #384

            0:  sub	x8, x8, #1

            // Theta Calculations
            eor3.16b   v25, v20, v15, v10
            eor3.16b   v26, v21, v16, v11
            eor3.16b   v27, v22, v17, v12
            eor3.16b   v28, v23, v18, v13
            eor3.16b   v29, v24, v19, v14
            eor3.16b   v25, v25,  v5,  v0
            eor3.16b   v26, v26,  v6,  v1
            eor3.16b   v27, v27,  v7,  v2
            eor3.16b   v28, v28,  v8,  v3
            eor3.16b   v29, v29,  v9,  v4
            rax1.2d    v30, v25, v27
            rax1.2d    v31, v26, v28
            rax1.2d    v27, v27, v29
            rax1.2d    v28, v28, v25
            rax1.2d    v29, v29, v26

            // Rho and Phi
            eor.16b     v0,  v0, v29
            xar.2d     v25,  v1, v30, #64 -  1
            xar.2d      v1,  v6, v30, #64 - 44
            xar.2d      v6,  v9, v28, #64 - 20
            xar.2d      v9, v22, v31, #64 - 61
            xar.2d     v22, v14, v28, #64 - 39
            xar.2d     v14, v20, v29, #64 - 18
            xar.2d     v26,  v2, v31, #64 - 62
            xar.2d      v2, v12, v31, #64 - 43
            xar.2d     v12, v13, v27, #64 - 25
            xar.2d     v13, v19, v28, #64 -  8
            xar.2d     v19, v23, v27, #64 - 56
            xar.2d     v23, v15, v29, #64 - 41
            xar.2d     v15,  v4, v28, #64 - 27
            xar.2d     v28, v24, v28, #64 - 14
            xar.2d     v24, v21, v30, #64 -  2
            xar.2d      v8,  v8, v27, #64 - 55
            xar.2d      v4, v16, v30, #64 - 45
            xar.2d     v16,  v5, v29, #64 - 36
            xar.2d      v5,  v3, v27, #64 - 28
            xar.2d     v27, v18, v27, #64 - 21
            xar.2d      v3, v17, v31, #64 - 15
            xar.2d     v30, v11, v30, #64 - 10
            xar.2d     v31,  v7, v31, #64 -  6
            xar.2d     v29, v10, v29, #64 -  3

            // Chi and Iota
            bcax.16b   v20, v26, v22,  v8
            bcax.16b   v21,  v8, v23, v22
            bcax.16b   v22, v22, v24, v23
            bcax.16b   v23, v23, v26, v24
            bcax.16b   v24, v24,  v8, v26

            ld1r.2d    {{v26}}, [x1], #8

            bcax.16b   v17, v30, v19,  v3
            bcax.16b   v18,  v3, v15, v19
            bcax.16b   v19, v19, v16, v15
            bcax.16b   v15, v15, v30, v16
            bcax.16b   v16, v16,  v3, v30

            bcax.16b   v10, v25, v12, v31
            bcax.16b   v11, v31, v13, v12
            bcax.16b   v12, v12, v14, v13
            bcax.16b   v13, v13, v25, v14
            bcax.16b   v14, v14, v31, v25

            bcax.16b    v7, v29,  v9,  v4
            bcax.16b    v8,  v4,  v5,  v9
            bcax.16b    v9,  v9,  v6,  v5
            bcax.16b    v5,  v5, v29,  v6
            bcax.16b    v6,  v6,  v4, v29

            bcax.16b    v3, v27,  v0, v28
            bcax.16b    v4, v28,  v1,  v0
            bcax.16b    v0,  v0,  v2,  v1
            bcax.16b    v1,  v1, v27,  v2
            bcax.16b    v2,  v2, v28, v27

            eor.16b v0,v0,v26

            // Rounds loop
            cbnz    w8, 0b

            // Write both states
            st1.2d	{{ v0- v3}}, [x0], #64
            st1.2d	{{ v4- v7}}, [x0], #64
            st1.2d	{{ v8-v11}}, [x0], #64
            st1.2d	{{v12-v15}}, [x0], #64
            st1.2d	{{v16-v19}}, [x0], #64
            st1.2d	{{v20-v23}}, [x0], #64
            st1.2d	{{v24}},     [x0]
        ",
            inout("x0") state.as_mut_ptr() => _,
            inout("x1") RC.as_ptr() => _,
            inout("x8") RC.len() => _,
            clobber_abi("C"),
            options(nostack)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_states_match_the_scalar_permutation() {
        let mut first: [u64; 25] =
            std::array::from_fn(|i| (i as u64).wrapping_mul(0x9E3779B97F4A7C15));
        let mut second: [u64; 25] = std::array::from_fn(|i| !(i as u64) << 7 ^ 0xA5A5);
        let mut both: State2 = std::array::from_fn(|i| [first[i], second[i]]);
        for round in 0..4 {
            keccak::f1600(&mut first);
            keccak::f1600(&mut second);
            if round % 2 == 0 {
                permute_both(&mut both);
            } else {
                permute_one(&mut both, 0);
                permute_one(&mut both, 1);
            }
            assert_eq!(both, std::array::from_fn(|i| [first[i], second[i]]));
        }
        // One state alone leaves the other as it was.
        permute_one(&mut both, 1);
        keccak::f1600(&mut second);
        assert_eq!(both, std::array::from_fn(|i| [first[i], second[i]]));
    }
}
