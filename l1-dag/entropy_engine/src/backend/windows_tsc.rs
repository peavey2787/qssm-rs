//! Windows x86_64: raw CPU jitter from [`_rdtsc`](core::arch::x86_64::_rdtsc) delta sampling (no OS RNG).
//!
//! All bytes are derived from time-stamp-counter deltas, variable spin/yield delays, and in-place
//! stirring that uses only further TSC samples—never `getrandom` or other software RNG.

// SAFETY: `_rdtsc` is only used on `cfg(all(windows, target_arch = "x86_64"))` builds where the
// instruction exists. Reads are side-effect-free aside from serializing instruction order.
use core::arch::x86_64::_rdtsc;
use std::hint::spin_loop;
use std::thread;
use std::time::Duration;

use qssm_utils::verify_density;
use crate::HeError;

const MAX_DENSITY_PASSES: usize = 12;

/// Fill `n` bytes from TSC jitter; retry with stirring until [`verify_density`] passes.
pub fn harvest_tsc_jitter(n: usize) -> Result<Vec<u8>, HeError> {
    let mut buf = collect_tsc_bytes(n)?;
    for _ in 0..MAX_DENSITY_PASSES {
        if verify_density(&buf) {
            return Ok(buf);
        }
        stir_in_place_tsc_only(&mut buf);
    }
    if verify_density(&buf) {
        Ok(buf)
    } else {
        Err(HeError::JitterDensityRejected)
    }
}

fn collect_tsc_bytes(n: usize) -> Result<Vec<u8>, HeError> {
    let mut out = Vec::with_capacity(n);
    let mut prev = unsafe { _rdtsc() };
    let mut mix = prev;

    while out.len() < n {
        let spins = (((prev ^ mix) >> 4) & 0x3FF) as usize + 24;
        for _ in 0..spins {
            spin_loop();
        }

        if out.len() % 17 < 6 {
            thread::yield_now();
        }

        let now = unsafe { _rdtsc() };
        let d = now.wrapping_sub(prev);
        prev = now;
        mix = mix.wrapping_add(d).rotate_left(7) ^ prev;

        let folded = d ^ d.rotate_left(23) ^ mix;
        let bytes = folded.to_le_bytes();
        for (k, &byte) in bytes.iter().enumerate() {
            let j = out.len();
            let m = mix.wrapping_add(j as u64).to_le_bytes();
            out.push(byte ^ m[k % 8]);
            if out.len() >= n {
                break;
            }
        }

        if out.len() < n && out.len() % 23 < 3 {
            let sleep_ns = 80u64.wrapping_add(d & 0x7F).wrapping_mul(4);
            thread::sleep(Duration::from_nanos(sleep_ns.min(500_000)));
            let t2 = unsafe { _rdtsc() };
            let d2 = t2.wrapping_sub(prev);
            prev = t2;
            mix ^= d2.rotate_right(11);
            let b = (d2 as u8)
                .wrapping_add((d2 >> 17) as u8)
                .wrapping_add((d ^ d2) as u8);
            out.push(b);
        }
    }

    out.truncate(n);
    Ok(out)
}

/// XOR each chunk with fresh TSC deltas (hardware-only stirring).
fn stir_in_place_tsc_only(buf: &mut [u8]) {
    let mut acc = unsafe { _rdtsc() };
    for ch in buf.chunks_mut(48) {
        let t0 = unsafe { _rdtsc() };
        let spins = ((acc ^ t0) as usize & 0x1FF) + 20;
        for _ in 0..spins {
            spin_loop();
        }
        if (acc as usize) & 1 == 0 {
            thread::yield_now();
        }
        let t1 = unsafe { _rdtsc() };
        let d = t1.wrapping_sub(t0);
        acc = acc.wrapping_add(d).rotate_left(13);

        for (j, b) in ch.iter_mut().enumerate() {
            let rot = (j as u32).wrapping_mul(3) & 56;
            *b ^= (d >> rot) as u8;
            *b ^= (acc >> ((j * 5) & 56)) as u8;
            *b ^= (d.wrapping_mul(j as u64 + 1)) as u8;
        }
    }
}
