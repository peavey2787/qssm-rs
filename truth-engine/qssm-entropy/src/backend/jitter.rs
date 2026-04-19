//! Cross-platform raw CPU jitter from hardware performance counters — **no OS RNG**.
//!
//! All bytes are derived from hardware timer deltas, variable spin/yield delays, and in-place
//! stirring that uses only further timer samples — never OS RNG, CSPRNG, or any
//! other software pseudorandom source.
//!
//! ## Supported architectures
//!
//! | Arch       | Counter                     | Instruction / intrinsic              |
//! |------------|-----------------------------|--------------------------------------|
//! | x86_64     | Time Stamp Counter (TSC)    | `_rdtsc` via `core::arch::x86_64`   |
//! | x86        | Time Stamp Counter (TSC)    | `_rdtsc` via `core::arch::x86`      |
//! | aarch64    | Virtual Timer Count (EL0)   | `mrs Xd, cntvct_el0` via `asm!`     |

use std::hint::spin_loop;
use std::thread;
use std::time::Duration;

use crate::HeError;
use qssm_utils::verify_density;

// ── Architecture-specific hardware counter reads ────────────────────────────

/// Read the raw hardware performance/timer counter.
///
/// # Safety
/// Caller must be on a supported architecture (enforced by `#[cfg]` at module level).
/// The reads are side-effect-free aside from serializing instruction order on x86.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn read_hw_counter() -> u64 {
    core::arch::x86_64::_rdtsc()
}

#[cfg(target_arch = "x86")]
#[inline(always)]
unsafe fn read_hw_counter() -> u64 {
    core::arch::x86::_rdtsc()
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn read_hw_counter() -> u64 {
    let val: u64;
    // CNTVCT_EL0 — virtual timer count register, readable from userspace (EL0)
    // on Linux, macOS, and Windows aarch64.
    core::arch::asm!("mrs {}, cntvct_el0", out(reg) val);
    val
}

// ── Public API ──────────────────────────────────────────────────────────────

const MAX_DENSITY_PASSES: usize = 12;

/// Fill `n` bytes from hardware jitter; retry with stirring until [`verify_density`] passes.
pub fn harvest_hw_jitter(n: usize) -> Result<Vec<u8>, HeError> {
    let mut buf = collect_jitter_bytes(n)?;
    for _ in 0..MAX_DENSITY_PASSES {
        if verify_density(&buf) {
            return Ok(buf);
        }
        stir_in_place_hw_only(&mut buf);
    }
    if verify_density(&buf) {
        Ok(buf)
    } else {
        Err(HeError::JitterDensityRejected)
    }
}

// ── Collection ──────────────────────────────────────────────────────────────

fn collect_jitter_bytes(n: usize) -> Result<Vec<u8>, HeError> {
    let mut out = Vec::with_capacity(n);
    let mut prev = unsafe { read_hw_counter() };
    let mut mix = prev;

    while out.len() < n {
        let spins = (((prev ^ mix) >> 4) & 0x3FF) as usize + 24;
        for _ in 0..spins {
            spin_loop();
        }

        if out.len() % 17 < 6 {
            thread::yield_now();
        }

        let now = unsafe { read_hw_counter() };
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
            let t2 = unsafe { read_hw_counter() };
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

// ── Stirring (hardware-only) ────────────────────────────────────────────────

/// XOR each chunk with fresh hardware timer deltas (hardware-only stirring).
fn stir_in_place_hw_only(buf: &mut [u8]) {
    let mut acc = unsafe { read_hw_counter() };
    for ch in buf.chunks_mut(48) {
        let t0 = unsafe { read_hw_counter() };
        let spins = ((acc ^ t0) as usize & 0x1FF) + 20;
        for _ in 0..spins {
            spin_loop();
        }
        if (acc as usize) & 1 == 0 {
            thread::yield_now();
        }
        let t1 = unsafe { read_hw_counter() };
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
