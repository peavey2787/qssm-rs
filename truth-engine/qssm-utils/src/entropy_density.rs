//! Heuristic min-entropy / density gate (not a full NIST SP 800-90B certification).

use rayon::prelude::*;

/// Minimum raw byte length for [`verify_density`].
pub const MIN_RAW_BYTES: usize = 256;

const CHUNK: usize = 4096;

/// Parallel bit and byte statistics; rejects obvious non-entropy (constant, extreme bias, simple alternation).
///
/// This is a **heuristic** guard against simulated or pathological inputs, not a formal randomness audit.
#[must_use]
pub fn verify_density(raw_jitter: &[u8]) -> bool {
    if raw_jitter.len() < MIN_RAW_BYTES {
        return false;
    }

    let (ones, zeros) = parallel_bit_counts(raw_jitter);
    let total = ones + zeros;
    if total == 0 {
        return false;
    }
    let p1 = ones as f64 / total as f64;
    let p0 = 1.0 - p1;
    let p_max = p0.max(p1);
    if p_max > 0.99 {
        return false;
    }

    if byte_max_fraction(raw_jitter) > 0.95 {
        return false;
    }

    if bit_transition_rate(raw_jitter) > 0.98 {
        return false;
    }

    if is_square_wave_bytes(raw_jitter) {
        return false;
    }

    true
}

fn parallel_bit_counts(buf: &[u8]) -> (u64, u64) {
    buf.par_chunks(CHUNK)
        .map(|chunk| {
            let mut ones = 0u64;
            for &b in chunk {
                ones += u64::from(b.count_ones());
            }
            let bits = (chunk.len() as u64) * 8;
            (ones, bits - ones)
        })
        .reduce(|| (0u64, 0u64), |a, b| (a.0 + b.0, a.1 + b.1))
}

fn byte_max_fraction(buf: &[u8]) -> f64 {
    let mut hist = [0u32; 256];
    for &b in buf {
        hist[usize::from(b)] += 1;
    }
    let n = buf.len() as f64;
    let mx = hist.iter().copied().max().unwrap_or(0) as f64;
    mx / n
}

fn bit_transition_rate(buf: &[u8]) -> f64 {
    let bit_len = buf.len().saturating_mul(8);
    if bit_len < 2 {
        return 0.0;
    }
    let mut transitions = 0u64;
    let mut prev: Option<bool> = None;
    for &byte in buf {
        for k in 0..8 {
            let bit = ((byte >> k) & 1) == 1;
            if let Some(p) = prev {
                if p != bit {
                    transitions += 1;
                }
            }
            prev = Some(bit);
        }
    }
    transitions as f64 / (bit_len.saturating_sub(1) as f64)
}

fn is_square_wave_bytes(buf: &[u8]) -> bool {
    if buf.len() < 8 {
        return false;
    }
    let mut uniq = [false; 256];
    let mut nuniq = 0usize;
    for &b in buf {
        if !uniq[usize::from(b)] {
            uniq[usize::from(b)] = true;
            nuniq += 1;
            if nuniq > 4 {
                return false;
            }
        }
    }
    if nuniq > 2 {
        return false;
    }
    let mut diff255 = 0usize;
    for w in buf.windows(2) {
        if w[0].abs_diff(w[1]) == 255 {
            diff255 += 1;
        }
    }
    let thresh = (buf.len() - 1) * 9 / 10;
    diff255 >= thresh
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_short_rejected() {
        assert!(!verify_density(&[0xAA; MIN_RAW_BYTES - 1]));
    }

    #[test]
    fn exact_min_boundary_constant_rejected() {
        assert!(!verify_density(&[0x00; MIN_RAW_BYTES]));
    }

    #[test]
    fn all_0xff_rejected() {
        assert!(!verify_density(&[0xFF; 512]));
    }

    #[test]
    fn square_wave_rejected() {
        let v: Vec<u8> = (0..512).map(|i| if i % 2 == 0 { 0x00 } else { 0xFF }).collect();
        assert!(!verify_density(&v));
    }

    #[test]
    fn pseudo_random_accepted() {
        // Knuth multiplicative hash — produces well-distributed byte values
        let v: Vec<u8> = (0u32..512)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 8) as u8)
            .collect();
        assert!(verify_density(&v));
    }

    #[test]
    fn exact_min_boundary_good_data_accepted() {
        let v: Vec<u8> = (0u32..MIN_RAW_BYTES as u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 8) as u8)
            .collect();
        assert!(verify_density(&v));
    }
}
