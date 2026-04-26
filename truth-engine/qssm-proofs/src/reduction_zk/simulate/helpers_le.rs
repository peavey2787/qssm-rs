
fn sample_centered_vec(label: &[u8], binding_context: [u8; 32], bound: u32) -> [i32; N] {
    sample_centered_vec_with_seed(label, binding_context, [0u8; 32], bound)
}

fn sample_centered_vec_with_seed(
    label: &[u8],
    binding_context: [u8; 32],
    simulator_seed: [u8; 32],
    bound: u32,
) -> [i32; N] {
    let modulus = 2 * bound + 1;
    let mut out = [0i32; N];
    for (idx, coeff) in out.iter_mut().enumerate() {
        let idx_bytes = (idx as u32).to_le_bytes();
        let h = hash_domain(
            DOMAIN_ZK_SIM,
            &[
                label,
                simulator_seed.as_slice(),
                binding_context.as_slice(),
                &idx_bytes,
            ],
        );
        let raw = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        *coeff = (raw % modulus) as i32 - bound as i32;
    }
    out
}

fn le_public_binding_fs_bytes(public: &PublicInstance) -> Vec<u8> {
    let _ = LE_FS_PUBLIC_BINDING_LAYOUT_VERSION;
    match public.binding() {
        PublicBinding::DigestCoeffVector { coeffs } => {
            let mut out = Vec::with_capacity(1 + coeffs.len() * 4);
            out.push(1);
            for &coeff in coeffs {
                out.extend_from_slice(&coeff.to_le_bytes());
            }
            out
        }
        _ => Vec::new(),
    }
}

fn le_mu_from_public(public: &PublicInstance) -> RqPoly {
    match public.binding() {
        PublicBinding::DigestCoeffVector { coeffs } => {
            let mut out = [0u32; N];
            out[..coeffs.len()].copy_from_slice(coeffs);
            RqPoly(out)
        }
        _ => RqPoly::zero(),
    }
}

fn le_fs_programmed_query_digest(
    binding_context: &[u8; 32],
    vk: &VerifyingKey,
    public: &PublicInstance,
    commitment: &Commitment,
    t: &RqPoly,
) -> [u8; 32] {
    FiatShamirOracle::le_programmed_query_digest(
        DOMAIN_ZK_SIM,
        binding_context,
        vk,
        public,
        commitment,
        t,
        &le_public_binding_fs_bytes(public),
    )
}

fn le_challenge_poly(seed: &[u8; 32]) -> [i32; C_POLY_SIZE] {
    FiatShamirOracle::le_challenge_poly(seed)
}

fn le_challenge_poly_to_rq(poly: &[i32; C_POLY_SIZE]) -> RqPoly {
    let mut out = [0u32; N];
    for idx in 0..C_POLY_SIZE {
        let coeff = poly[idx];
        out[idx] = if coeff >= 0 {
            (coeff as u32) % Q
        } else {
            Q - ((-coeff) as u32 % Q)
        };
    }
    RqPoly(out)
}

fn le_worst_case_cr_inf_norm(beta: u32, c_poly_size: usize, c_poly_span: i32) -> u64 {
    c_poly_size as u64 * c_poly_span.unsigned_abs() as u64 * u64::from(beta)
}

fn le_required_eta_for_hvzk(
    n: usize,
    beta: u32,
    c_poly_size: usize,
    c_poly_span: i32,
    epsilon_log2: f64,
) -> f64 {
    let worst_case_cr_inf_norm = le_worst_case_cr_inf_norm(beta, c_poly_size, c_poly_span);
    let epsilon = 2f64.powf(epsilon_log2);
    let ln_arg = (2.0 * n as f64) / epsilon;
    11.0 * worst_case_cr_inf_norm as f64 * (ln_arg.ln() / std::f64::consts::PI).sqrt()
}

fn le_challenge_space_log2(c_poly_size: usize, c_poly_span: i32) -> f64 {
    c_poly_size as f64 * ((2 * c_poly_span + 1) as f64).log2()
}

fn le_minimum_gamma_for_support_containment(
    eta: u32,
    beta: u32,
    c_poly_size: usize,
    c_poly_span: i32,
) -> u64 {
    u64::from(eta) + le_worst_case_cr_inf_norm(beta, c_poly_size, c_poly_span)
}

