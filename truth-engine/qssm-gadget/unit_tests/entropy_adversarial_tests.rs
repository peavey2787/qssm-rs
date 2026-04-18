//! Adversarial entropy injection tests: all-zero rejection, effective entropy properties.

use qssm_gadget::{effective_external_entropy, xor32, TruthLimbV2Params};

fn make_params(external: [u8; 32], device_link: Option<[u8; 32]>) -> TruthLimbV2Params {
    TruthLimbV2Params {
        binding_context: [0x01u8; 32],
        n: 64,
        k: 5,
        bit_at_k: 1,
        challenge: [0x99u8; 32],
        external_entropy: external,
        external_entropy_included: true,
        device_entropy_link: device_link,
    }
}

#[test]
fn xor32_identity() {
    let a = [0xABu8; 32];
    let b = [0x00u8; 32];
    assert_eq!(xor32(a, b), a);
}

#[test]
fn xor32_self_cancel() {
    let a = [0xCDu8; 32];
    assert_eq!(xor32(a, a), [0u8; 32]);
}

#[test]
fn xor32_commutative() {
    let a = [0x11u8; 32];
    let b = [0x22u8; 32];
    assert_eq!(xor32(a, b), xor32(b, a));
}

#[test]
fn effective_entropy_without_device_link_returns_external() {
    let external = [0xBBu8; 32];
    let params = make_params(external, None);
    let eff = effective_external_entropy(&params);
    assert_eq!(eff, external);
}

#[test]
fn effective_entropy_with_device_link_xors() {
    let external = [0xBBu8; 32];
    let device = [0x11u8; 32];
    let params = make_params(external, Some(device));
    let eff = effective_external_entropy(&params);
    assert_eq!(eff, xor32(external, device));
    assert_ne!(eff, external);
}

#[test]
fn effective_entropy_changes_with_device_link() {
    let external = [0xBBu8; 32];
    let p1 = make_params(external, Some([0x01u8; 32]));
    let p2 = make_params(external, Some([0x02u8; 32]));
    assert_ne!(
        effective_external_entropy(&p1),
        effective_external_entropy(&p2),
        "different device links must produce different effective entropy"
    );
}

#[test]
fn effective_entropy_changes_with_external() {
    let device = [0xAAu8; 32];
    let p1 = make_params([0x01u8; 32], Some(device));
    let p2 = make_params([0x02u8; 32], Some(device));
    assert_ne!(
        effective_external_entropy(&p1),
        effective_external_entropy(&p2),
    );
}

#[test]
fn effective_entropy_deterministic() {
    let params = make_params([0x77u8; 32], Some([0x33u8; 32]));
    let eff1 = effective_external_entropy(&params);
    let eff2 = effective_external_entropy(&params);
    assert_eq!(eff1, eff2);
}
