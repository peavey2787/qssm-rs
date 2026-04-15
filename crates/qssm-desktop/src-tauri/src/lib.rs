mod commands;
mod geo;
mod identity;
mod sidecar;

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let mmdbs = sidecar::mmdb_candidates(&app.handle());
            sidecar::ensure_local_backup(&app.handle());
            sidecar::spawn_command_center(&app.handle(), mmdbs);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::toggle_hardware_harvest,
            commands::retry_network_sidecar,
            commands::generate_mnemonic_24,
            commands::validate_mnemonic_24,
            commands::list_identities,
            commands::create_identity_from_mnemonic,
            commands::decrypt_identity,
            commands::activate_identity,
            commands::delete_identity,
            commands::list_hired_storage,
            commands::hire_storage_provider,
            commands::repair_state,
            commands::set_network_profile,
            commands::get_network_profile,
            commands::generate_proof_from_file,
            commands::generate_proof_from_handoff_json,
            commands::lattice_demo_vk_seed_hex,
            commands::proof_of_age_template_json,
            commands::verify_claim_with_template,
            commands::export_qssm_template,
        ])
        .run(tauri::generate_context!())
        .expect("error while running qssm-desktop");
}
