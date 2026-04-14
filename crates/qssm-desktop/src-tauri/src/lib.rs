mod commands;
mod geo;
mod identity;
mod sidecar;

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let mmdbs = sidecar::mmdb_candidates(&app.handle());
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running qssm-desktop");
}
