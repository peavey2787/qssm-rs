mod commands;

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
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
