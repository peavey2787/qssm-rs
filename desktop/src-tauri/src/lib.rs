mod commands;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::compile_blueprint,
            commands::commit_secret,
            commands::prove_claim,
            commands::verify_proof,
            commands::open_secret,
            commands::proof_of_age_template_json,
            commands::verify_claim_with_template,
            commands::import_qssm_template,
            commands::export_qssm_template,
        ])
        .run(tauri::generate_context!())
        .expect("error while running qssm-desktop");
}
