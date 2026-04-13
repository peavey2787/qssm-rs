//! Embed `icon.ico` into Windows binaries from this package (e.g. `millionaires_duel.exe`).
fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("windows") {
        return;
    }

    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let icon = manifest_dir.join("crates/qssm-desktop/src-tauri/icons/icon.ico");

    println!("cargo:rerun-if-changed={}", icon.display());

    if !icon.exists() {
        println!(
            "cargo:warning=qssm-ref: no icon at {} — skipping winres (place icon.ico there for a branded .exe)",
            icon.display()
        );
        return;
    }

    let mut res = winres::WindowsResource::new();
    res.set_icon(icon.to_str().expect("icon path is valid UTF-8"));
    res.compile().expect("winres: Windows resource compile (is rc.exe / link.exe available?)");
}
