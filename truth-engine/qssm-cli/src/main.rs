use std::{env, fs, process};

fn usage() -> ! {
    eprintln!(
        "Usage: qssm <command> [args...]

Commands:
  compile <template-id-or-json>           Compile a template into a blueprint (hex)
  commit  <secret> <salt-hex>             Commit a secret (hex output)
  prove   <claim-json> <salt-hex> <bp>    Prove a claim against a blueprint (hex)
  verify  <proof-hex> <blueprint-hex>     Verify a proof against a blueprint
  open    <secret> <salt-hex>             Re-derive commitment (hex output)

Arguments marked <bp>, <proof-hex>, <blueprint-hex> accept hex strings or @file paths."
    );
    process::exit(1);
}

fn hex_or_file(arg: &str) -> Vec<u8> {
    if let Some(path) = arg.strip_prefix('@') {
        fs::read(path).unwrap_or_else(|e| {
            eprintln!("Error reading {path}: {e}");
            process::exit(1);
        })
    } else {
        hex::decode(arg).unwrap_or_else(|e| {
            eprintln!("Invalid hex: {e}");
            process::exit(1);
        })
    }
}

fn parse_salt(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).unwrap_or_else(|e| {
        eprintln!("Invalid salt hex: {e}");
        process::exit(1);
    });
    <[u8; 32]>::try_from(bytes.as_slice()).unwrap_or_else(|_| {
        eprintln!("Salt must be exactly 32 bytes (64 hex chars)");
        process::exit(1);
    })
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }

    match args[1].as_str() {
        "compile" => {
            if args.len() < 3 {
                usage();
            }
            match qssm_core::compile(&args[2]) {
                Ok(blueprint) => println!("{}", hex::encode(&blueprint)),
                Err(e) => {
                    eprintln!("compile error: {e}");
                    process::exit(1);
                }
            }
        }

        "commit" => {
            if args.len() < 4 {
                usage();
            }
            let salt = parse_salt(&args[3]);
            let commitment = qssm_core::commit(args[2].as_bytes(), &salt);
            println!("{}", hex::encode(&commitment));
        }

        "prove" => {
            if args.len() < 5 {
                usage();
            }
            let salt = parse_salt(&args[3]);
            let blueprint = hex_or_file(&args[4]);
            match qssm_core::prove(args[2].as_bytes(), &salt, &blueprint) {
                Ok(proof) => println!("{}", hex::encode(&proof)),
                Err(e) => {
                    eprintln!("prove error: {e}");
                    process::exit(1);
                }
            }
        }

        "verify" => {
            if args.len() < 4 {
                usage();
            }
            let proof = hex_or_file(&args[2]);
            let blueprint = hex_or_file(&args[3]);
            if qssm_core::verify(&proof, &blueprint) {
                println!("true");
            } else {
                println!("false");
                process::exit(1);
            }
        }

        "open" => {
            if args.len() < 4 {
                usage();
            }
            let salt = parse_salt(&args[3]);
            let opened = qssm_core::open(args[2].as_bytes(), &salt);
            println!("{}", hex::encode(&opened));
        }

        _ => usage(),
    }
}
