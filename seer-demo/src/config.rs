use solana_keypair::{read_keypair_file, Pubkey, Signer};
use std::{collections::HashMap, fs, path::PathBuf};

#[derive(Debug)]
pub struct Config {
    pub dwarf_sources: HashMap<Pubkey, PathBuf>,
    pub manager_program_id: Pubkey,
    pub treasury_program_id: Pubkey,
    pub nftminter_program_id: Pubkey,
}

impl Config {
    pub fn load_config(project_root: PathBuf) -> Self {
        let deploy_dir = project_root.join("target/deploy");
        let mut dwarf_sources: HashMap<Pubkey, PathBuf> = HashMap::new();

        let mut manager: Option<Pubkey> = None;
        let mut nftminter: Option<Pubkey> = None;
        let mut treasury: Option<Pubkey> = None;

        if let Ok(entries) = fs::read_dir(&deploy_dir) {
            let mut json_files = HashMap::new();
            let mut so_files = HashMap::new();

            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if file_name.ends_with("-keypair.json") {
                        if let Some(base) = file_name.strip_suffix("-keypair.json") {
                            json_files.insert(base.to_string(), path);
                        }
                    } else if file_name.ends_with(".so") {
                        if let Some(base) = file_name.strip_suffix(".so") {
                            so_files.insert(base.to_string(), path);
                        }
                    }
                }
            }

            for (name, json_path) in json_files {
                if let Some(so_path) = so_files.get(&name) {
                    match read_keypair_file(&json_path) {
                        Ok(kp) => {
                            let address = kp.pubkey();

                            if name == "manager" {
                                manager = Some(address.clone());
                            } else if name == "nftminter" {
                                nftminter = Some(address.clone());
                            } else if name == "treasury" {
                                treasury = Some(address.clone());
                            }

                            dwarf_sources.insert(address, so_path.canonicalize().unwrap());
                        }
                        Err(err) => {
                            eprintln!(
                                "Failed to read keypair file {}: {}",
                                json_path.display(),
                                err
                            );
                        }
                    }
                }
            }
        } else {
            eprintln!("Deploy directory not found: {}", deploy_dir.display());
        }

        Config {
            dwarf_sources,
            manager_program_id: manager.expect("Manager not in target/debug!"),
            treasury_program_id: treasury.expect("Treasury not in target/debug!"),
            nftminter_program_id: nftminter.expect("Nftminter not in target/debug!"),
        }
    }
}
