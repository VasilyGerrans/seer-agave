use solana_keypair::{read_keypair_file, Keypair, Pubkey, Signer};
use std::{collections::HashMap, path::PathBuf};

#[derive(Debug)]
pub struct Config {
    pub sources: HashMap<Pubkey, PathBuf>,
    pub manager_program_id: Pubkey,
    pub treasury_program_id: Pubkey,
    pub nftminter_program_id: Pubkey,
    pub campaign_keypair: Keypair,
}

impl Config {
    pub fn new(project_root: PathBuf) -> Self {
        let kp_dir = project_root.join("target/deploy");
        let manager_pk = read_keypair_file(kp_dir.join("manager-keypair.json"))
            .unwrap()
            .pubkey();
        let treasury_pk = read_keypair_file(kp_dir.join("treasury-keypair.json"))
            .unwrap()
            .pubkey();
        let nftminter_pk = read_keypair_file(kp_dir.join("nftminter-keypair.json"))
            .unwrap()
            .pubkey();

        let so_dir = project_root.join("target/sbpf-solana-solana/release");
        let manager_so = so_dir.join("manager.so").canonicalize().unwrap();
        let treasury_so = so_dir.join("treasury.so").canonicalize().unwrap();
        let nftminter_so = so_dir.join("nftminter.so").canonicalize().unwrap();

        Config {
            sources: HashMap::from([
                (manager_pk, manager_so),
                (treasury_pk, treasury_so),
                (nftminter_pk, nftminter_so),
            ]),
            manager_program_id: manager_pk,
            treasury_program_id: treasury_pk,
            nftminter_program_id: nftminter_pk,
            campaign_keypair: Keypair::new(),
        }
    }
}
