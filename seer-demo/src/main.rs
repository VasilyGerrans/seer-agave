use solana_keypair::{Keypair, Signer};
use solana_program_test::*;
use solana_transaction::Transaction;
use std::{collections::HashMap, env, path::PathBuf};

mod config;
mod instructions;
mod utils;

#[tokio::main]
async fn main() {
    let project_root: PathBuf = env::var("PROJECT_ROOT")
        .expect("PROJECT_ROOT environment variable not set")
        .parse()
        .expect("Invalid PROJECT_ROOT");

    let config = config::Config::load_config(project_root.clone());

    let dwarf_sources: HashMap<solana_address::Address, PathBuf> = config.dwarf_sources;
    let nftminter = config.nftminter_program_id;
    let manager = config.manager_program_id;
    let treasury = config.treasury_program_id;
    let campaign_account = Keypair::new();

    let mut program_test = ProgramTest::default();

    for (k, v) in dwarf_sources.iter() {
        utils::add_upgradeable_program_to_genesis(&mut program_test, &k, v);
    }

    seer::init(dwarf_sources.clone(), Some(project_root.to_string_lossy().to_string()));

    let context = program_test.start_with_context().await;
    let payer = &context.payer;
    let recent_blockhash = context.last_blockhash;

    let nft_init_ix = instructions::nftminter_initialize_config(&nftminter, &payer.pubkey());

    let create_campaign_ix = instructions::manager_create_campaign(
        &manager,
        &treasury,
        &payer.pubkey(),
        &campaign_account.pubkey(),
    );

    let mint_account = Keypair::new();

    let contribute_ix = instructions::manager_contribute(&
        &manager, 
        &treasury, 
        &nftminter, 
        &payer.pubkey(), 
        &campaign_account.pubkey(), 
        &mint_account.pubkey(),
    );

    let tx = Transaction::new_signed_with_payer(
        &[nft_init_ix, create_campaign_ix, contribute_ix],
        Some(&payer.pubkey()),
        &[payer, &campaign_account, &mint_account],
        recent_blockhash,
    );

    let transaction_hash = tx.signatures[0].clone();

    println!("Running tx: {}", transaction_hash);

    let sim = context.banks_client.simulate_transaction(tx).await.unwrap();
    println!("{:#?}", sim.simulation_details.unwrap().logs);
}
