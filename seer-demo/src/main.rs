use solana_keypair::Signer;
use solana_program_test::ProgramTest;
use solana_transaction::Transaction;
use std::{env, path::PathBuf};

mod config;
mod instructions;
mod utils;

#[tokio::main]
async fn main() {
    let project_root: PathBuf = env::var("PROJECT_ROOT")
        .expect("PROJECT_ROOT environment variable not set")
        .parse()
        .expect("Invalid PROJECT_ROOT");

    let config = config::Config::new(project_root.clone());

    let mut program_test = ProgramTest::default();
    for (k, v) in config.sources.iter() {
        utils::add_upgradeable_program_to_genesis(&mut program_test, &k, v);
    }

    seer::init(
        config.sources,
        Some(project_root.to_string_lossy().to_string()),
    );

    let context = program_test.start_with_context().await;
    let payer = &context.payer;
    let recent_blockhash = context.last_blockhash;

    let nft_init_ix =
        instructions::nftminter_initialize_config(&config.nftminter_program_id, &payer.pubkey());

    let create_campaign_ix = instructions::manager_create_campaign(
        &config.manager_program_id,
        &config.treasury_program_id,
        &payer.pubkey(),
        &config.campaign_keypair.pubkey(),
    );

    let contribute_ix = instructions::manager_contribute(
        &config.manager_program_id,
        &config.treasury_program_id,
        &config.nftminter_program_id,
        &payer.pubkey(),
        &config.campaign_keypair.pubkey(),
        &config.mint_keypair.pubkey(),
    );

    let tx = Transaction::new_signed_with_payer(
        &[nft_init_ix, create_campaign_ix, contribute_ix],
        Some(&payer.pubkey()),
        &[payer, &config.campaign_keypair, &config.mint_keypair],
        recent_blockhash,
    );

    let transaction_hash = tx.signatures[0].clone();
    println!("Running tx: {}", transaction_hash);

    let sim = context.banks_client.simulate_transaction(tx).await.unwrap();
    println!("{:#?}", sim.simulation_details.unwrap().logs);
}
