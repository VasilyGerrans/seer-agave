use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_system_program::id;
use spl_associated_token_account_interface::address::get_associated_token_address;

#[derive(BorshSerialize)]
pub enum NftMinterInstruction {
    InitializeConfig,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum ManagerInstruction {
    CreateCampaign { goal: u64 },
    Contribute { amount: u64 },
}

pub fn nftminter_initialize_config(nft_program_id: &Pubkey, payer: &Pubkey) -> Instruction {
    let (nft_config_pda, _) = Pubkey::find_program_address(&[b"nft_config"], nft_program_id);

    Instruction {
        program_id: *nft_program_id,
        accounts: vec![
            AccountMeta::new_readonly(*payer, true),
            AccountMeta::new(nft_config_pda, false),
            AccountMeta::new_readonly(id(), false),
        ],
        data: borsh::to_vec(&NftMinterInstruction::InitializeConfig).unwrap(),
    }
}

pub fn manager_create_campaign(
    manager_program_id: &Pubkey,
    treasury_program_id: &Pubkey,
    payer: &Pubkey,
    campaign_account: &Pubkey,
) -> Instruction {
    let (vault_pda, _) =
        Pubkey::find_program_address(&[b"vault", campaign_account.as_ref()], treasury_program_id);

    Instruction {
        program_id: *manager_program_id,
        accounts: vec![
            AccountMeta::new_readonly(*payer, true),
            AccountMeta::new(*campaign_account, true),
            AccountMeta::new(vault_pda, false),
            AccountMeta::new_readonly(*treasury_program_id, false),
            AccountMeta::new_readonly(id(), false),
        ],
        data: borsh::to_vec(&ManagerInstruction::CreateCampaign {
            goal: 5_000_000_000,
        })
        .unwrap(),
    }
}

pub fn manager_contribute(
    manager_program_id: &Pubkey,
    treasury_program_id: &Pubkey,
    nftminter_program_id: &Pubkey,
    contributor: &Pubkey,
    campaign_account: &Pubkey,
    mint_account: &Pubkey,
) -> Instruction {
    let vault_pda =
        Pubkey::find_program_address(&[b"vault", campaign_account.as_ref()], treasury_program_id).0;
    let nft_config_pda = Pubkey::find_program_address(&[b"nft_config"], nftminter_program_id).0;
    let mint_authority_pda =
        Pubkey::find_program_address(&[b"mint_authority"], nftminter_program_id).0;

    let recipient_token_account = get_associated_token_address(contributor, mint_account);

    Instruction {
        program_id: *manager_program_id,
        accounts: vec![
            AccountMeta::new_readonly(*contributor, true),
            AccountMeta::new(*campaign_account, false),
            AccountMeta::new(vault_pda, false),
            AccountMeta::new_readonly(*treasury_program_id, false),
            AccountMeta::new_readonly(*nftminter_program_id, false),
            AccountMeta::new_readonly(nft_config_pda, false),
            AccountMeta::new(*mint_account, true),
            AccountMeta::new_readonly(mint_authority_pda, false),
            AccountMeta::new(Pubkey::from(recipient_token_account.to_bytes()), false),
            AccountMeta::new_readonly(Pubkey::from(spl_token::ID.to_bytes()), false),
            AccountMeta::new_readonly(id(), false),
            AccountMeta::new_readonly(solana_program::sysvar::rent::ID, false),
        ],
        data: borsh::to_vec(&ManagerInstruction::Contribute {
            amount: 1_000_000, // Example amount
        })
        .unwrap(),
    }
}
