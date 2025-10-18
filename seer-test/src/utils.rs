use solana_account::Account;
use solana_loader_v3_interface::{get_program_data_address, state::UpgradeableLoaderState};
use solana_program_test::{read_file, ProgramTest};
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_sdk_ids::bpf_loader_upgradeable;
use std::path::PathBuf;

fn bpf_loader_upgradeable_program_accounts(
    program_id: &Pubkey,
    elf: &[u8],
    rent: &Rent,
) -> [(Pubkey, Account); 2] {
    let programdata_address = get_program_data_address(program_id);
    let program_account = {
        let space = UpgradeableLoaderState::size_of_program();
        let lamports = rent.minimum_balance(space);
        let data = bincode::serialize(&UpgradeableLoaderState::Program {
            programdata_address,
        })
        .unwrap();
        Account {
            lamports,
            data,
            owner: bpf_loader_upgradeable::id(),
            executable: true,
            rent_epoch: u64::MAX,
        }
    };
    let programdata_account = {
        let space = UpgradeableLoaderState::size_of_programdata_metadata() + elf.len();
        let lamports = rent.minimum_balance(space);
        let mut data = bincode::serialize(&UpgradeableLoaderState::ProgramData {
            slot: 0,
            upgrade_authority_address: Some(Pubkey::default()),
        })
        .unwrap();
        data.extend_from_slice(elf);
        Account {
            lamports,
            data,
            owner: bpf_loader_upgradeable::id(),
            executable: false,
            rent_epoch: u64::MAX,
        }
    };
    [
        (*program_id, program_account),
        (programdata_address, programdata_account),
    ]
}

pub fn add_upgradeable_program_to_genesis(
    program_test: &mut ProgramTest,
    program_id: &Pubkey,
    program_path: &PathBuf,
) {
    let elf = read_file(program_path);
    let program_accounts =
        bpf_loader_upgradeable_program_accounts(program_id, &elf, &Rent::default());
    for (address, account) in program_accounts {
        program_test.add_genesis_account(address, account);
    }
}
