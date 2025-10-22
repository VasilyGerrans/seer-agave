use solana_keypair::Pubkey;
use solana_program_binaries as programs;
use solana_program_test::*;
use solana_rent::Rent;
use std::path::PathBuf;

pub fn add_upgradeable_program_to_genesis(
    program_test: &mut ProgramTest,
    program_id: &Pubkey,
    program_path: &PathBuf,
) {
    let elf = read_file(program_path);
    let program_accounts =
        programs::bpf_loader_upgradeable_program_accounts(program_id, &elf, &Rent::default());
    for (address, account) in program_accounts {
        program_test.add_genesis_account(address, account);
    }
}
