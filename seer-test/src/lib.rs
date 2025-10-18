use std::{collections::HashMap, path::PathBuf};
use solana_address::Address;
use solana_program_test::ProgramTest;

pub mod utils;

pub fn get_program_test(sources: HashMap<Address, PathBuf>, project_root: Option<String>) -> ProgramTest {
    seer::init(sources.clone(), project_root);

    let mut program_test = ProgramTest::default();

    for (k, v) in sources.iter() {
        utils::add_upgradeable_program_to_genesis(
            &mut program_test, 
            &k, 
            v,
        );
    }

    program_test
}
