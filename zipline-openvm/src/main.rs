// main.rs
#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::btree_map::BTreeMap as Map;
use alloc::vec::Vec;
use ethereum_consensus::bellatrix::minimal as spec;
use openvm::io::read;
use preimage_oracle::hashmap_oracle::HashMapOracle;
use zipline_finality_client::{
    input::ZiplineInput,
    ssz_state_reader::{PatchedSszStateReader, SszStateReader},
};
use zipline_spec::MinimalSpec as Spec;

openvm::entry!(main);

fn main() {
    log::debug!("Zipline state transition start");
    let input: ZiplineInput<
        { spec::MAX_VALIDATORS_PER_COMMITTEE },
        { spec::MAX_ATTESTATIONS },
        10,
    > = read();

    let oracle_provider: Map<[u8; 32], Vec<u8>> = read();
    let hashmap_oracle = HashMapOracle::from(oracle_provider);

    let state_reader = SszStateReader::<_, Spec>::new(hashmap_oracle, input.state_root).unwrap();

    let result = zipline_finality_client::verify::<
        Spec,
        PatchedSszStateReader<_, Spec>,
        { spec::MAX_VALIDATORS_PER_COMMITTEE },
        { spec::MAX_ATTESTATIONS },
        10,
    >(state_reader, input);

    let _ = result.unwrap();
}
