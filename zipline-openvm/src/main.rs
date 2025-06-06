// main.rs
#![no_std]

extern crate alloc;

use alloc::collections::btree_map::BTreeMap as Map;
use alloc::vec::Vec;
// use ethereum_consensus::bellatrix::minimal as spec;
use openvm::io::read;
use preimage_oracle::hashmap_oracle::HashMapOracle;
use zipline_finality_client::{
    input::ZiplineInput,
    ssz_state_reader::{PatchedSszStateReader, SszStateReader},
};
use zipline_spec::{MinimalSpec as Spec};
use openvm_pairing_guest::bls12_381::Bls12_381G1Affine;


openvm_algebra_guest::moduli_macros::moduli_init! {
    "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
}

openvm_algebra_guest::complex_macros::complex_init! {
    Bls12_381Fp2 { mod_idx = 0 },
}

openvm_ecc_guest::sw_macros::sw_init! {
    Bls12_381G1Affine
}


fn main() {
    log::debug!("Zipline state transition start");
    let input: ZiplineInput<
        2048,
        128,
        10,
    > = read();

    let oracle_provider: Map<[u8; 32], Vec<u8>> = read();
    let hashmap_oracle = HashMapOracle::from(oracle_provider);

    let state_reader = SszStateReader::<_, Spec>::new(hashmap_oracle, input.state_root).unwrap();

    let result = zipline_finality_client::verify::<
        Spec,
        PatchedSszStateReader<_, Spec>,
        2048,
        128,
        10,
    >(state_reader, input);

    let _ = result.unwrap();
}
