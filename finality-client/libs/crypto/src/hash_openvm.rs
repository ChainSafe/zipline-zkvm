
#[derive(Clone)]
pub struct Sha256OpenVm {
    buffer: Vec<u8>,
}

mod sha256_digest {
    use super::Sha256OpenVm;
    use alloc::vec::Vec;
    use {
        digest::{
            consts::U64, core_api::BlockSizeUser, generic_array::GenericArray, typenum::U32, Digest,
            FixedOutput, FixedOutputReset, OutputSizeUser,
        },
        openvm_sha256_guest::sha256,
    };

    impl OutputSizeUser for Sha256OpenVm {
        type OutputSize = U32;
    }

    impl digest::Update for Sha256OpenVm {
        fn update(&mut self, input: &[u8]) {
            self.buffer.extend_from_slice(input);
        }
    }

    impl FixedOutput for Sha256OpenVm {
        fn finalize_into(self, out: &mut digest::Output<Self>) {
            let hash = sha256(&self.buffer);
            out.copy_from_slice(&hash);
        }
    }

    impl digest::Reset for Sha256OpenVm {
        fn reset(&mut self) {
            self.buffer.clear();
        }
    }

    impl FixedOutputReset for Sha256OpenVm {
        fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>) {
            let hash = sha256(&self.buffer);
            out.copy_from_slice(&hash);
            self.reset();
        }
    }

    impl Digest for Sha256OpenVm {
        fn update(&mut self, input: impl AsRef<[u8]>) {
            digest::Update::update(self, input.as_ref());
        }

        fn new() -> Self {
            Self { buffer: Vec::new() }
        }

        fn new_with_prefix(data: impl AsRef<[u8]>) -> Self {
            let mut hasher = Self::new();
            hasher.update(data.as_ref());
            hasher
        }

        fn chain_update(mut self, data: impl AsRef<[u8]>) -> Self {
            self.update(data.as_ref());
            self
        }

        fn finalize(self) -> digest::Output<Self> {
            let hash = sha256(&self.buffer);
            GenericArray::from(hash)
        }

        fn finalize_into(self, out: &mut digest::Output<Self>) {
            FixedOutput::finalize_into(self, out);
        }

        fn finalize_reset(&mut self) -> digest::Output<Self>
        where
            Self: digest::FixedOutputReset,
        {
            let hash = sha256(&self.buffer);
            let output = GenericArray::from(hash);
            self.reset();
            output
        }

        fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>)
        where
            Self: digest::FixedOutputReset,
        {
            FixedOutputReset::finalize_into_reset(self, out);
        }

        fn reset(&mut self)
        where
            Self: digest::Reset,
        {
            digest::Reset::reset(self);
        }

        fn output_size() -> usize {
            32
        }

        fn digest(data: impl AsRef<[u8]>) -> digest::Output<Self> {
            let hash = sha256(data.as_ref());
            GenericArray::from(hash)
        }
    }

    impl BlockSizeUser for Sha256OpenVm {
        type BlockSize = U64;
    }
}

/// Length of a SHA256 hash in bytes.
pub const HASH_LEN: usize = 32;

pub type H256 = [u8; HASH_LEN];
use core::convert::Into;
use core::iter::IntoIterator;
use core::iter::Iterator;

use alloc::vec::Vec;
use digest::Digest;
/// Returns the digest of `input` using the best available implementation.
pub fn hash(input: &[u8]) -> Vec<u8> {
    Sha2CrateImpl {}.hash(input)
}

/// Hash function returning a fixed-size array (to save on allocations).
/// This is the preferred way to hash
pub fn hash_fixed(input: &[u8]) -> [u8; HASH_LEN] {
    Sha2CrateImpl {}.hash_fixed(input)
}

/// Compute the hash of two slices concatenated.
pub fn hash_concat(h1: &[u8], h2: &[u8]) -> [u8; HASH_LEN] {
    let mut ctx = <Sha256OpenVm as Sha256Context>::new();
    Sha256Context::update(&mut ctx, h1);
    Sha256Context::update(&mut ctx, h2);
    Sha256Context::finalize(ctx)
}

/// Context trait for abstracting over implementation contexts.
pub trait Sha256Context {
    fn new() -> Self;

    fn update(&mut self, bytes: &[u8]);

    fn finalize(self) -> [u8; HASH_LEN];
}

/// Top-level trait for Sha256 hashing
pub trait Sha256 {
    type Context: Sha256Context;

    fn hash(&self, input: &[u8]) -> Vec<u8>;

    fn hash_fixed(&self, input: &[u8]) -> [u8; HASH_LEN];
}

/// Implementation of SHA256 using the `sha2` crate.
// We can switch this out with other impls if they are found to be faster on MIPS
struct Sha2CrateImpl;

impl Sha256Context for Sha256OpenVm {
    fn new() -> Self {
        Digest::new()
    }

    fn update(&mut self, bytes: &[u8]) {
        Digest::update(self, bytes)
    }

    fn finalize(self) -> [u8; HASH_LEN] {
        Digest::finalize(self).into()
    }
}

impl Sha256 for Sha2CrateImpl {
    type Context = Sha256OpenVm;

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        Self::Context::digest(input).into_iter().collect()
    }

    fn hash_fixed(&self, input: &[u8]) -> [u8; HASH_LEN] {
        Self::Context::digest(input).into()
    }
}
