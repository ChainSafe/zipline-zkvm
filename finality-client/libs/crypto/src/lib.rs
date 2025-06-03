#![no_std]
extern crate alloc;

pub mod bls;
#[cfg(not(feature = "use-intrinsics"))]
pub mod hash;
#[cfg(feature = "use-intrinsics")]
pub mod hash_openvm;
#[cfg(feature = "use-intrinsics")]
pub use hash_openvm as hash;

#[cfg(test)]
mod spec_tests;
