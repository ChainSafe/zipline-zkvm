#![no_std]
extern crate alloc;

#[cfg(feature = "use-intrinsics")]
pub mod bls_openvm;
#[cfg(feature = "use-intrinsics")]
pub use bls_openvm as bls;
#[cfg(not(feature = "use-intrinsics"))]
pub mod bls;



#[cfg(feature = "use-intrinsics")]
pub mod hash_openvm;
#[cfg(feature = "use-intrinsics")]
pub use hash_openvm as hash;
#[cfg(not(feature = "use-intrinsics"))]
pub mod hash;

#[cfg(test)]
mod spec_tests;
