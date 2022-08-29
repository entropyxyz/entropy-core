#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{
    traits::Get,
    weights::{constants::RocksDbWeight, Weight},
};
use sp_std::marker::PhantomData;

// The weight info trait for `pallet_constraints`.
pub trait WeightInfo {
    fn add_whitelist_address(a: u32) -> Weight;
}

/// Weights for pallet_constraints using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    // Storage: Constraints AddressWhitelist (r:1 w:1)
    fn add_whitelist_address(a: u32) -> Weight {
        (24_045_000 as Weight)
			// Standard Error: 0
			.saturating_add((278_000 as Weight).saturating_mul(a as Weight))
			.saturating_add(T::DbWeight::get().reads(1 as Weight))
			.saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
}

// For backwards compatibility and tests
impl WeightInfo for () {
    // Storage: Constraints AddressWhitelist (r:1 w:1)
    fn add_whitelist_address(a: u32) -> Weight {
        (24_045_000 as Weight)
			// Standard Error: 0
			.saturating_add((278_000 as Weight).saturating_mul(a as Weight))
			.saturating_add(RocksDbWeight::get().reads(1 as Weight))
			.saturating_add(RocksDbWeight::get().writes(1 as Weight))
    }
}
