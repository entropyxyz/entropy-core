#![allow(clippy::all)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{
    traits::Get,
    weights::{constants::RocksDbWeight, Weight},
};
use sp_std::marker::PhantomData;

// The weight info trait for `pallet_constraints`.
pub trait WeightInfo {
    fn update_constraints(a: u32, b: u32) -> Weight;
    fn update_v2_constraints() -> Weight;
}

/// Weights for pallet_constraints using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    // Storage: Constraints AddressWhitelist (r:1 w:1)
    fn update_constraints(a: u32, b: u32) -> Weight {
        Weight::from_ref_time(24_045_000_u64)
			// Standard Error: 0
			+ Weight::from_ref_time(278_000_u64.saturating_mul(a as u64 + b as u64))
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
    }

    // Storage: Constraints AllowedToModifyConstraints (r:1 w:0)
    // Storage: Constraints V2Storage (r:0 w:1)
    fn update_v2_constraints() -> Weight {
        // Minimum execution time: 46_000 nanoseconds.
        Weight::from_ref_time(54_000_000 as u64)
            .saturating_add(T::DbWeight::get().reads(1 as u64))
            .saturating_add(T::DbWeight::get().writes(1 as u64))
    }
}

// For backwards compatibility and tests
impl WeightInfo for () {
    // Storage: Constraints AddressWhitelist (r:1 w:1)
    fn update_constraints(a: u32, b: u32) -> Weight {
        Weight::from_ref_time(24_045_000_u64)
			// Standard Error: 0
			+ Weight::from_ref_time(278_000_u64.saturating_mul(a as u64 + b as u64))
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
    }

    // Storage: Constraints AllowedToModifyConstraints (r:1 w:0)
    // Storage: Constraints V2Storage (r:0 w:1)
    fn update_v2_constraints() -> Weight {
        // Minimum execution time: 46_000 nanoseconds.
        Weight::from_ref_time(54_000_000 as u64)
            .saturating_add(RocksDbWeight::get().reads(1 as u64))
            .saturating_add(RocksDbWeight::get().writes(1 as u64))
    }
}
