#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{
    traits::Get,
    weights::{constants::RocksDbWeight, Weight},
};
use sp_std::marker::PhantomData;

// The weight info trait for `pallet_realyer`.
pub trait WeightInfo {
    fn prep_transaction() -> Weight;
    fn register() -> Weight;
    fn move_active_to_pending_failure(m: u64) -> Weight;
    fn move_active_to_pending_no_failure(m: u64) -> Weight;
}

/// Weights for pallet_realyer using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn prep_transaction() -> Weight {
        Weight::from_ref_time(33_000_000 as u64)
            .saturating_add(T::DbWeight::get().reads(1 as u64))
            .saturating_add(T::DbWeight::get().writes(1 as u64))
    }

    fn register() -> Weight {
        Weight::from_ref_time(23_000_000 as u64).saturating_add(T::DbWeight::get().writes(1 as u64))
    }

    fn move_active_to_pending_no_failure(m: u64) -> Weight {
        Weight::from_ref_time(38_655_000 as u64)
			// Standard Error: 71_000
			.saturating_add(Weight::from_ref_time(531_000 as u64).saturating_mul(m as u64))
			.saturating_add(T::DbWeight::get().reads(6 as u64))
			.saturating_add(T::DbWeight::get().writes(3 as u64))
    }

    fn move_active_to_pending_failure(m: u64) -> Weight {
        Weight::from_ref_time(31_350_000 as u64)
			// Standard Error: 55_000
			.saturating_add(Weight::from_ref_time(1_143_000 as u64).saturating_mul(m as u64))
			.saturating_add(T::DbWeight::get().reads(6 as u64))
			.saturating_add(T::DbWeight::get().writes(3 as u64))
    }
}

// For backwards compatibility and tests
impl WeightInfo for () {
    fn prep_transaction() -> Weight {
        Weight::from_ref_time(33_000_000 as u64)
            .saturating_add(RocksDbWeight::get().reads(1 as u64))
            .saturating_add(RocksDbWeight::get().writes(1 as u64))
    }

    fn register() -> Weight {
        Weight::from_ref_time(23_000_000 as u64)
            .saturating_add(RocksDbWeight::get().writes(1 as u64))
    }

    fn move_active_to_pending_no_failure(m: u64) -> Weight {
        Weight::from_ref_time(38_655_000 as u64)
			// Standard Error: 71_000
			.saturating_add(Weight::from_ref_time(531_000 as u64).saturating_mul(m as u64))
			.saturating_add(RocksDbWeight::get().reads(6 as u64))
			.saturating_add(RocksDbWeight::get().writes(3 as u64))
    }

    fn move_active_to_pending_failure(m: u64) -> Weight {
        Weight::from_ref_time(31_350_000 as u64)
			// Standard Error: 55_000
			.saturating_add(Weight::from_ref_time(1_143_000 as u64).saturating_mul(m as u64))
			.saturating_add(RocksDbWeight::get().reads(6 as u64))
			.saturating_add(RocksDbWeight::get().writes(3 as u64))
    }
}
