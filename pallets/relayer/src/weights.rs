
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use sp_std::marker::PhantomData;

// The weight info trait for `pallet_realyer`.
pub trait WeightInfo {
	fn prep_transaction() -> Weight;
	fn register() -> Weight;
	fn move_active_to_pending(f: u32, m: u32) -> Weight;
}

/// Weights for pallet_realyer using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	fn prep_transaction() -> Weight {
		(33_000_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(1 as Weight))
			.saturating_add(T::DbWeight::get().writes(1 as Weight))
	}
	fn register() -> Weight {
		(23_000_000 as Weight)
			.saturating_add(T::DbWeight::get().writes(1 as Weight))
	}
	fn move_active_to_pending(f: u32, m: u32, ) -> Weight {
		(37_634_000 as Weight)
			// Standard Error: 35_000
			.saturating_add((28_000 as Weight).saturating_mul(f as Weight))
			// Standard Error: 35_000
			.saturating_add((726_000 as Weight).saturating_mul(m as Weight))
			.saturating_add(T::DbWeight::get().reads(6 as Weight))
			.saturating_add(T::DbWeight::get().writes(3 as Weight))
	}
}


// For backwards compatibility and tests
impl WeightInfo for () {
	fn prep_transaction() -> Weight {
		(33_000_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(1 as Weight))
			.saturating_add(RocksDbWeight::get().writes(1 as Weight))
	}
	fn register() -> Weight {
		(23_000_000 as Weight)
			.saturating_add(RocksDbWeight::get().writes(1 as Weight))
	}
	fn move_active_to_pending(f: u32, m: u32, ) -> Weight {
		(37_634_000 as Weight)
			// Standard Error: 35_000
			.saturating_add((28_000 as Weight).saturating_mul(f as Weight))
			// Standard Error: 35_000
			.saturating_add((726_000 as Weight).saturating_mul(m as Weight))
			.saturating_add(RocksDbWeight::get().reads(6 as Weight))
			.saturating_add(RocksDbWeight::get().writes(3 as Weight))
	}
}
