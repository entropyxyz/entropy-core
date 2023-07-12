#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(clippy::all)]

use frame_support::{
    traits::Get,
    weights::{constants::RocksDbWeight, Weight},
};
use sp_std::marker::PhantomData;

/// Weight functions needed for module_transaction_pause.
pub trait WeightInfo {
    fn pause_transaction() -> Weight;
    fn unpause_transaction() -> Weight;
}

pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	/// Storage: TransactionPause PausedTransactions (r:1 w:1)
	/// Proof Skipped: TransactionPause PausedTransactions (max_values: None, max_size: None, mode: Measured)
	fn pause_transaction() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `109`
		//  Estimated: `3574`
		// Minimum execution time: 27_000_000 picoseconds.
		Weight::from_parts(27_000_000, 0)
			.saturating_add(Weight::from_parts(0, 3574))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: TransactionPause PausedTransactions (r:1 w:1)
	/// Proof Skipped: TransactionPause PausedTransactions (max_values: None, max_size: None, mode: Measured)
	fn unpause_transaction() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `160`
		//  Estimated: `3625`
		// Minimum execution time: 28_000_000 picoseconds.
		Weight::from_parts(29_000_000, 0)
			.saturating_add(Weight::from_parts(0, 3625))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
}

// For backwards compatibility and tests
impl WeightInfo for () {
    /// Storage: TransactionPause PausedTransactions (r:1 w:1)
	/// Proof Skipped: TransactionPause PausedTransactions (max_values: None, max_size: None, mode: Measured)
	fn pause_transaction() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `109`
		//  Estimated: `3574`
		// Minimum execution time: 27_000_000 picoseconds.
		Weight::from_parts(27_000_000, 0)
			.saturating_add(Weight::from_parts(0, 3574))
			.saturating_add(RocksDbWeight::get().reads(1))
			.saturating_add(RocksDbWeight::get().writes(1))
	}
	/// Storage: TransactionPause PausedTransactions (r:1 w:1)
	/// Proof Skipped: TransactionPause PausedTransactions (max_values: None, max_size: None, mode: Measured)
	fn unpause_transaction() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `160`
		//  Estimated: `3625`
		// Minimum execution time: 28_000_000 picoseconds.
		Weight::from_parts(29_000_000, 0)
			.saturating_add(Weight::from_parts(0, 3625))
			.saturating_add(RocksDbWeight::get().reads(1))
			.saturating_add(RocksDbWeight::get().writes(1))
	}
}
