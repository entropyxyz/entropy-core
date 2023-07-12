#![allow(clippy::all)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{
    traits::Get,
    weights::{constants::RocksDbWeight, Weight},
};
use sp_std::marker::PhantomData;

// The weight info trait for `pallet_realyer`.
pub trait WeightInfo {
    fn register(evm_acl_len: u32, btc_acl_len: u32) -> Weight;
    fn swap_keys() -> Weight;
    fn confirm_register_swapping(c: u32) -> Weight;
    fn confirm_register_registered(c: u32) -> Weight;
    fn confirm_register_registering(c: u32) -> Weight;
}

pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	/// Storage: Relayer Registered (r:1 w:0)
	/// Proof Skipped: Relayer Registered (max_values: None, max_size: None, mode: Measured)
	/// Storage: Relayer Registering (r:1 w:1)
	/// Proof Skipped: Relayer Registering (max_values: None, max_size: None, mode: Measured)
	/// The range of component `a` is `[0, 25]`.
	/// The range of component `b` is `[0, 25]`.
	fn register(_a: u32, b: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `133`
		//  Estimated: `3598`
		// Minimum execution time: 28_000_000 picoseconds.
		Weight::from_parts(30_199_190, 0)
			.saturating_add(Weight::from_parts(0, 3598))
			// Standard Error: 4_105
			.saturating_add(Weight::from_parts(16_435, 0).saturating_mul(b.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: Relayer Registered (r:1 w:1)
	/// Proof Skipped: Relayer Registered (max_values: None, max_size: None, mode: Measured)
	/// Storage: Relayer Registering (r:0 w:1)
	/// Proof Skipped: Relayer Registering (max_values: None, max_size: None, mode: Measured)
	fn swap_keys() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `187`
		//  Estimated: `3652`
		// Minimum execution time: 28_000_000 picoseconds.
		Weight::from_parts(29_000_000, 0)
			.saturating_add(Weight::from_parts(0, 3652))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: StakingExtension ThresholdToStash (r:1 w:0)
	/// Proof Skipped: StakingExtension ThresholdToStash (max_values: None, max_size: None, mode: Measured)
	/// Storage: Relayer Registering (r:1 w:1)
	/// Proof Skipped: Relayer Registering (max_values: None, max_size: None, mode: Measured)
	/// Storage: StakingExtension SigningGroups (r:1 w:0)
	/// Proof Skipped: StakingExtension SigningGroups (max_values: None, max_size: None, mode: Measured)
	/// The range of component `c` is `[0, 2]`.
	fn confirm_register_registering(c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `16478`
		//  Estimated: `19943`
		// Minimum execution time: 46_000_000 picoseconds.
		Weight::from_parts(49_912_983, 0)
			.saturating_add(Weight::from_parts(0, 19943))
			// Standard Error: 269_872
			.saturating_add(Weight::from_parts(6_105_801, 0).saturating_mul(c.into()))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: StakingExtension ThresholdToStash (r:1 w:0)
	/// Proof Skipped: StakingExtension ThresholdToStash (max_values: None, max_size: None, mode: Measured)
	/// Storage: Relayer Registering (r:1 w:1)
	/// Proof Skipped: Relayer Registering (max_values: None, max_size: None, mode: Measured)
	/// Storage: StakingExtension SigningGroups (r:1 w:0)
	/// Proof Skipped: StakingExtension SigningGroups (max_values: None, max_size: None, mode: Measured)
	/// Storage: Relayer Registered (r:0 w:1)
	/// Proof Skipped: Relayer Registered (max_values: None, max_size: None, mode: Measured)
	/// Storage: Constraints AllowedToModifyConstraints (r:0 w:1)
	/// Proof Skipped: Constraints AllowedToModifyConstraints (max_values: None, max_size: None, mode: Measured)
	/// The range of component `c` is `[0, 2]`.
	fn confirm_register_registered(c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `16479`
		//  Estimated: `19944`
		// Minimum execution time: 52_000_000 picoseconds.
		Weight::from_parts(56_737_292, 0)
			.saturating_add(Weight::from_parts(0, 19944))
			// Standard Error: 81_956
			.saturating_add(Weight::from_parts(1_047_513, 0).saturating_mul(c.into()))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: StakingExtension ThresholdToStash (r:1 w:0)
	/// Proof Skipped: StakingExtension ThresholdToStash (max_values: None, max_size: None, mode: Measured)
	/// Storage: Relayer Registering (r:1 w:1)
	/// Proof Skipped: Relayer Registering (max_values: None, max_size: None, mode: Measured)
	/// Storage: StakingExtension SigningGroups (r:1 w:0)
	/// Proof Skipped: StakingExtension SigningGroups (max_values: None, max_size: None, mode: Measured)
	/// Storage: Relayer Registered (r:0 w:1)
	/// Proof Skipped: Relayer Registered (max_values: None, max_size: None, mode: Measured)
	/// The range of component `c` is `[0, 2]`.
	fn confirm_register_swapping(c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `16479`
		//  Estimated: `19944`
		// Minimum execution time: 50_000_000 picoseconds.
		Weight::from_parts(54_109_392, 0)
			.saturating_add(Weight::from_parts(0, 19944))
			// Standard Error: 105_147
			.saturating_add(Weight::from_parts(712_707, 0).saturating_mul(c.into()))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(2))
	}
}

// For backwards compatibility and tests
impl WeightInfo for () {
    /// Storage: Relayer Registered (r:1 w:0)
	/// Proof Skipped: Relayer Registered (max_values: None, max_size: None, mode: Measured)
	/// Storage: Relayer Registering (r:1 w:1)
	/// Proof Skipped: Relayer Registering (max_values: None, max_size: None, mode: Measured)
	/// The range of component `a` is `[0, 25]`.
	/// The range of component `b` is `[0, 25]`.
	fn register(_a: u32, b: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `133`
		//  Estimated: `3598`
		// Minimum execution time: 28_000_000 picoseconds.
		Weight::from_parts(30_199_190, 0)
			.saturating_add(Weight::from_parts(0, 3598))
			// Standard Error: 4_105
			.saturating_add(Weight::from_parts(16_435, 0).saturating_mul(b.into()))
			.saturating_add(RocksDbWeight::get().reads(2))
			.saturating_add(RocksDbWeight::get().writes(1))
	}
	/// Storage: Relayer Registered (r:1 w:1)
	/// Proof Skipped: Relayer Registered (max_values: None, max_size: None, mode: Measured)
	/// Storage: Relayer Registering (r:0 w:1)
	/// Proof Skipped: Relayer Registering (max_values: None, max_size: None, mode: Measured)
	fn swap_keys() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `187`
		//  Estimated: `3652`
		// Minimum execution time: 28_000_000 picoseconds.
		Weight::from_parts(29_000_000, 0)
			.saturating_add(Weight::from_parts(0, 3652))
			.saturating_add(RocksDbWeight::get().reads(1))
			.saturating_add(RocksDbWeight::get().writes(2))
	}
	/// Storage: StakingExtension ThresholdToStash (r:1 w:0)
	/// Proof Skipped: StakingExtension ThresholdToStash (max_values: None, max_size: None, mode: Measured)
	/// Storage: Relayer Registering (r:1 w:1)
	/// Proof Skipped: Relayer Registering (max_values: None, max_size: None, mode: Measured)
	/// Storage: StakingExtension SigningGroups (r:1 w:0)
	/// Proof Skipped: StakingExtension SigningGroups (max_values: None, max_size: None, mode: Measured)
	/// The range of component `c` is `[0, 2]`.
	fn confirm_register_registering(c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `16478`
		//  Estimated: `19943`
		// Minimum execution time: 46_000_000 picoseconds.
		Weight::from_parts(49_912_983, 0)
			.saturating_add(Weight::from_parts(0, 19943))
			// Standard Error: 269_872
			.saturating_add(Weight::from_parts(6_105_801, 0).saturating_mul(c.into()))
			.saturating_add(RocksDbWeight::get().reads(3))
			.saturating_add(RocksDbWeight::get().writes(1))
	}
	/// Storage: StakingExtension ThresholdToStash (r:1 w:0)
	/// Proof Skipped: StakingExtension ThresholdToStash (max_values: None, max_size: None, mode: Measured)
	/// Storage: Relayer Registering (r:1 w:1)
	/// Proof Skipped: Relayer Registering (max_values: None, max_size: None, mode: Measured)
	/// Storage: StakingExtension SigningGroups (r:1 w:0)
	/// Proof Skipped: StakingExtension SigningGroups (max_values: None, max_size: None, mode: Measured)
	/// Storage: Relayer Registered (r:0 w:1)
	/// Proof Skipped: Relayer Registered (max_values: None, max_size: None, mode: Measured)
	/// Storage: Constraints AllowedToModifyConstraints (r:0 w:1)
	/// Proof Skipped: Constraints AllowedToModifyConstraints (max_values: None, max_size: None, mode: Measured)
	/// The range of component `c` is `[0, 2]`.
	fn confirm_register_registered(c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `16479`
		//  Estimated: `19944`
		// Minimum execution time: 52_000_000 picoseconds.
		Weight::from_parts(56_737_292, 0)
			.saturating_add(Weight::from_parts(0, 19944))
			// Standard Error: 81_956
			.saturating_add(Weight::from_parts(1_047_513, 0).saturating_mul(c.into()))
			.saturating_add(RocksDbWeight::get().reads(3))
			.saturating_add(RocksDbWeight::get().writes(3))
	}
	/// Storage: StakingExtension ThresholdToStash (r:1 w:0)
	/// Proof Skipped: StakingExtension ThresholdToStash (max_values: None, max_size: None, mode: Measured)
	/// Storage: Relayer Registering (r:1 w:1)
	/// Proof Skipped: Relayer Registering (max_values: None, max_size: None, mode: Measured)
	/// Storage: StakingExtension SigningGroups (r:1 w:0)
	/// Proof Skipped: StakingExtension SigningGroups (max_values: None, max_size: None, mode: Measured)
	/// Storage: Relayer Registered (r:0 w:1)
	/// Proof Skipped: Relayer Registered (max_values: None, max_size: None, mode: Measured)
	/// The range of component `c` is `[0, 2]`.
	fn confirm_register_swapping(c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `16479`
		//  Estimated: `19944`
		// Minimum execution time: 50_000_000 picoseconds.
		Weight::from_parts(54_109_392, 0)
			.saturating_add(Weight::from_parts(0, 19944))
			// Standard Error: 105_147
			.saturating_add(Weight::from_parts(712_707, 0).saturating_mul(c.into()))
			.saturating_add(RocksDbWeight::get().reads(3))
			.saturating_add(RocksDbWeight::get().writes(2))
	}
}
