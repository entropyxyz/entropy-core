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
    fn prep_transaction(s: u32) -> Weight;
    fn register() -> Weight;
    fn move_active_to_pending_failure(m: u32) -> Weight;
    fn move_active_to_pending_no_failure(m: u32) -> Weight;
}

/// Weights for pallet_realyer using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    // Storage: StakingExtension SigningGroups (r:2 w:0)
    // Storage: StakingExtension IsValidatorSynced (r:1 w:0)
    // Storage: StakingExtension ThresholdServers (r:1 w:0)
    // Storage: Relayer Messages (r:1 w:1)
    /// The range of component `s` is `[0, 500]`.
    fn prep_transaction(s: u32) -> Weight {
        Weight::from_ref_time(168_000_000 as u64)
			// Standard Error: 463_132
			.saturating_add(Weight::from_ref_time(9_472_133 as u64).saturating_mul(s as u64))
			.saturating_add(T::DbWeight::get().reads(5 as u64))
			.saturating_add(T::DbWeight::get().reads((1 as u64).saturating_mul(s as u64)))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
    }

    fn register() -> Weight {
        Weight::from_ref_time(23_000_000_u64).saturating_add(T::DbWeight::get().writes(1_u64))
    }

    // Storage: Relayer Messages (r:1 w:0)
    // Storage: Relayer Failures (r:1 w:0)
    // Storage: Relayer Responsibility (r:1 w:0)
    // Storage: Relayer Unresponsive (r:1 w:1)
    // Storage: Authorship Author (r:1 w:0)
    // Storage: System Digest (r:1 w:0)
    // Storage: Relayer Pending (r:0 w:1)
    /// The range of component `m` is `[0, 10]`.
    fn move_active_to_pending_no_failure(m: u32) -> Weight {
        Weight::from_ref_time(42_000_000 as u64)
			// Standard Error: 711_254
			.saturating_add(Weight::from_ref_time(3_176_966 as u64).saturating_mul(m as u64))
			.saturating_add(T::DbWeight::get().reads(6 as u64))
			.saturating_add(T::DbWeight::get().writes(2 as u64))
    }

    // Storage: Relayer Messages (r:1 w:0)
    // Storage: Relayer Failures (r:1 w:0)
    // Storage: Relayer Responsibility (r:1 w:0)
    // Storage: Relayer Unresponsive (r:1 w:1)
    // Storage: Authorship Author (r:1 w:0)
    // Storage: System Digest (r:1 w:0)
    // Storage: Relayer Pending (r:0 w:1)
    /// The range of component `m` is `[0, 10]`.
    fn move_active_to_pending_failure(m: u32) -> Weight {
        Weight::from_ref_time(43_000_000 as u64)
			// Standard Error: 419_771
			.saturating_add(Weight::from_ref_time(4_272_471 as u64).saturating_mul(m as u64))
			.saturating_add(T::DbWeight::get().reads(6 as u64))
			.saturating_add(T::DbWeight::get().writes(2 as u64))
    }
}

// For backwards compatibility and tests
impl WeightInfo for () {
    // Storage: StakingExtension SigningGroups (r:2 w:0)
    // Storage: StakingExtension IsValidatorSynced (r:1 w:0)
    // Storage: StakingExtension ThresholdServers (r:1 w:0)
    // Storage: Relayer Messages (r:1 w:1)
    /// The range of component `s` is `[0, 500]`.
    fn prep_transaction(s: u32) -> Weight {
        Weight::from_ref_time(168_000_000 as u64)
			// Standard Error: 463_132
			.saturating_add(Weight::from_ref_time(9_472_133 as u64).saturating_mul(s as u64))
			.saturating_add(RocksDbWeight::get().reads(5 as u64))
			.saturating_add(RocksDbWeight::get().reads((1 as u64).saturating_mul(s as u64)))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
    }

    fn register() -> Weight {
        Weight::from_ref_time(23_000_000_u64).saturating_add(RocksDbWeight::get().writes(1_u64))
    }

    // Storage: Relayer Messages (r:1 w:0)
    // Storage: Relayer Failures (r:1 w:0)
    // Storage: Relayer Responsibility (r:1 w:0)
    // Storage: Relayer Unresponsive (r:1 w:1)
    // Storage: Authorship Author (r:1 w:0)
    // Storage: System Digest (r:1 w:0)
    // Storage: Relayer Pending (r:0 w:1)
    /// The range of component `m` is `[0, 10]`.
    fn move_active_to_pending_no_failure(m: u32) -> Weight {
        Weight::from_ref_time(42_000_000 as u64)
			// Standard Error: 711_254
			.saturating_add(Weight::from_ref_time(3_176_966 as u64).saturating_mul(m as u64))
			.saturating_add(RocksDbWeight::get().reads(6 as u64))
			.saturating_add(RocksDbWeight::get().writes(2 as u64))
    }

    // Storage: Relayer Messages (r:1 w:0)
    // Storage: Relayer Failures (r:1 w:0)
    // Storage: Relayer Responsibility (r:1 w:0)
    // Storage: Relayer Unresponsive (r:1 w:1)
    // Storage: Authorship Author (r:1 w:0)
    // Storage: System Digest (r:1 w:0)
    // Storage: Relayer Pending (r:0 w:1)
    /// The range of component `m` is `[0, 10]`.
    fn move_active_to_pending_failure(m: u32) -> Weight {
        Weight::from_ref_time(43_000_000 as u64)
			// Standard Error: 419_771
			.saturating_add(Weight::from_ref_time(4_272_471 as u64).saturating_mul(m as u64))
			.saturating_add(RocksDbWeight::get().reads(6 as u64))
			.saturating_add(RocksDbWeight::get().writes(2 as u64))
    }
}
