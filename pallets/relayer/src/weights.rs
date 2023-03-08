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
    fn register(evm_acl_len: u32, btc_acl_len: u32) -> Weight;
    fn swap_keys() -> Weight;
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

    fn register(evm_acl_len: u32, btc_acl_len: u32) -> Weight {
        Weight::from_ref_time(23_000_000_u64)
            .saturating_add(T::DbWeight::get().writes(1_u64))
            .saturating_add(Weight::from_ref_time(143_000_u64).saturating_mul(evm_acl_len as u64))
            .saturating_add(Weight::from_ref_time(143_000_u64).saturating_mul(btc_acl_len as u64))
    }

    // Storage: Relayer Registered (r:1 w:1)
    // Storage: Relayer Registering (r:0 w:1)
    fn swap_keys() -> Weight {
        // Minimum execution time: 39_000 nanoseconds.
        Weight::from_ref_time(39_000_000 as u64)
            .saturating_add(T::DbWeight::get().reads(1 as u64))
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

    fn register(evm_acl_len: u32, btc_acl_len: u32) -> Weight {
        Weight::from_ref_time(23_000_000_u64)
            .saturating_add(RocksDbWeight::get().writes(1_u64))
            .saturating_add(Weight::from_ref_time(531_000_u64).saturating_mul(evm_acl_len as u64))
            .saturating_add(Weight::from_ref_time(531_000_u64).saturating_mul(btc_acl_len as u64))
    }

    // Storage: Relayer Registered (r:1 w:1)
    // Storage: Relayer Registering (r:0 w:1)
    fn swap_keys() -> Weight {
        // Minimum execution time: 39_000 nanoseconds.
        Weight::from_ref_time(39_000_000 as u64)
            .saturating_add(RocksDbWeight::get().reads(1 as u64))
            .saturating_add(RocksDbWeight::get().writes(2 as u64))
    }
}
