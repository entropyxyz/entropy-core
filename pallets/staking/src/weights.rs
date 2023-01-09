#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(clippy::all)]

use frame_support::{
    traits::Get,
    weights::{constants::RocksDbWeight, Weight},
};
use sp_std::marker::PhantomData;

// The weight info trait for `pallet_realyer`.
pub trait WeightInfo {
    fn change_endpoint() -> Weight;
    fn change_threshold_accounts() -> Weight;
    fn withdraw_unbonded() -> Weight;
    fn validate() -> Weight;
    fn declare_synced() -> Weight;
    fn new_session_handler_helper(_c: u32, _n: u32) -> Weight;
}

/// Weights for pallet_realyer using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn change_endpoint() -> Weight {
        Weight::from_ref_time(34_000_000_u64)
            .saturating_add(T::DbWeight::get().reads(1_u64))
            .saturating_add(T::DbWeight::get().writes(1_u64))
    }

    // Storage: Staking Ledger (r:1 w:0)
    // Storage: StakingExtension ThresholdAccounts (r:0 w:1)
    fn change_threshold_accounts() -> Weight {
        Weight::from_ref_time(34_000_000_u64)
            .saturating_add(T::DbWeight::get().reads(1_u64))
            .saturating_add(T::DbWeight::get().writes(1_u64))
    }

    // Storage: Staking Ledger (r:1 w:1)
    // Storage: Staking CurrentEra (r:1 w:0)
    // Storage: Balances Locks (r:1 w:1)
    // Storage: System Account (r:1 w:1)
    fn withdraw_unbonded() -> Weight {
        Weight::from_ref_time(41_000_000_u64)
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }

    // Storage: Staking Ledger (r:1 w:0)
    // Storage: Staking MinValidatorBond (r:1 w:0)
    // Storage: Staking MinCommission (r:1 w:0)
    // Storage: Staking Validators (r:1 w:1)
    // Storage: Staking MaxValidatorsCount (r:1 w:0)
    // Storage: Staking Nominators (r:1 w:0)
    // Storage: Staking Bonded (r:1 w:0)
    // Storage: BagsList ListNodes (r:1 w:1)
    // Storage: BagsList ListBags (r:1 w:1)
    // Storage: BagsList CounterForListNodes (r:1 w:1)
    // Storage: Staking CounterForValidators (r:1 w:1)
    // Storage: StakingExtension ThresholdAccounts (r:0 w:1)
    // Storage: StakingExtension EndpointRegister (r:0 w:1)
    fn validate() -> Weight {
        Weight::from_ref_time(95_000_000_u64)
            .saturating_add(T::DbWeight::get().reads(11_u64))
            .saturating_add(T::DbWeight::get().writes(7_u64))
    }

    fn declare_synced() -> Weight {
        Weight::from_ref_time(36_000_000 as u64)
            .saturating_add(T::DbWeight::get().reads(1 as u64))
            .saturating_add(T::DbWeight::get().writes(1 as u64))
    }

    // Storage: StakingExtension SigningGroups (r:2 w:2)
    /// The range of component `c` is `[0, 1000]`.
    /// The range of component `n` is `[0, 1000]`.
    fn new_session_handler_helper(c: u32, n: u32) -> Weight {
        Weight::from_ref_time(39_000_000 as u64)
			// Standard Error: 42_909
			.saturating_add(Weight::from_ref_time(1_364_743 as u64).saturating_mul(c as u64))
			// Standard Error: 42_909
			.saturating_add(Weight::from_ref_time(1_392_245 as u64).saturating_mul(n as u64))
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().writes(2 as u64))
    }
}

// For backwards compatibility and tests
impl WeightInfo for () {
    fn change_endpoint() -> Weight {
        Weight::from_ref_time(34_000_000_u64)
            .saturating_add(RocksDbWeight::get().reads(1_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64))
    }

    // Storage: Staking Ledger (r:1 w:0)
    // Storage: StakingExtension ThresholdAccounts (r:0 w:1)
    fn change_threshold_accounts() -> Weight {
        Weight::from_ref_time(34_000_000_u64)
            .saturating_add(RocksDbWeight::get().reads(1_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64))
    }

    // Storage: Staking Ledger (r:1 w:1)
    // Storage: Staking CurrentEra (r:1 w:0)
    // Storage: Balances Locks (r:1 w:1)
    // Storage: System Account (r:1 w:1)
    fn withdraw_unbonded() -> Weight {
        Weight::from_ref_time(41_000_000_u64)
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }

    // Storage: Staking Ledger (r:1 w:0)
    // Storage: Staking MinValidatorBond (r:1 w:0)
    // Storage: Staking MinCommission (r:1 w:0)
    // Storage: Staking Validators (r:1 w:1)
    // Storage: Staking MaxValidatorsCount (r:1 w:0)
    // Storage: Staking Nominators (r:1 w:0)
    // Storage: Staking Bonded (r:1 w:0)
    // Storage: BagsList ListNodes (r:1 w:1)
    // Storage: BagsList ListBags (r:1 w:1)
    // Storage: BagsList CounterForListNodes (r:1 w:1)
    // Storage: Staking CounterForValidators (r:1 w:1)
    // Storage: StakingExtension ThresholdAccounts (r:0 w:1)
    // Storage: StakingExtension EndpointRegister (r:0 w:1)
    fn validate() -> Weight {
        Weight::from_ref_time(95_000_000_u64)
            .saturating_add(RocksDbWeight::get().reads(11_u64))
            .saturating_add(RocksDbWeight::get().writes(7_u64))
    }

    fn declare_synced() -> Weight {
        Weight::from_ref_time(36_000_000 as u64)
            .saturating_add(RocksDbWeight::get().reads(1 as u64))
            .saturating_add(RocksDbWeight::get().writes(1 as u64))
    }

    // Storage: StakingExtension SigningGroups (r:2 w:2)
    /// The range of component `c` is `[0, 1000]`.
    /// The range of component `n` is `[0, 1000]`.
    fn new_session_handler_helper(c: u32, n: u32) -> Weight {
        Weight::from_ref_time(39_000_000 as u64)
			// Standard Error: 42_909
			.saturating_add(Weight::from_ref_time(1_364_743 as u64).saturating_mul(c as u64))
			// Standard Error: 42_909
			.saturating_add(Weight::from_ref_time(1_392_245 as u64).saturating_mul(n as u64))
			.saturating_add(RocksDbWeight::get().reads(2 as u64))
			.saturating_add(RocksDbWeight::get().writes(2 as u64))
    }
}
