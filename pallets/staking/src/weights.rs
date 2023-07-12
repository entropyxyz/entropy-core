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

/// Weight functions for `pallet_staking_extension`.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    /// Storage: Staking Ledger (r:1 w:0)
    /// Proof: Staking Ledger (max_values: None, max_size: Some(1091), added: 3566, mode:
    /// MaxEncodedLen) Storage: StakingExtension ThresholdServers (r:1 w:1)
    /// Proof Skipped: StakingExtension ThresholdServers (max_values: None, max_size: None, mode:
    /// Measured)
    fn change_endpoint() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `1098`
        //  Estimated: `4563`
        // Minimum execution time: 50_000_000 picoseconds.
        Weight::from_parts(52_000_000, 0)
            .saturating_add(Weight::from_parts(0, 4563))
            .saturating_add(T::DbWeight::get().reads(2))
            .saturating_add(T::DbWeight::get().writes(1))
    }

    /// Storage: Staking Ledger (r:1 w:0)
    /// Proof: Staking Ledger (max_values: None, max_size: Some(1091), added: 3566, mode:
    /// MaxEncodedLen) Storage: StakingExtension ThresholdServers (r:1 w:1)
    /// Proof Skipped: StakingExtension ThresholdServers (max_values: None, max_size: None, mode:
    /// Measured) Storage: StakingExtension ThresholdToStash (r:0 w:1)
    /// Proof Skipped: StakingExtension ThresholdToStash (max_values: None, max_size: None, mode:
    /// Measured)
    fn change_threshold_accounts() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `1098`
        //  Estimated: `4563`
        // Minimum execution time: 47_000_000 picoseconds.
        Weight::from_parts(52_000_000, 0)
            .saturating_add(Weight::from_parts(0, 4563))
            .saturating_add(T::DbWeight::get().reads(2))
            .saturating_add(T::DbWeight::get().writes(2))
    }

    /// Storage: Staking Ledger (r:1 w:1)
    /// Proof: Staking Ledger (max_values: None, max_size: Some(1091), added: 3566, mode:
    /// MaxEncodedLen) Storage: Staking CurrentEra (r:1 w:0)
    /// Proof: Staking CurrentEra (max_values: Some(1), max_size: Some(4), added: 499, mode:
    /// MaxEncodedLen) Storage: Balances Locks (r:1 w:1)
    /// Proof: Balances Locks (max_values: None, max_size: Some(1299), added: 3774, mode:
    /// MaxEncodedLen) Storage: Balances Freezes (r:1 w:0)
    /// Proof: Balances Freezes (max_values: None, max_size: Some(49), added: 2524, mode:
    /// MaxEncodedLen) Storage: System Account (r:1 w:1)
    /// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode:
    /// MaxEncodedLen)
    fn withdraw_unbonded() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `1039`
        //  Estimated: `4764`
        // Minimum execution time: 75_000_000 picoseconds.
        Weight::from_parts(81_000_000, 0)
            .saturating_add(Weight::from_parts(0, 4764))
            .saturating_add(T::DbWeight::get().reads(5))
            .saturating_add(T::DbWeight::get().writes(3))
    }

    /// Storage: Staking Ledger (r:1 w:0)
    /// Proof: Staking Ledger (max_values: None, max_size: Some(1091), added: 3566, mode:
    /// MaxEncodedLen) Storage: Staking MinValidatorBond (r:1 w:0)
    /// Proof: Staking MinValidatorBond (max_values: Some(1), max_size: Some(16), added: 511, mode:
    /// MaxEncodedLen) Storage: Staking MinCommission (r:1 w:0)
    /// Proof: Staking MinCommission (max_values: Some(1), max_size: Some(4), added: 499, mode:
    /// MaxEncodedLen) Storage: Staking Validators (r:1 w:1)
    /// Proof: Staking Validators (max_values: None, max_size: Some(45), added: 2520, mode:
    /// MaxEncodedLen) Storage: Staking MaxValidatorsCount (r:1 w:0)
    /// Proof: Staking MaxValidatorsCount (max_values: Some(1), max_size: Some(4), added: 499, mode:
    /// MaxEncodedLen) Storage: Staking Nominators (r:1 w:0)
    /// Proof: Staking Nominators (max_values: None, max_size: Some(558), added: 3033, mode:
    /// MaxEncodedLen) Storage: Staking Bonded (r:1 w:0)
    /// Proof: Staking Bonded (max_values: None, max_size: Some(72), added: 2547, mode:
    /// MaxEncodedLen) Storage: BagsList ListNodes (r:1 w:1)
    /// Proof: BagsList ListNodes (max_values: None, max_size: Some(154), added: 2629, mode:
    /// MaxEncodedLen) Storage: BagsList ListBags (r:1 w:1)
    /// Proof: BagsList ListBags (max_values: None, max_size: Some(82), added: 2557, mode:
    /// MaxEncodedLen) Storage: BagsList CounterForListNodes (r:1 w:1)
    /// Proof: BagsList CounterForListNodes (max_values: Some(1), max_size: Some(4), added: 499,
    /// mode: MaxEncodedLen) Storage: Staking CounterForValidators (r:1 w:1)
    /// Proof: Staking CounterForValidators (max_values: Some(1), max_size: Some(4), added: 499,
    /// mode: MaxEncodedLen) Storage: StakingExtension ThresholdServers (r:0 w:1)
    /// Proof Skipped: StakingExtension ThresholdServers (max_values: None, max_size: None, mode:
    /// Measured) Storage: StakingExtension ThresholdToStash (r:0 w:1)
    /// Proof Skipped: StakingExtension ThresholdToStash (max_values: None, max_size: None, mode:
    /// Measured)
    fn validate() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `1431`
        //  Estimated: `4556`
        // Minimum execution time: 111_000_000 picoseconds.
        Weight::from_parts(113_000_000, 0)
            .saturating_add(Weight::from_parts(0, 4556))
            .saturating_add(T::DbWeight::get().reads(11))
            .saturating_add(T::DbWeight::get().writes(7))
    }

    /// Storage: StakingExtension ThresholdToStash (r:1 w:0)
    /// Proof Skipped: StakingExtension ThresholdToStash (max_values: None, max_size: None, mode:
    /// Measured) Storage: StakingExtension IsValidatorSynced (r:0 w:1)
    /// Proof Skipped: StakingExtension IsValidatorSynced (max_values: None, max_size: None, mode:
    /// Measured)
    fn declare_synced() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `265`
        //  Estimated: `3730`
        // Minimum execution time: 24_000_000 picoseconds.
        Weight::from_parts(25_000_000, 0)
            .saturating_add(Weight::from_parts(0, 3730))
            .saturating_add(T::DbWeight::get().reads(1))
            .saturating_add(T::DbWeight::get().writes(1))
    }

    /// Storage: StakingExtension SigningGroups (r:2 w:2)
    /// Proof Skipped: StakingExtension SigningGroups (max_values: None, max_size: None, mode:
    /// Measured) The range of component `c` is `[0, 1000]`.
    /// The range of component `n` is `[0, 1000]`.
    fn new_session_handler_helper(c: u32, n: u32) -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `198 + c * (32 ±0)`
        //  Estimated: `6136 + c * (32 ±0)`
        // Minimum execution time: 35_000_000 picoseconds.
        Weight::from_parts(35_000_000, 0)
			.saturating_add(Weight::from_parts(0, 6136))
			// Standard Error: 36_508
			.saturating_add(Weight::from_parts(1_163_078, 0).saturating_mul(c.into()))
			// Standard Error: 36_508
			.saturating_add(Weight::from_parts(1_187_631, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
			.saturating_add(Weight::from_parts(0, 32).saturating_mul(c.into()))
    }
}

// For backwards compatibility and tests
impl WeightInfo for () {
    /// Storage: Staking Ledger (r:1 w:0)
    /// Proof: Staking Ledger (max_values: None, max_size: Some(1091), added: 3566, mode:
    /// MaxEncodedLen) Storage: StakingExtension ThresholdServers (r:1 w:1)
    /// Proof Skipped: StakingExtension ThresholdServers (max_values: None, max_size: None, mode:
    /// Measured)
    fn change_endpoint() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `1098`
        //  Estimated: `4563`
        // Minimum execution time: 50_000_000 picoseconds.
        Weight::from_parts(52_000_000, 0)
            .saturating_add(Weight::from_parts(0, 4563))
            .saturating_add(RocksDbWeight::get().reads(2))
            .saturating_add(RocksDbWeight::get().writes(1))
    }

    /// Storage: Staking Ledger (r:1 w:0)
    /// Proof: Staking Ledger (max_values: None, max_size: Some(1091), added: 3566, mode:
    /// MaxEncodedLen) Storage: StakingExtension ThresholdServers (r:1 w:1)
    /// Proof Skipped: StakingExtension ThresholdServers (max_values: None, max_size: None, mode:
    /// Measured) Storage: StakingExtension ThresholdToStash (r:0 w:1)
    /// Proof Skipped: StakingExtension ThresholdToStash (max_values: None, max_size: None, mode:
    /// Measured)
    fn change_threshold_accounts() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `1098`
        //  Estimated: `4563`
        // Minimum execution time: 47_000_000 picoseconds.
        Weight::from_parts(52_000_000, 0)
            .saturating_add(Weight::from_parts(0, 4563))
            .saturating_add(RocksDbWeight::get().reads(2))
            .saturating_add(RocksDbWeight::get().writes(2))
    }

    /// Storage: Staking Ledger (r:1 w:1)
    /// Proof: Staking Ledger (max_values: None, max_size: Some(1091), added: 3566, mode:
    /// MaxEncodedLen) Storage: Staking CurrentEra (r:1 w:0)
    /// Proof: Staking CurrentEra (max_values: Some(1), max_size: Some(4), added: 499, mode:
    /// MaxEncodedLen) Storage: Balances Locks (r:1 w:1)
    /// Proof: Balances Locks (max_values: None, max_size: Some(1299), added: 3774, mode:
    /// MaxEncodedLen) Storage: Balances Freezes (r:1 w:0)
    /// Proof: Balances Freezes (max_values: None, max_size: Some(49), added: 2524, mode:
    /// MaxEncodedLen) Storage: System Account (r:1 w:1)
    /// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode:
    /// MaxEncodedLen)
    fn withdraw_unbonded() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `1039`
        //  Estimated: `4764`
        // Minimum execution time: 75_000_000 picoseconds.
        Weight::from_parts(81_000_000, 0)
            .saturating_add(Weight::from_parts(0, 4764))
            .saturating_add(RocksDbWeight::get().reads(5))
            .saturating_add(RocksDbWeight::get().writes(3))
    }

    /// Storage: Staking Ledger (r:1 w:0)
    /// Proof: Staking Ledger (max_values: None, max_size: Some(1091), added: 3566, mode:
    /// MaxEncodedLen) Storage: Staking MinValidatorBond (r:1 w:0)
    /// Proof: Staking MinValidatorBond (max_values: Some(1), max_size: Some(16), added: 511, mode:
    /// MaxEncodedLen) Storage: Staking MinCommission (r:1 w:0)
    /// Proof: Staking MinCommission (max_values: Some(1), max_size: Some(4), added: 499, mode:
    /// MaxEncodedLen) Storage: Staking Validators (r:1 w:1)
    /// Proof: Staking Validators (max_values: None, max_size: Some(45), added: 2520, mode:
    /// MaxEncodedLen) Storage: Staking MaxValidatorsCount (r:1 w:0)
    /// Proof: Staking MaxValidatorsCount (max_values: Some(1), max_size: Some(4), added: 499, mode:
    /// MaxEncodedLen) Storage: Staking Nominators (r:1 w:0)
    /// Proof: Staking Nominators (max_values: None, max_size: Some(558), added: 3033, mode:
    /// MaxEncodedLen) Storage: Staking Bonded (r:1 w:0)
    /// Proof: Staking Bonded (max_values: None, max_size: Some(72), added: 2547, mode:
    /// MaxEncodedLen) Storage: BagsList ListNodes (r:1 w:1)
    /// Proof: BagsList ListNodes (max_values: None, max_size: Some(154), added: 2629, mode:
    /// MaxEncodedLen) Storage: BagsList ListBags (r:1 w:1)
    /// Proof: BagsList ListBags (max_values: None, max_size: Some(82), added: 2557, mode:
    /// MaxEncodedLen) Storage: BagsList CounterForListNodes (r:1 w:1)
    /// Proof: BagsList CounterForListNodes (max_values: Some(1), max_size: Some(4), added: 499,
    /// mode: MaxEncodedLen) Storage: Staking CounterForValidators (r:1 w:1)
    /// Proof: Staking CounterForValidators (max_values: Some(1), max_size: Some(4), added: 499,
    /// mode: MaxEncodedLen) Storage: StakingExtension ThresholdServers (r:0 w:1)
    /// Proof Skipped: StakingExtension ThresholdServers (max_values: None, max_size: None, mode:
    /// Measured) Storage: StakingExtension ThresholdToStash (r:0 w:1)
    /// Proof Skipped: StakingExtension ThresholdToStash (max_values: None, max_size: None, mode:
    /// Measured)
    fn validate() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `1431`
        //  Estimated: `4556`
        // Minimum execution time: 111_000_000 picoseconds.
        Weight::from_parts(113_000_000, 0)
            .saturating_add(Weight::from_parts(0, 4556))
            .saturating_add(RocksDbWeight::get().reads(11))
            .saturating_add(RocksDbWeight::get().writes(7))
    }

    /// Storage: StakingExtension ThresholdToStash (r:1 w:0)
    /// Proof Skipped: StakingExtension ThresholdToStash (max_values: None, max_size: None, mode:
    /// Measured) Storage: StakingExtension IsValidatorSynced (r:0 w:1)
    /// Proof Skipped: StakingExtension IsValidatorSynced (max_values: None, max_size: None, mode:
    /// Measured)
    fn declare_synced() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `265`
        //  Estimated: `3730`
        // Minimum execution time: 24_000_000 picoseconds.
        Weight::from_parts(25_000_000, 0)
            .saturating_add(Weight::from_parts(0, 3730))
            .saturating_add(RocksDbWeight::get().reads(1))
            .saturating_add(RocksDbWeight::get().writes(1))
    }

    /// Storage: StakingExtension SigningGroups (r:2 w:2)
    /// Proof Skipped: StakingExtension SigningGroups (max_values: None, max_size: None, mode:
    /// Measured) The range of component `c` is `[0, 1000]`.
    /// The range of component `n` is `[0, 1000]`.
    fn new_session_handler_helper(c: u32, n: u32) -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `198 + c * (32 ±0)`
        //  Estimated: `6136 + c * (32 ±0)`
        // Minimum execution time: 35_000_000 picoseconds.
        Weight::from_parts(35_000_000, 0)
			.saturating_add(Weight::from_parts(0, 6136))
			// Standard Error: 36_508
			.saturating_add(Weight::from_parts(1_163_078, 0).saturating_mul(c.into()))
			// Standard Error: 36_508
			.saturating_add(Weight::from_parts(1_187_631, 0).saturating_mul(n.into()))
			.saturating_add(RocksDbWeight::get().reads(2))
			.saturating_add(RocksDbWeight::get().writes(2))
			.saturating_add(Weight::from_parts(0, 32).saturating_mul(c.into()))
    }
}
