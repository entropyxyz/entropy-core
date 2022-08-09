#![allow(unused_parens)]
#![allow(unused_imports)]

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
}

/// Weights for pallet_realyer using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
  fn change_endpoint() -> Weight {
    (34_000_000 as Weight)
      .saturating_add(T::DbWeight::get().reads(1 as Weight))
      .saturating_add(T::DbWeight::get().writes(1 as Weight))
  }

  // Storage: Staking Ledger (r:1 w:0)
  // Storage: StakingExtension ThresholdAccounts (r:0 w:1)
  fn change_threshold_accounts() -> Weight {
    (34_000_000 as Weight)
      .saturating_add(T::DbWeight::get().reads(1 as Weight))
      .saturating_add(T::DbWeight::get().writes(1 as Weight))
  }

  // Storage: Staking Ledger (r:1 w:1)
  // Storage: Staking CurrentEra (r:1 w:0)
  // Storage: Balances Locks (r:1 w:1)
  // Storage: System Account (r:1 w:1)
  fn withdraw_unbonded() -> Weight {
    (41_000_000 as Weight)
      .saturating_add(T::DbWeight::get().reads(4 as Weight))
      .saturating_add(T::DbWeight::get().writes(3 as Weight))
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
    (95_000_000 as Weight)
      .saturating_add(T::DbWeight::get().reads(11 as Weight))
      .saturating_add(T::DbWeight::get().writes(7 as Weight))
  }
}

// For backwards compatibility and tests
impl WeightInfo for () {
  fn change_endpoint() -> Weight {
    (34_000_000 as Weight)
      .saturating_add(RocksDbWeight::get().reads(1 as Weight))
      .saturating_add(RocksDbWeight::get().writes(1 as Weight))
  }

  // Storage: Staking Ledger (r:1 w:0)
  // Storage: StakingExtension ThresholdAccounts (r:0 w:1)
  fn change_threshold_accounts() -> Weight {
    (34_000_000 as Weight)
      .saturating_add(RocksDbWeight::get().reads(1 as Weight))
      .saturating_add(RocksDbWeight::get().writes(1 as Weight))
  }

  // Storage: Staking Ledger (r:1 w:1)
  // Storage: Staking CurrentEra (r:1 w:0)
  // Storage: Balances Locks (r:1 w:1)
  // Storage: System Account (r:1 w:1)
  fn withdraw_unbonded() -> Weight {
    (41_000_000 as Weight)
      .saturating_add(RocksDbWeight::get().reads(4 as Weight))
      .saturating_add(RocksDbWeight::get().writes(3 as Weight))
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
    (95_000_000 as Weight)
      .saturating_add(RocksDbWeight::get().reads(11 as Weight))
      .saturating_add(RocksDbWeight::get().writes(7 as Weight))
  }
}
