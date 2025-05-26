// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Mocks for the parameters pallet.

#![cfg(test)]

use entropy_shared::attestation::MEASUREMENT_VALUE_MOCK_QUOTE;
use frame_support::{
    construct_runtime, derive_impl, ord_parameter_types,
    traits::{ConstU64, Everything, OneSessionHandler},
};
use frame_system::EnsureRoot;
use sp_core::H256;
use sp_runtime::{
    testing::UintAuthorityId,
    traits::{ConvertInto, IdentityLookup},
    BuildStorage,
};

use super::*;

pub type AccountId = u128;

use crate as pallet_parameters;

#[derive_impl(frame_system::config_preludes::TestDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Runtime {
    type AccountData = ();
    type AccountId = AccountId;
    type BaseCallFilter = Everything;
    type Block = Block;
    type BlockHashCount = ConstU64<250>;
    type BlockLength = ();
    type BlockWeights = ();
    type DbWeight = ();
    type Hash = H256;
    type Hashing = sp_runtime::traits::BlakeTwo256;
    type Lookup = IdentityLookup<Self::AccountId>;
    type MaxConsumers = frame_support::traits::ConstU32<16>;
    type Nonce = u64;
    type OnKilledAccount = ();
    type OnNewAccount = ();
    type OnSetCode = ();
    type PalletInfo = PalletInfo;
    type RuntimeCall = RuntimeCall;
    type RuntimeEvent = RuntimeEvent;
    type RuntimeOrigin = RuntimeOrigin;
    type SS58Prefix = ();
    type SystemWeightInfo = ();
    type Version = ();
}

pub struct MockSessionManager;
impl pallet_session::SessionManager<AccountId> for MockSessionManager {
    fn end_session(_: sp_staking::SessionIndex) {}
    fn start_session(_: sp_staking::SessionIndex) {}
    fn new_session(_: sp_staking::SessionIndex) -> Option<Vec<AccountId>> {
        None
    }
}

pub struct OtherSessionHandler;
impl OneSessionHandler<AccountId> for OtherSessionHandler {
    type Key = UintAuthorityId;

    fn on_genesis_session<'a, I: 'a>(_: I)
    where
        I: Iterator<Item = (&'a AccountId, Self::Key)>,
        AccountId: 'a,
    {
    }

    fn on_new_session<'a, I: 'a>(_: bool, _: I, _: I)
    where
        I: Iterator<Item = (&'a AccountId, Self::Key)>,
        AccountId: 'a,
    {
    }

    fn on_disabled(_validator_index: u32) {}
}

impl sp_runtime::BoundToRuntimeAppPublic for OtherSessionHandler {
    type Public = UintAuthorityId;
}

impl pallet_session::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type ValidatorId = u128;
    type ValidatorIdOf = ConvertInto;
    type ShouldEndSession = pallet_session::PeriodicSessions<ConstU64<1>, ConstU64<0>>;
    type NextSessionRotation = pallet_session::PeriodicSessions<ConstU64<1>, ConstU64<0>>;
    type SessionManager = MockSessionManager;
    type SessionHandler = (OtherSessionHandler,);
    type Keys = UintAuthorityId;
    type DisablingStrategy = ();
    type WeightInfo = ();
}

ord_parameter_types! {
  pub const One: AccountId = 1;
}

impl Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type UpdateOrigin = EnsureRoot<AccountId>;
    type WeightInfo = ();
}

type Block = frame_system::mocking::MockBlock<Runtime>;

construct_runtime!(
  pub enum Runtime
  {
    System: frame_system,
    Parameters: pallet_parameters,
    Session: pallet_session,

  }
);

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<Runtime>::default().build_storage().unwrap();
    let pallet_parameters = pallet_parameters::GenesisConfig::<Runtime> {
        request_limit: 5u32,
        max_instructions_per_programs: 5u64,
        total_signers: 5u8,
        threshold: 3u8,
        accepted_measurement_values: vec![BoundedVec::try_from(
            MEASUREMENT_VALUE_MOCK_QUOTE.to_vec(),
        )
        .unwrap()],
        _config: Default::default(),
    };
    pallet_parameters.assimilate_storage(&mut t).unwrap();
    t.into()
}
