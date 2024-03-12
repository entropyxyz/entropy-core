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

use frame_support::parameter_types;
use frame_system as system;
use pallet_session::historical as pallet_session_historical;
use sp_core::H256;
use sp_runtime::{
    testing::UintAuthorityId,
    traits::{BlakeTwo256, ConvertInto, IdentityLookup},
    BuildStorage,
};
use sp_staking::{
    offence::{OffenceError, ReportOffence},
    SessionIndex,
};

use crate as pallet_slashing;

type Block = frame_system::mocking::MockBlock<Test>;
type Balance = u64;
type AccountId = u64;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Balances: pallet_balances,
    Slashing: pallet_slashing,
    Session: pallet_session,
    Historical: pallet_session_historical,
  }
);

parameter_types! {
  pub const BlockHashCount: u64 = 250;
  pub const SS58Prefix: u8 = 42;
}

impl system::Config for Test {
    type AccountData = pallet_balances::AccountData<u64>;
    type AccountId = u64;
    type BaseCallFilter = frame_support::traits::Everything;
    type Block = Block;
    type BlockHashCount = BlockHashCount;
    type BlockLength = ();
    type BlockWeights = ();
    type DbWeight = ();
    type Hash = H256;
    type Hashing = BlakeTwo256;
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
    type SS58Prefix = SS58Prefix;
    type SystemWeightInfo = ();
    type Version = ();
}

parameter_types! {
  pub const ExistentialDeposit: Balance = 1;
}

impl pallet_balances::Config for Test {
    type AccountStore = System;
    type Balance = Balance;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type FreezeIdentifier = ();
    type MaxFreezes = ();
    type MaxHolds = ();
    type MaxLocks = ();
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    type RuntimeEvent = RuntimeEvent;
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = RuntimeFreezeReason;
    type WeightInfo = ();
}

parameter_types! {
  pub const Period: u64 = 1;
  pub const Offset: u64 = 0;
}

parameter_types! {
    pub static Validators: Option<Vec<u64>> = Some(vec![
        1,
        2,
        3,
    ]);
}
pub struct TestSessionManager;
impl pallet_session::SessionManager<u64> for TestSessionManager {
    fn new_session(_new_index: SessionIndex) -> Option<Vec<u64>> {
        Validators::mutate(|l| l.take())
    }
    fn end_session(_: SessionIndex) {}
    fn start_session(_: SessionIndex) {}
}

impl pallet_session::historical::SessionManager<u64, u64> for TestSessionManager {
    fn new_session(_new_index: SessionIndex) -> Option<Vec<(u64, u64)>> {
        Validators::mutate(|l| {
            l.take().map(|validators| validators.iter().map(|v| (*v, *v)).collect())
        })
    }
    fn end_session(_: SessionIndex) {}
    fn start_session(_: SessionIndex) {}
}

impl pallet_session::Config for Test {
    type Keys = UintAuthorityId;
    type NextSessionRotation = pallet_session::PeriodicSessions<Period, Offset>;
    type RuntimeEvent = RuntimeEvent;
    type SessionHandler = (Slashing,);
    type SessionManager = TestSessionManager; // TODO (Nando): Use HistoricalSessionManager?
    type ShouldEndSession = pallet_session::PeriodicSessions<Period, Offset>;
    type ValidatorId = AccountId;
    type ValidatorIdOf = ConvertInto;
    type WeightInfo = ();
}

impl pallet_session::historical::Config for Test {
    type FullIdentification = u64;
    type FullIdentificationOf = ConvertInto;
}

type IdentificationTuple = (u64, u64);
type Offence = crate::UnresponsivenessOffence<IdentificationTuple>;

parameter_types! {
    pub static Offences: Vec<Offence> = vec![];
}

/// A mock offence report handler.
pub struct OffenceHandler;
impl ReportOffence<AccountId, IdentificationTuple, Offence> for OffenceHandler {
    fn report_offence(_reporters: Vec<u64>, offence: Offence) -> Result<(), OffenceError> {
        Offences::mutate(|l| l.push(offence));
        Ok(())
    }

    fn is_known_offence(_offenders: &[IdentificationTuple], _time_slot: &SessionIndex) -> bool {
        false
    }
}

parameter_types! {
  // pub const MinValidators: u32 = 3;
  pub const ReportThreshold: u32 = 5;
}

impl pallet_slashing::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type AuthorityId = UintAuthorityId;
    type ReportThreshold = ReportThreshold;
    type ValidatorSet = Historical;
    type ReportUnresponsiveness = OffenceHandler;

    // type MinValidators = MinValidators;
    // type ValidatorIdOf = ConvertInto;
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut storage = system::GenesisConfig::<Test>::default().build_storage().unwrap();
    let _ = pallet_session::GenesisConfig::<Test> {
        keys: (0..5).map(|id| (id, id, UintAuthorityId(id))).collect(),
    }
    .assimilate_storage(&mut storage);
    sp_io::TestExternalities::from(storage)
}
