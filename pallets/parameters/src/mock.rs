// This file is part of Acala.

// Copyright (C) 2020-2022 Acala Foundation.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Mocks for the transaction pause module.

#![cfg(test)]

use frame_support::{
    construct_runtime, ord_parameter_types, parameter_types,
    traits::{ConstU64, Everything},
};
use frame_system::EnsureSignedBy;
use sp_core::H256;
use sp_runtime::{traits::IdentityLookup, BuildStorage};

use super::*;

pub type AccountId = u128;

use crate as pallet_parameters;

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

ord_parameter_types! {
  pub const One: AccountId = 1;
}

parameter_types! {
  pub const RequestLimit: u32 = 5;
}

impl Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type UpdateOrigin = EnsureSignedBy<One, AccountId>;
    type WeightInfo = ();
}

type Block = frame_system::mocking::MockBlock<Runtime>;

construct_runtime!(
  pub enum Runtime
  {
    System: frame_system,
    Parameters: pallet_parameters,
  }
);

pub struct ExtBuilder;

impl Default for ExtBuilder {
    fn default() -> Self {
        ExtBuilder
    }
}

impl ExtBuilder {
    pub fn build(self) -> sp_io::TestExternalities {
        let mut t = frame_system::GenesisConfig::<Runtime>::default().build_storage().unwrap();
        let pallet_parameters =
            pallet_parameters::GenesisConfig::<Runtime> { request_limit: 5, ..Default::default() };
        pallet_parameters.assimilate_storage(&mut t).unwrap();
        t.into()
    }
}