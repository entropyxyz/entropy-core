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

//! Mocks for the outtie pallet.

#![cfg(test)]
use entropy_shared::attestation::QuoteContext;
use frame_support::{
    construct_runtime, derive_impl, parameter_types,
    traits::{ConstU64, Everything, OneSessionHandler},
};
use sp_core::H256;
use sp_runtime::{
    testing::UintAuthorityId,
    traits::{ConvertInto, IdentityLookup},
    BuildStorage,
};

use super::*;

pub type AccountId = u128;

use crate as pallet_outtie;

#[derive_impl(frame_system::config_preludes::TestDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Test {
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

impl pallet_session::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type ValidatorId = u128;
    type ValidatorIdOf = ConvertInto;
    type ShouldEndSession = pallet_session::PeriodicSessions<ConstU64<1>, ConstU64<0>>;
    type NextSessionRotation = pallet_session::PeriodicSessions<ConstU64<1>, ConstU64<0>>;
    type SessionManager = MockSessionManager;
    type SessionHandler = (OtherSessionHandler,);
    type Keys = UintAuthorityId;
    type WeightInfo = ();
}

parameter_types! {
  pub const MaxEndpointLength: u32 = 3;
}

pub(crate) const VALID_QUOTE: [u8; 32] = [0; 32];
pub(crate) const INVALID_QUOTE: [u8; 32] = [1; 32];

// TODO deduplicate this from staking extension pallet mock
pub struct MockAttestationHandler;

impl entropy_shared::attestation::AttestationHandler<AccountId> for MockAttestationHandler {
    fn verify_quote(
        _attestee: &AccountId,
        _x25519_public_key: entropy_shared::X25519PublicKey,
        quote: Vec<u8>,
        _context: QuoteContext,
    ) -> Result<
        entropy_shared::BoundedVecEncodedVerifyingKey,
        entropy_shared::attestation::VerifyQuoteError,
    > {
        let quote: Result<[u8; 32], _> = quote.try_into();
        match quote {
            Ok(q) if q == VALID_QUOTE => Ok([0; 33].to_vec().try_into().unwrap()),
            Ok(q) if q == INVALID_QUOTE => {
                Err(entropy_shared::attestation::VerifyQuoteError::BadQuote)
            },
            _ => {
                // We don't really want to verify quotes for tests in this pallet, so if we get
                // something else we'll just accept it.
                Ok(BoundedVec::new())
            },
        }
    }

    fn request_quote(_attestee: &AccountId, _nonce: [u8; 32]) {}
}

impl Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type MaxEndpointLength = MaxEndpointLength;
    type WeightInfo = ();
    type AttestationHandler = MockAttestationHandler;
}

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Outtie: pallet_outtie,
    Session: pallet_session,

  }
);

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
    t.into()
}
