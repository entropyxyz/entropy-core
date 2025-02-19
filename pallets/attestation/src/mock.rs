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

use entropy_shared::attestation::MEASUREMENT_VALUE_MOCK_QUOTE;
use frame_election_provider_support::{
    bounds::{ElectionBounds, ElectionBoundsBuilder},
    onchain, SequentialPhragmen, VoteWeight,
};
use frame_support::{
    derive_impl, parameter_types,
    traits::{ConstU32, OneSessionHandler, Randomness},
};
use frame_system as system;
use frame_system::EnsureRoot;
use pallet_session::historical as pallet_session_historical;
use sp_core::H256;
use sp_runtime::{
    curve::PiecewiseLinear,
    testing::{TestXt, UintAuthorityId},
    traits::{BlakeTwo256, ConvertInto, IdentityLookup},
    BoundedVec, BuildStorage, Perbill,
};
use sp_staking::{EraIndex, SessionIndex};
use std::cell::RefCell;

use crate as pallet_attestation;

/// This is a randomly generated secret p256 ECDSA key - for mocking the provisioning certification
/// key
pub const PCK: [u8; 32] = [
    117, 153, 212, 7, 220, 16, 181, 32, 110, 138, 4, 68, 208, 37, 104, 54, 1, 110, 232, 207, 100,
    168, 16, 99, 66, 83, 21, 178, 81, 155, 132, 37,
];

const NULL_ARR: [u8; 32] = [0; 32];

type Block = frame_system::mocking::MockBlock<Test>;
type BlockNumber = u64;
type AccountId = u64;
type Balance = u64;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
  pub enum Test
  {
    Attestation: pallet_attestation,
    System: frame_system,
    Balances: pallet_balances,
    Timestamp: pallet_timestamp,
    Staking: pallet_staking_extension,
    FrameStaking: pallet_staking,
    Session: pallet_session,
    Historical: pallet_session_historical,
    BagsList: pallet_bags_list,
    Parameters: pallet_parameters,
    Slashing: pallet_slashing,
  }
);

impl pallet_attestation::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type Randomness = TestPastRandomness;
}

parameter_types! {
  pub const BlockHashCount: u64 = 250;
  pub const SS58Prefix: u8 = 42;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig as frame_system::DefaultConfig)]
impl system::Config for Test {
    type AccountData = pallet_balances::AccountData<Balance>;
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
  pub const MinimumPeriod: u64 = 3;
}

impl pallet_timestamp::Config for Test {
    type MinimumPeriod = MinimumPeriod;
    type Moment = u64;
    type OnTimestampSet = ();
    type WeightInfo = ();
}

parameter_types! {
  pub const ExistentialDeposit: Balance = 10;
  pub const MaxLocks: u32 = 5;
}
impl pallet_balances::Config for Test {
    type AccountStore = System;
    type Balance = Balance;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type FreezeIdentifier = ();
    type MaxFreezes = ();

    type MaxLocks = MaxLocks;
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    type RuntimeEvent = RuntimeEvent;
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = RuntimeFreezeReason;
    type WeightInfo = ();
}

pub struct OtherSessionHandler;
impl OneSessionHandler<AccountId> for OtherSessionHandler {
    type Key = UintAuthorityId;

    fn on_genesis_session<'a, I>(_: I)
    where
        I: Iterator<Item = (&'a AccountId, Self::Key)> + 'a,
        AccountId: 'a,
    {
    }

    fn on_new_session<'a, I>(_: bool, _: I, _: I)
    where
        I: Iterator<Item = (&'a AccountId, Self::Key)> + 'a,
        AccountId: 'a,
    {
    }

    fn on_disabled(_validator_index: u32) {}
}

impl sp_runtime::BoundToRuntimeAppPublic for OtherSessionHandler {
    type Public = UintAuthorityId;
}

parameter_types! {
  pub const Period: BlockNumber = 5;
  pub const Offset: BlockNumber = 0;
}

sp_runtime::impl_opaque_keys! {
  pub struct SessionKeys {
    pub other: OtherSessionHandler,
  }
}

parameter_types! {
    pub static ElectionsBounds: ElectionBounds = ElectionBoundsBuilder::default().build();
}

pub struct OnChainSeqPhragmen;
impl onchain::Config for OnChainSeqPhragmen {
    type DataProvider = FrameStaking;
    type MaxWinners = ConstU32<100>;
    type Solver = SequentialPhragmen<AccountId, Perbill>;
    type System = Test;
    type Bounds = ElectionsBounds;
    type WeightInfo = ();
}

pallet_staking_reward_curve::build! {
  const REWARD_CURVE: PiecewiseLinear<'static> = curve!(
    min_inflation: 0_025_000u64,
    max_inflation: 0_100_000,
    ideal_stake: 0_500_000,
    falloff: 0_050_000,
    max_piece_count: 40,
    test_precision: 0_005_000,
  );
}
parameter_types! {
  pub const RewardCurve: &'static sp_runtime::curve::PiecewiseLinear<'static> = &REWARD_CURVE;

  pub const MaxKeys: u32 = 10_000;
  pub const MaxPeerInHeartbeats: u32 = 10_000;
  pub const MaxPeerDataEncodingSize: u32 = 1_000;
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Test
where
    RuntimeCall: From<C>,
{
    type Extrinsic = TestXt<RuntimeCall, ()>;
    type OverarchingCall = RuntimeCall;
}

const THRESHOLDS: [sp_npos_elections::VoteWeight; 9] =
    [10, 20, 30, 40, 50, 60, 1_000, 2_000, 10_000];

parameter_types! {
  pub static BagThresholds: &'static [sp_npos_elections::VoteWeight] = &THRESHOLDS;
}

impl pallet_bags_list::Config for Test {
    type BagThresholds = BagThresholds;
    type RuntimeEvent = RuntimeEvent;
    type Score = VoteWeight;
    type ScoreProvider = FrameStaking;
    type WeightInfo = ();
}

parameter_types! {
  pub const SessionsPerEra: SessionIndex = 2;
  pub const BondingDuration: EraIndex = 0;
  pub const SlashDeferDuration: EraIndex = 0;
  pub const AttestationPeriod: u64 = 100;
  pub const ElectionLookahead: u64 = 0;
  pub const StakingUnsignedPriority: u64 = u64::MAX / 2;
  pub const OffendingValidatorsThreshold: Perbill = Perbill::from_percent(17);
}

pub struct StakingBenchmarkingConfig;
impl pallet_staking::BenchmarkingConfig for StakingBenchmarkingConfig {
    type MaxNominators = ConstU32<1000>;
    type MaxValidators = ConstU32<1000>;
}

impl pallet_staking::Config for Test {
    type AdminOrigin = frame_system::EnsureRoot<Self::AccountId>;
    type BenchmarkingConfig = StakingBenchmarkingConfig;
    type BondingDuration = BondingDuration;
    type Currency = Balances;
    type CurrencyBalance = Balance;
    type CurrencyToVote = ();
    type ElectionProvider = onchain::OnChainExecution<OnChainSeqPhragmen>;
    type EraPayout = pallet_staking::ConvertCurve<RewardCurve>;
    type EventListeners = ();
    type GenesisElectionProvider = Self::ElectionProvider;
    type HistoryDepth = ConstU32<84>;
    type MaxExposurePageSize = ConstU32<64>;
    type MaxControllersInDeprecationBatch = ConstU32<100>;
    type MaxUnlockingChunks = ConstU32<32>;
    type NextNewSession = Session;
    type NominationsQuota = pallet_staking::FixedNominationsQuota<16>;
    type OffendingValidatorsThreshold = OffendingValidatorsThreshold;
    type Reward = ();
    type RewardRemainder = ();
    type RuntimeEvent = RuntimeEvent;
    type SessionInterface = Self;
    type SessionsPerEra = SessionsPerEra;
    type Slash = ();
    type SlashDeferDuration = SlashDeferDuration;
    type TargetList = pallet_staking::UseValidatorsMap<Self>;
    type UnixTime = pallet_timestamp::Pallet<Test>;
    type VoterList = BagsList;
    type WeightInfo = ();
}

impl pallet_session::Config for Test {
    type Keys = UintAuthorityId;
    type NextSessionRotation = pallet_session::PeriodicSessions<Period, Offset>;
    type RuntimeEvent = RuntimeEvent;
    type SessionHandler = (OtherSessionHandler,);
    type SessionManager = pallet_session::historical::NoteHistoricalRoot<Test, FrameStaking>;
    type ShouldEndSession = pallet_session::PeriodicSessions<Period, Offset>;
    type ValidatorId = AccountId;
    type ValidatorIdOf = ConvertInto;
    type WeightInfo = ();
}

impl pallet_session::historical::Config for Test {
    type FullIdentification = pallet_staking::Exposure<AccountId, Balance>;
    type FullIdentificationOf = pallet_staking::ExposureOf<Test>;
}

thread_local! {
  pub static LAST_RANDOM: RefCell<Option<(H256, u64)>> = RefCell::new(None);
}

pub struct TestPastRandomness;
impl Randomness<H256, BlockNumber> for TestPastRandomness {
    fn random(_subject: &[u8]) -> (H256, u64) {
        LAST_RANDOM.with(|p| {
            if let Some((output, known_since)) = &*p.borrow() {
                (*output, *known_since)
            } else {
                (H256::zero(), frame_system::Pallet::<Test>::block_number())
            }
        })
    }
}
parameter_types! {
  pub const MaxEndpointLength: u32 = 3;
}
impl pallet_staking_extension::Config for Test {
    type AttestationHandler = ();
    type Currency = Balances;
    type MaxEndpointLength = MaxEndpointLength;
    type Randomness = TestPastRandomness;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
}

parameter_types! {
  pub const UncleGenerations: u64 = 0;
}

parameter_types! {
  pub const MaxProgramHashes: u32 = 5u32;
  pub const KeyVersionNumber: u8 = 1;
}

parameter_types! {
  pub const MaxBytecodeLength: u32 = 3;
  pub const ProgramDepositPerByte: u32 = 5;
  pub const MaxOwnedPrograms: u32 = 5;
}

impl pallet_parameters::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type UpdateOrigin = EnsureRoot<Self::AccountId>;
    type WeightInfo = ();
}

parameter_types! {
    pub const ReportThreshold: u32 = 5;
}

impl pallet_slashing::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type AuthorityId = UintAuthorityId;
    type ReportThreshold = ReportThreshold;
    type ValidatorSet = Historical;
    type ReportUnresponsiveness = ();
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = system::GenesisConfig::<Test>::default().build_storage().unwrap();

    let pallet_attestation = pallet_attestation::GenesisConfig::<Test> {
        initial_pending_attestations: vec![(0, NULL_ARR)],
        initial_attestation_requests: Vec::new(),
    };
    pallet_attestation.assimilate_storage(&mut t).unwrap();

    let pck = tdx_quote::SigningKey::from_bytes(&PCK.into()).unwrap();
    let pck_encoded = tdx_quote::encode_verifying_key(&pck.verifying_key()).unwrap();
    let pallet_staking_extension = pallet_staking_extension::GenesisConfig::<Test> {
        threshold_servers: vec![
            // (ValidatorID, (AccountId, X25519PublicKey, TssServerURL, PCK))
            (5, (0, NULL_ARR, vec![20], pck_encoded.to_vec().try_into().unwrap())),
        ],
        proactive_refresh_data: (vec![], vec![]),
        jump_started_signers: None,
    };
    pallet_staking_extension.assimilate_storage(&mut t).unwrap();

    let pallet_parameters = pallet_parameters::GenesisConfig::<Test> {
        request_limit: 5u32,
        max_instructions_per_programs: 5u64,
        total_signers: 3u8,
        threshold: 2u8,
        accepted_measurement_values: vec![BoundedVec::try_from(
            MEASUREMENT_VALUE_MOCK_QUOTE.to_vec(),
        )
        .unwrap()],
        _config: Default::default(),
    };

    pallet_parameters.assimilate_storage(&mut t).unwrap();

    t.into()
}
