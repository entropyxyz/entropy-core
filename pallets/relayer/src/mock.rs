use frame_election_provider_support::{onchain, SequentialPhragmen, VoteWeight};
use frame_support::{
  parameter_types,
  traits::{ConstU32, FindAuthor, OneSessionHandler},
};
use frame_system as system;
use pallet_session::historical as pallet_session_historical;
use sp_core::H256;
use sp_runtime::{
  curve::PiecewiseLinear,
  testing::{Header, TestXt, UintAuthorityId},
  traits::{BlakeTwo256, ConvertInto, IdentityLookup},
  Perbill,
};
use sp_staking::{EraIndex, SessionIndex};

use crate as pallet_relayer;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;
type BlockNumber = u64;
type AccountId = u64;
type Balance = u64;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
  pub enum Test where
    Block = Block,
    NodeBlock = Block,
    UncheckedExtrinsic = UncheckedExtrinsic,
  {
    System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
    Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
    Authorship: pallet_authorship::{Pallet, Call, Storage, Inherent},
    Timestamp: pallet_timestamp::{Pallet, Call, Storage, Inherent},
    Relayer: pallet_relayer::{Pallet, Call, Storage, Event<T>},
    Staking: pallet_staking_extension::{Pallet, Call, Storage, Event<T>, Config<T>},
    FrameStaking: pallet_staking::{Pallet, Call, Storage, Event<T>},
    Session: pallet_session::{Pallet, Call, Storage, Event, Config<T>},
    Historical: pallet_session_historical::{Pallet},
    BagsList: pallet_bags_list::{Pallet, Call, Storage, Event<T>},
  }
);

parameter_types! {
  pub const BlockHashCount: u64 = 250;
  pub const SS58Prefix: u8 = 42;
}

impl system::Config for Test {
  type AccountData = pallet_balances::AccountData<Balance>;
  type AccountId = u64;
  type BaseCallFilter = frame_support::traits::Everything;
  type BlockHashCount = BlockHashCount;
  type BlockLength = ();
  type BlockNumber = u64;
  type BlockWeights = ();
  type Call = Call;
  type DbWeight = ();
  type Event = Event;
  type Hash = H256;
  type Hashing = BlakeTwo256;
  type Header = Header;
  type Index = u64;
  type Lookup = IdentityLookup<Self::AccountId>;
  type MaxConsumers = frame_support::traits::ConstU32<16>;
  type OnKilledAccount = ();
  type OnNewAccount = ();
  type OnSetCode = ();
  type Origin = Origin;
  type PalletInfo = PalletInfo;
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
  type Event = Event;
  type ExistentialDeposit = ExistentialDeposit;
  type MaxLocks = MaxLocks;
  type MaxReserves = ();
  type ReserveIdentifier = [u8; 8];
  type WeightInfo = ();
}

pub struct OtherSessionHandler;
impl OneSessionHandler<AccountId> for OtherSessionHandler {
  type Key = UintAuthorityId;

  fn on_genesis_session<'a, I: 'a>(_: I)
  where
    I: Iterator<Item = (&'a AccountId, Self::Key)>,
    AccountId: 'a, {
  }

  fn on_new_session<'a, I: 'a>(_: bool, _: I, _: I)
  where
    I: Iterator<Item = (&'a AccountId, Self::Key)>,
    AccountId: 'a, {
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

pub struct OnChainSeqPhragmen;
impl onchain::ExecutionConfig for OnChainSeqPhragmen {
  type DataProvider = FrameStaking;
  type Solver = SequentialPhragmen<AccountId, Perbill>;
  type System = Test;
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
  pub const MaxNominatorRewardedPerValidator: u32 = 64;
  pub const MaxKeys: u32 = 10_000;
  pub const MaxPeerInHeartbeats: u32 = 10_000;
  pub const MaxPeerDataEncodingSize: u32 = 1_000;
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Test
where Call: From<C>
{
  type Extrinsic = TestXt<Call, ()>;
  type OverarchingCall = Call;
}

const THRESHOLDS: [sp_npos_elections::VoteWeight; 9] =
  [10, 20, 30, 40, 50, 60, 1_000, 2_000, 10_000];

parameter_types! {
  pub static BagThresholds: &'static [sp_npos_elections::VoteWeight] = &THRESHOLDS;
}

impl pallet_bags_list::Config for Test {
  type BagThresholds = BagThresholds;
  type Event = Event;
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
  pub static MaxNominations: u32 = 16;
}

pub struct StakingBenchmarkingConfig;
impl pallet_staking::BenchmarkingConfig for StakingBenchmarkingConfig {
  type MaxNominators = ConstU32<1000>;
  type MaxValidators = ConstU32<1000>;
}

impl pallet_staking::Config for Test {
  type BenchmarkingConfig = StakingBenchmarkingConfig;
  type BondingDuration = BondingDuration;
  type Currency = Balances;
  type CurrencyToVote = frame_support::traits::SaturatingCurrencyToVote;
  type ElectionProvider = onchain::UnboundedExecution<OnChainSeqPhragmen>;
  type EraPayout = pallet_staking::ConvertCurve<RewardCurve>;
  type Event = Event;
  type GenesisElectionProvider = Self::ElectionProvider;
  type MaxNominations = MaxNominations;
  type MaxNominatorRewardedPerValidator = MaxNominatorRewardedPerValidator;
  type MaxUnlockingChunks = ConstU32<32>;
  type NextNewSession = Session;
  type OffendingValidatorsThreshold = OffendingValidatorsThreshold;
  type Reward = ();
  type RewardRemainder = ();
  type SessionInterface = Self;
  type SessionsPerEra = SessionsPerEra;
  type Slash = ();
  type SlashCancelOrigin = frame_system::EnsureRoot<Self::AccountId>;
  type SlashDeferDuration = SlashDeferDuration;
  type UnixTime = pallet_timestamp::Pallet<Test>;
  type VoterList = BagsList;
  type WeightInfo = ();
}

impl pallet_session::Config for Test {
  type Event = Event;
  type Keys = UintAuthorityId;
  type NextSessionRotation = pallet_session::PeriodicSessions<Period, Offset>;
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

parameter_types! {
  pub const MaxEndpointLength: u32 = 3;
}
impl pallet_staking_extension::Config for Test {
  type Currency = Balances;
  type Event = Event;
  type MaxEndpointLength = MaxEndpointLength;
  type WeightInfo = ();
}

parameter_types! {
  pub const UncleGenerations: u64 = 0;
}

/// Author of block is always 11
pub struct Author11;
impl FindAuthor<u64> for Author11 {
  fn find_author<'a, I>(_digests: I) -> Option<u64>
  where I: 'a + IntoIterator<Item = (frame_support::ConsensusEngineId, &'a [u8])> {
    Some(11)
  }
}

impl pallet_authorship::Config for Test {
  type EventHandler = ();
  type FilterUncle = ();
  type FindAuthor = Author11;
  type UncleGenerations = UncleGenerations;
}

parameter_types! {
  pub const PruneBlock: u64 = 3;
}

impl pallet_relayer::Config for Test {
  type Event = Event;
  type PruneBlock = PruneBlock;
  type WeightInfo = ();
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
  system::GenesisConfig::default().build_storage::<Test>().unwrap().into()
}
