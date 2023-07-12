use std::cell::RefCell;

use frame_election_provider_support::{onchain, SequentialPhragmen, VoteWeight};
use frame_support::{
    parameter_types,
    traits::{ConstU32, GenesisBuild, OneSessionHandler},
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
use sp_staking::{
    offence::{OffenceError, ReportOffence},
    EraIndex, SessionIndex,
};

use crate as pallet_slashing;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;
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
    Slashing: pallet_slashing::{Pallet, Call, Storage, Event<T>},
    Session: pallet_session::{Pallet, Call, Storage, Event, Config<T>},
    Historical: pallet_session_historical::{Pallet},
    Timestamp: pallet_timestamp::{Pallet, Call, Storage, Inherent},
    Staking: pallet_staking::{Pallet, Call, Storage, Config<T>, Event<T>},
    BagsList: pallet_bags_list::{Pallet, Call, Storage, Event<T>},
  }
);
type AccountId = u64;

parameter_types! {
  pub const BlockHashCount: u64 = 250;
  pub const SS58Prefix: u8 = 42;
}

impl system::Config for Test {
    type AccountData = pallet_balances::AccountData<Balance>;
    type AccountId = AccountId;
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockHashCount = BlockHashCount;
    type BlockLength = ();
    type BlockNumber = u64;
    type BlockWeights = ();
    type DbWeight = ();
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type Header = Header;
    type Index = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type MaxConsumers = frame_support::traits::ConstU32<16>;
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

impl sp_runtime::BoundToRuntimeAppPublic for TestSessionHandler {
    type Public = UintAuthorityId;
}

pub struct TestSessionHandler;
impl pallet_session::SessionHandler<AccountId> for TestSessionHandler {
    const KEY_TYPE_IDS: &'static [sp_runtime::KeyTypeId] = &[];

    fn on_genesis_session<Ks: sp_runtime::traits::OpaqueKeys>(_validators: &[(AccountId, Ks)]) {}

    fn on_new_session<Ks: sp_runtime::traits::OpaqueKeys>(
        _: bool,
        _: &[(AccountId, Ks)],
        _: &[(AccountId, Ks)],
    ) {
    }

    fn on_disabled(_: u32) {}
}

impl OneSessionHandler<AccountId> for TestSessionHandler {
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

parameter_types! {
  pub const Period: u64 = 1;
  pub const Offset: u64 = 0;
}

sp_runtime::impl_opaque_keys! {
  pub struct SessionKeys {
    pub foo: TestSessionHandler,
  }
}

impl pallet_session::Config for Test {
    type Keys = SessionKeys;
    type NextSessionRotation = pallet_session::PeriodicSessions<Period, Offset>;
    type RuntimeEvent = RuntimeEvent;
    type SessionHandler = (TestSessionHandler,);
    type SessionManager = ();
    type ShouldEndSession = pallet_session::PeriodicSessions<Period, Offset>;
    type ValidatorId = AccountId;
    type ValidatorIdOf = ConvertInto;
    type WeightInfo = ();
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Test
where RuntimeCall: From<C>
{
    type Extrinsic = TestXt<RuntimeCall, ()>;
    type OverarchingCall = RuntimeCall;
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
  pub const SessionsPerEra: SessionIndex = 3;
  pub const BondingDuration: EraIndex = 3;
  pub const SlashDeferDuration: EraIndex = 0;
  pub const RewardCurve: &'static PiecewiseLinear<'static> = &REWARD_CURVE;
  pub const OffendingValidatorsThreshold: Perbill = Perbill::from_percent(16);
  pub static MaxNominations: u32 = 16;
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
    type ScoreProvider = Staking;
    type WeightInfo = ();
}

pub struct OnChainSeqPhragmen;
impl onchain::Config for OnChainSeqPhragmen {
    type DataProvider = Staking;
    type MaxWinners = ConstU32<100>;
    type Solver = SequentialPhragmen<AccountId, Perbill>;
    type System = Test;
    type TargetsBound = ConstU32<{ u32::MAX }>;
    type VotersBound = ConstU32<{ u32::MAX }>;
    type WeightInfo = ();
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
    type CurrencyToVote = frame_support::traits::SaturatingCurrencyToVote;
    type ElectionProvider = onchain::OnChainExecution<OnChainSeqPhragmen>;
    type EraPayout = pallet_staking::ConvertCurve<RewardCurve>;
    type GenesisElectionProvider = Self::ElectionProvider;
    type HistoryDepth = ConstU32<84>;
    type MaxNominations = MaxNominations;
    type MaxNominatorRewardedPerValidator = ConstU32<64>;
    type MaxUnlockingChunks = ConstU32<32>;
    type NextNewSession = Session;
    type OffendingValidatorsThreshold = OffendingValidatorsThreshold;
    type OnStakerSlash = ();
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

parameter_types! {
  pub const ExistentialDeposit: Balance = 1;
}

impl pallet_balances::Config for Test {
    type AccountStore = System;
    type Balance = Balance;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type FreezeIdentifier = ();
    type HoldIdentifier = ();
    type MaxFreezes = ();
    type MaxHolds = ();
    type MaxLocks = ();
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
}

impl pallet_session::historical::Config for Test {
    type FullIdentification = pallet_staking::Exposure<AccountId, Balance>;
    type FullIdentificationOf = pallet_staking::ExposureOf<Self>;
}

type IdentificationTuple = (u64, pallet_staking::Exposure<u64, Balance>);
type Offence = crate::TuxAngry<IdentificationTuple>;

thread_local! {
  pub static OFFENCES: RefCell<Vec<(Vec<u64>, Offence)>> = RefCell::new(vec![]);
}

pub struct OffenceHandler;
impl ReportOffence<u64, IdentificationTuple, Offence> for OffenceHandler {
    fn report_offence(reporters: Vec<u64>, offence: Offence) -> Result<(), OffenceError> {
        OFFENCES.with(|l| l.borrow_mut().push((reporters, offence)));
        Ok(())
    }

    fn is_known_offence(_offenders: &[IdentificationTuple], _time_slot: &SessionIndex) -> bool {
        false
    }
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
  pub const MinValidators: u32 = 3;
}

impl pallet_slashing::Config for Test {
    type AuthorityId = UintAuthorityId;
    type MinValidators = MinValidators;
    type ReportBad = OffenceHandler;
    type RuntimeEvent = RuntimeEvent;
    type ValidatorIdOf = ConvertInto;
    type ValidatorSet = Historical;
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut storage = system::GenesisConfig::default().build_storage::<Test>().unwrap();
    let _ = pallet_session::GenesisConfig::<Test> {
        keys: (0..5).map(|id| (id, id, SessionKeys { foo: id.into() })).collect(),
    }
    .assimilate_storage(&mut storage);
    sp_io::TestExternalities::from(storage)
}
