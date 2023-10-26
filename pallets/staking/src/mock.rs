use core::convert::{TryFrom, TryInto};
use std::cell::RefCell;

use frame_election_provider_support::{onchain, SequentialPhragmen, VoteWeight};
use frame_support::{
    parameter_types,
    traits::{ConstU32, Get, Hooks, OneSessionHandler},
};
use frame_system as system;
use pallet_session::{historical as pallet_session_historical, ShouldEndSession};
// use pallet_session::historical as pallet_session_historical;
use pallet_staking_extension::ServerInfo;
use sp_core::H256;
use sp_runtime::{
    curve::PiecewiseLinear,
    testing::{TestXt, UintAuthorityId},
    traits::{BlakeTwo256, ConvertInto, IdentityLookup, OpaqueKeys, Zero},
    BuildStorage, KeyTypeId, Perbill,
};
use sp_staking::{EraIndex, SessionIndex};

use crate as pallet_staking_extension;

type Block = frame_system::mocking::MockBlock<Test>;
type BlockNumber = u64;

pub const INIT_TIMESTAMP: u64 = 30_000;
pub const BLOCK_TIME: u64 = 1000;
const NULL_ARR: [u8; 32] = [0; 32];

pub const KEY_ID_A: KeyTypeId = KeyTypeId([4; 4]);
pub const KEY_ID_B: KeyTypeId = KeyTypeId([9; 4]);
// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Balances: pallet_balances,
    Timestamp: pallet_timestamp,
    Staking: pallet_staking_extension,
    FrameStaking: pallet_staking,
    Session: pallet_session,
    Historical: pallet_session_historical,
    BagsList: pallet_bags_list,
  }
);

thread_local! {
    pub static FORCE_SESSION_END: RefCell<bool> = RefCell::new(false);
    pub static SESSION_LENGTH: RefCell<u64> = RefCell::new(2);
    pub static SESSION_CHANGED: RefCell<bool> = RefCell::new(false);


}
type AccountId = u64;
type Balance = u64;

parameter_types! {
  pub const BlockHashCount: u64 = 250;
  pub const SS58Prefix: u8 = 42;
}

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
    type MaxHolds = ();
    type MaxLocks = MaxLocks;
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    type RuntimeEvent = RuntimeEvent;
    type RuntimeHoldReason = RuntimeHoldReason;
    type WeightInfo = ();
}

#[derive(Debug, Clone, codec::Encode, codec::Decode, PartialEq, Eq)]
pub struct PreUpgradeMockSessionKeys {
    pub a: [u8; 32],
    pub b: [u8; 64],
}

impl OpaqueKeys for PreUpgradeMockSessionKeys {
    type KeyTypeIdProviders = ();

    fn key_ids() -> &'static [KeyTypeId] {
        &[KEY_ID_A, KEY_ID_B]
    }

    fn get_raw(&self, i: KeyTypeId) -> &[u8] {
        match i {
            i if i == KEY_ID_A => &self.a[..],
            i if i == KEY_ID_B => &self.b[..],
            _ => &[],
        }
    }
}

pub struct MockSessionManager;
impl pallet_session::SessionManager<u64> for MockSessionManager {
    fn end_session(_: sp_staking::SessionIndex) {}

    fn start_session(_: sp_staking::SessionIndex) {}

    fn new_session(idx: sp_staking::SessionIndex) -> Option<Vec<u64>> {
        let validators;
        if idx == 0 {
            validators = vec![1, 2]
        } else if idx == 1 {
            validators = vec![2, 1]
        } else if idx == 2 {
            validators = vec![1, 3]
        } else if idx == 3 {
            validators = vec![1]
        } else if idx == 4 {
            validators = vec![3, 4]
        } else if idx == 5 {
            validators = vec![1, 2, 3]
        } else if idx == 6 {
            validators = vec![1, 2, 3, 4, 5]
        } else {
            validators = vec![]
        }
        let _ = Staking::new_session_handler(&validators);
        Some(validators)
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

    fn on_new_session<'a, I: 'a>(_changed: bool, _validators: I, _queued_validators: I)
    where
        I: Iterator<Item = (&'a AccountId, Self::Key)>,
        AccountId: 'a,
    {
        // let authorities = validators.map(|(_account, k)| (k, 1)).collect::<Vec<_>>();
        // let next_authorities = queued_validators.map(|(_account, k)| (k, 1)).collect::<Vec<_>>();
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
impl onchain::Config for OnChainSeqPhragmen {
    type DataProvider = FrameStaking;
    type MaxWinners = ConstU32<100>;
    type Solver = SequentialPhragmen<AccountId, Perbill>;
    type System = Test;
    type TargetsBound = ConstU32<{ u32::MAX }>;
    type VotersBound = ConstU32<{ u32::MAX }>;
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
  pub const MaxNominatorRewardedPerValidator: u32 = 64;
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
  pub static MaxNominations: u32 = 16;
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
    type MaxNominations = MaxNominations;
    type MaxNominatorRewardedPerValidator = MaxNominatorRewardedPerValidator;
    type MaxUnlockingChunks = ConstU32<32>;
    type NextNewSession = Session;
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

pub struct TestShouldEndSession;
impl ShouldEndSession<u64> for TestShouldEndSession {
    fn should_end_session(now: u64) -> bool {
        let l = SESSION_LENGTH.with(|l| *l.borrow());
        now % l == 0
            || FORCE_SESSION_END.with(|l| {
                let r = *l.borrow();
                *l.borrow_mut() = false;
                r
            })
    }
}

impl pallet_session::Config for Test {
    type Keys = UintAuthorityId;
    type NextSessionRotation = pallet_session::PeriodicSessions<Period, Offset>;
    type RuntimeEvent = RuntimeEvent;
    type SessionHandler = (OtherSessionHandler,);
    type SessionManager = pallet_session::historical::NoteHistoricalRoot<Test, FrameStaking>;
    type ShouldEndSession = TestShouldEndSession;
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
    type MaxEndpointLength = MaxEndpointLength;
    type RuntimeEvent = RuntimeEvent;
    // type ValidatorId = AccountId;
    type WeightInfo = ();
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = system::GenesisConfig::<Test>::default().build_storage().unwrap();
    let pallet_balances = pallet_balances::GenesisConfig::<Test> {
        balances: vec![(1, 100), (2, 100), (3, 100), (4, 100)],
    };
    let pallet_staking_extension = pallet_staking_extension::GenesisConfig::<Test> {
        threshold_servers: vec![
            (5, ServerInfo { tss_account: 7, x25519_public_key: NULL_ARR, endpoint: vec![20] }),
            (6, ServerInfo { tss_account: 8, x25519_public_key: NULL_ARR, endpoint: vec![40] }),
        ],
        // Alice, Bob are represented by 1, 2 in the following tuples, respectively.
        signing_groups: vec![(0, vec![1]), (1, vec![2])],
        activate_proactive_refresh: false,
    };

    pallet_balances.assimilate_storage(&mut t).unwrap();
    pallet_staking_extension.assimilate_storage(&mut t).unwrap();

    t.into()
}

pub(crate) fn run_to_block(n: BlockNumber) {
    FrameStaking::on_finalize(System::block_number());
    for b in (System::block_number() + 1)..=n {
        System::set_block_number(b);
        Session::on_initialize(b);
        <FrameStaking as Hooks<u64>>::on_initialize(b);
        Timestamp::set_timestamp(System::block_number() * BLOCK_TIME + INIT_TIMESTAMP);
        if b != n {
            FrameStaking::on_finalize(System::block_number());
        }
    }
}

pub(crate) fn start_session(session_index: SessionIndex) {
    let end: u64 = if Offset::get().is_zero() {
        (session_index as u64) * Period::get()
    } else {
        Offset::get() + (session_index.saturating_sub(1) as u64) * Period::get()
    };
    run_to_block(end);
    // session must have progressed properly.
    // assert_eq!(
    //     Session::current_index(),
    //     session_index,
    //     "current session index = {}, expected = {}",
    //     Session::current_index(),
    //     session_index,
    // );
}

pub(crate) fn start_active_era(era_index: EraIndex) {
    start_session(era_index * <SessionsPerEra as Get<u32>>::get());
}
