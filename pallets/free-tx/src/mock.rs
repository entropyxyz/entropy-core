use core::convert::{TryFrom, TryInto};

use frame_election_provider_support::{onchain, SequentialPhragmen, VoteWeight};
use frame_support::{
  parameter_types,
  traits::{ConstU32, GenesisBuild, Get, Hooks, OneSessionHandler},
};
use frame_system as system;
use pallet_session::historical as pallet_session_historical;
use pallet_staking::StakerStatus;
use sp_core::H256;
use sp_runtime::{
  curve::PiecewiseLinear,
  testing::{Header, TestXt, UintAuthorityId},
  traits::{BlakeTwo256, ConvertInto, IdentityLookup, Zero},
  Perbill,
};
use sp_staking::{EraIndex, SessionIndex};
use sp_std::collections::btree_map::BTreeMap;

use crate as pallet_free_tx;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;
type BlockNumber = u64;

pub const INIT_TIMESTAMP: u64 = 30_000;
pub const BLOCK_TIME: u64 = 1000;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
  pub enum Test where
    Block = Block,
    NodeBlock = Block,
    UncheckedExtrinsic = UncheckedExtrinsic,
  {
    System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
    Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
    Timestamp: pallet_timestamp::{Pallet, Call, Storage, Inherent},
    Staking: pallet_staking_extension::{Pallet, Call, Storage, Event<T>, Config<T>},
    FrameStaking: pallet_staking::{Pallet, Call, Storage, Event<T>},
    Session: pallet_session::{Pallet, Call, Storage, Event, Config<T>},
    Historical: pallet_session_historical::{Pallet},
    BagsList: pallet_bags_list::{Pallet, Call, Storage, Event<T>},
    FreeTx: pallet_free_tx::{Pallet, Call, Storage, Event<T>},
  }
);
type AccountId = u64;
type Balance = u64;

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
  pub static ExistentialDeposit: Balance = 1;
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
  pub static Period: BlockNumber = 5;
  pub static Offset: BlockNumber = 0;
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
  pub static SessionsPerEra: SessionIndex = 3;
  pub const BondingDuration: EraIndex = 0;
  pub static SlashDeferDuration: EraIndex = 0;
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
  type Keys = SessionKeys;
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

impl pallet_free_tx::Config for Test {
  type Call = Call;
  type Event = Event;
  type WeightInfo = ();
}

// Build genesis storage according to the mock runtime.
// pub fn new_test_ext() -> sp_io::TestExternalities {
//   let mut t = system::GenesisConfig::default().build_storage::<Test>().unwrap();
//   let pallet_balances = pallet_balances::GenesisConfig::<Test> {
//     balances: vec![(1, 100), (2, 100), (3, 100), (4, 100)],
//   };
//   let pallet_staking_extension = pallet_staking_extension::GenesisConfig::<Test> {
//     endpoints:          vec![(5, vec![20]), (6, vec![40])],
//     threshold_accounts: vec![(5, 7), (6, 8)],
//   };

//   pallet_balances.assimilate_storage(&mut t).unwrap();
//   pallet_staking_extension.assimilate_storage(&mut t).unwrap();

//   let _ = pallet_session::GenesisConfig::<Test> {
//     keys: if self.has_stakers {
//       // set the keys for the first session.
//       stakers.into_iter().map(|(id, ..)| (id, id, SessionKeys { other: id.into() })).collect()
//     } else {
//       // set some dummy validators in genesis.
//       (0..self.validator_count as u64)
//         .map(|id| (id, id, SessionKeys { other: id.into() }))
//         .collect()
//     },
//   }
//   .assimilate_storage(&mut t);

//   let mut externalities: sp_io::TestExternalities = t.into();

//   externalities.execute_with(|| {
//     System::set_block_number(1);
//     Session::on_initialize(1);
//     <FrameStaking as Hooks<u64>>::on_initialize(1);
//     Timestamp::set_timestamp(INIT_TIMESTAMP);
//   });

//   externalities
// }

pub struct ExtBuilder {
  nominate:                 bool,
  validator_count:          u32,
  minimum_validator_count:  u32,
  invulnerables:            Vec<AccountId>,
  has_stakers:              bool,
  initialize_first_session: bool,
  pub min_nominator_bond:   Balance,
  min_validator_bond:       Balance,
  balance_factor:           Balance,
  status:                   BTreeMap<AccountId, StakerStatus<AccountId>>,
  stakes:                   BTreeMap<AccountId, Balance>,
  stakers:                  Vec<(AccountId, AccountId, Balance, StakerStatus<AccountId>)>,
}

impl Default for ExtBuilder {
  fn default() -> Self {
    Self {
      nominate:                 true,
      validator_count:          2,
      minimum_validator_count:  0,
      balance_factor:           1,
      invulnerables:            vec![],
      has_stakers:              true,
      initialize_first_session: true,
      min_nominator_bond:       ExistentialDeposit::get(),
      min_validator_bond:       ExistentialDeposit::get(),
      status:                   Default::default(),
      stakes:                   Default::default(),
      stakers:                  Default::default(),
    }
  }
}

impl ExtBuilder {
  pub fn existential_deposit(self, existential_deposit: Balance) -> Self {
    EXISTENTIAL_DEPOSIT.with(|v| *v.borrow_mut() = existential_deposit);
    self
  }

  pub fn nominate(mut self, nominate: bool) -> Self {
    self.nominate = nominate;
    self
  }

  pub fn validator_count(mut self, count: u32) -> Self {
    self.validator_count = count;
    self
  }

  pub fn minimum_validator_count(mut self, count: u32) -> Self {
    self.minimum_validator_count = count;
    self
  }

  pub fn slash_defer_duration(self, eras: EraIndex) -> Self {
    SLASH_DEFER_DURATION.with(|v| *v.borrow_mut() = eras);
    self
  }

  pub fn invulnerables(mut self, invulnerables: Vec<AccountId>) -> Self {
    self.invulnerables = invulnerables;
    self
  }

  pub fn session_per_era(self, length: SessionIndex) -> Self {
    SESSIONS_PER_ERA.with(|v| *v.borrow_mut() = length);
    self
  }

  pub fn period(self, length: BlockNumber) -> Self {
    PERIOD.with(|v| *v.borrow_mut() = length);
    self
  }

  pub fn has_stakers(mut self, has: bool) -> Self {
    self.has_stakers = has;
    self
  }

  pub fn initialize_first_session(mut self, init: bool) -> Self {
    self.initialize_first_session = init;
    self
  }

  pub fn offset(self, offset: BlockNumber) -> Self {
    OFFSET.with(|v| *v.borrow_mut() = offset);
    self
  }

  pub fn min_nominator_bond(mut self, amount: Balance) -> Self {
    self.min_nominator_bond = amount;
    self
  }

  pub fn min_validator_bond(mut self, amount: Balance) -> Self {
    self.min_validator_bond = amount;
    self
  }

  pub fn set_status(mut self, who: AccountId, status: StakerStatus<AccountId>) -> Self {
    self.status.insert(who, status);
    self
  }

  pub fn set_stake(mut self, who: AccountId, stake: Balance) -> Self {
    self.stakes.insert(who, stake);
    self
  }

  pub fn add_staker(
    mut self,
    stash: AccountId,
    ctrl: AccountId,
    stake: Balance,
    status: StakerStatus<AccountId>,
  ) -> Self {
    self.stakers.push((stash, ctrl, stake, status));
    self
  }

  pub fn balance_factor(mut self, factor: Balance) -> Self {
    self.balance_factor = factor;
    self
  }

  fn build(self) -> sp_io::TestExternalities {
    sp_tracing::try_init_simple();
    let mut storage = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();

    let _ = pallet_balances::GenesisConfig::<Test> {
      balances: vec![
        (1, 10 * self.balance_factor),
        (2, 20 * self.balance_factor),
        (3, 300 * self.balance_factor),
        (4, 400 * self.balance_factor),
        // controllers
        (10, self.balance_factor),
        (20, self.balance_factor),
        (30, self.balance_factor),
        (40, self.balance_factor),
        (50, self.balance_factor),
        // stashes
        (11, self.balance_factor * 1000),
        (21, self.balance_factor * 2000),
        (31, self.balance_factor * 2000),
        (41, self.balance_factor * 2000),
        (51, self.balance_factor * 2000),
        // optional nominator
        (100, self.balance_factor * 2000),
        (101, self.balance_factor * 2000),
        // aux accounts
        (60, self.balance_factor),
        (61, self.balance_factor * 2000),
        (70, self.balance_factor),
        (71, self.balance_factor * 2000),
        (80, self.balance_factor),
        (81, self.balance_factor * 2000),
        // This allows us to have a total_payout different from 0.
        (999, 1_000_000_000_000),
      ],
    }
    .assimilate_storage(&mut storage);

    let mut stakers = vec![];
    if self.has_stakers {
      stakers = vec![
        // (stash, ctrl, stake, status)
        // these two will be elected in the default test where we elect 2.
        (11, 10, self.balance_factor * 1000, StakerStatus::<AccountId>::Validator),
        (21, 20, self.balance_factor * 1000, StakerStatus::<AccountId>::Validator),
        // a loser validator
        (31, 30, self.balance_factor * 500, StakerStatus::<AccountId>::Validator),
        // an idle validator
        (41, 40, self.balance_factor * 1000, StakerStatus::<AccountId>::Idle),
      ];
      // optionally add a nominator
      if self.nominate {
        stakers.push((
          101,
          100,
          self.balance_factor * 500,
          StakerStatus::<AccountId>::Nominator(vec![11, 21]),
        ))
      }
      // replace any of the status if needed.
      self.status.into_iter().for_each(|(stash, status)| {
        let (_, _, _, ref mut prev_status) =
          stakers.iter_mut().find(|s| s.0 == stash).expect("set_status staker should exist; qed");
        *prev_status = status;
      });
      // replaced any of the stakes if needed.
      self.stakes.into_iter().for_each(|(stash, stake)| {
        let (_, _, ref mut prev_stake, _) =
          stakers.iter_mut().find(|s| s.0 == stash).expect("set_stake staker should exits; qed.");
        *prev_stake = stake;
      });
      // extend stakers if needed.
      stakers.extend(self.stakers)
    }

    let _ = pallet_staking::GenesisConfig::<Test> {
      stakers: stakers.clone(),
      validator_count: self.validator_count,
      minimum_validator_count: self.minimum_validator_count,
      invulnerables: self.invulnerables,
      slash_reward_fraction: Perbill::from_percent(10),
      min_nominator_bond: self.min_nominator_bond,
      min_validator_bond: self.min_validator_bond,
      ..Default::default()
    }
    .assimilate_storage(&mut storage);

    let _ = pallet_session::GenesisConfig::<Test> {
      keys: if self.has_stakers {
        // set the keys for the first session.
        stakers.into_iter().map(|(id, ..)| (id, id, SessionKeys { other: id.into() })).collect()
      } else {
        // set some dummy validators in genesis.
        (0..self.validator_count as u64)
          .map(|id| (id, id, SessionKeys { other: id.into() }))
          .collect()
      },
    }
    .assimilate_storage(&mut storage);

    let mut ext = sp_io::TestExternalities::from(storage);

    if self.initialize_first_session {
      // We consider all test to start after timestamp is initialized This must be ensured by
      // having `timestamp::on_initialize` called before `staking::on_initialize`. Also, if
      // session length is 1, then it is already triggered.
      ext.execute_with(|| {
        System::set_block_number(1);
        Session::on_initialize(1);
        <Staking as Hooks<u64>>::on_initialize(1);
        Timestamp::set_timestamp(INIT_TIMESTAMP);
      });
    }

    ext
  }

  pub fn build_and_execute(self, test: impl FnOnce() -> ()) {
    sp_tracing::try_init_simple();
    let mut ext = self.build();
    ext.execute_with(test);
    // ext.execute_with(post_conditions);
  }
}

pub(crate) fn run_to_block(n: BlockNumber) {
  // JH current_era is not getting set somehwere  in here
  // print the system block number
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
  assert_eq!(
    Session::current_index(),
    session_index,
    "current session index = {}, expected = {}",
    Session::current_index(),
    session_index,
  );
}

pub(crate) fn active_era() -> EraIndex { FrameStaking::active_era().unwrap().index }

pub(crate) fn current_era() -> EraIndex { FrameStaking::current_era().unwrap() }

/// Progress until the given era.
pub(crate) fn start_active_era(era_index: EraIndex) {
  start_session((era_index * <SessionsPerEra as Get<u32>>::get()).into());
  assert_eq!(active_era(), era_index);
  // One way or another, current_era must have changed before the active era, so they must match
  // at this point.
  assert_eq!(current_era(), active_era());
}

// Build genesis storage according to the mock runtime.
// pub fn new_test_ext() -> sp_io::TestExternalities {
//   system::GenesisConfig::default().build_storage::<Test>().unwrap().into()
// }

pub type SystemCall = frame_system::Call<Test>;

// // Build genesis storage according to the mock runtime.
// pub fn new_test_ext() -> sp_io::TestExternalities {
//   let mut t = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();
//   pallet_balances::GenesisConfig::<Test> {
//     balances: vec![(1, 10), (2, 10), (3, 10), (4, 10), (5, 2)],
//   }
//   .assimilate_storage(&mut t)
//   .unwrap();

//   let mut ext = sp_io::TestExternalities::new(t);
//   ext.execute_with(|| System::set_block_number(1));
//   ext
// }
