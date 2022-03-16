use crate as pallet_propagation;
use frame_election_provider_support::onchain;
use frame_support::{
	parameter_types,
	traits::{ConstU32, FindAuthor, OneSessionHandler},
};
use frame_system as system;
use pallet_session::historical as pallet_session_historical;
use pallet_staking::{EraIndex, SessionInterface};
use sp_core::H256;
use sp_runtime::{
	curve::PiecewiseLinear,
	testing::{Header, TestXt, UintAuthorityId},
	traits::{BlakeTwo256, ConvertInto, IdentityLookup},
	Perbill,
};
use sp_staking::SessionIndex;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;
type BlockNumber = u64;

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
		FrameStaking: pallet_staking::{Pallet, Call, Storage, Event<T>},
		Staking: pallet_staking_extension::{Pallet, Call, Storage, Event<T>},
		Propagation: pallet_propagation::{Pallet, Call, Storage, Event<T>},
		Session: pallet_session::{Pallet, Call, Storage, Event, Config<T>},
		Historical: pallet_session_historical::{Pallet},
	}
);

type Balance = u64;
type AccountId = u64;

parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub const SS58Prefix: u8 = 42;
}

impl system::Config for Test {
	type BaseCallFilter = frame_support::traits::Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type DbWeight = ();
	type Origin = Origin;
	type Call = Call;
	type Index = u64;
	type BlockNumber = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = u64;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type Event = Event;
	type BlockHashCount = BlockHashCount;
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = pallet_balances::AccountData<Balance>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = SS58Prefix;
	type OnSetCode = ();
	type MaxConsumers = frame_support::traits::ConstU32<16>;
}

parameter_types! {
	pub const ExistentialDeposit: Balance = 10;
	pub const MaxLocks: u32 = 5;
}
impl pallet_balances::Config for Test {
	type MaxLocks = MaxLocks;
	type MaxReserves = ();
	type ReserveIdentifier = [u8; 8];
	type Balance = Balance;
	type Event = Event;
	type DustRemoval = ();
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type WeightInfo = ();
}

parameter_types! {
	pub const UncleGenerations: u64 = 0;
}

/// Author of block is always 11
pub struct Author11;
impl FindAuthor<u64> for Author11 {
	fn find_author<'a, I>(_digests: I) -> Option<u64>
	where
		I: 'a + IntoIterator<Item = (frame_support::ConsensusEngineId, &'a [u8])>,
	{
		Some(11)
	}
}

impl pallet_authorship::Config for Test {
	type FindAuthor = Author11;
	type UncleGenerations = UncleGenerations;
	type FilterUncle = ();
	type EventHandler = ();
}

impl onchain::Config for Test {
	type Accuracy = Perbill;
	type DataProvider = FrameStaking;
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
	Call: From<C>,
{
	type OverarchingCall = Call;
	type Extrinsic = TestXt<Call, ()>;
}

parameter_types! {
	pub const MinimumPeriod: u64 = 3;
}

impl pallet_timestamp::Config for Test {
	type Moment = u64;
	type OnTimestampSet = ();
	type MinimumPeriod = MinimumPeriod;
	type WeightInfo = ();
}

parameter_types! {
	pub const MaxEndpointLength: u32 = 3;
}
impl pallet_staking_extension::Config for Test {
	type Event = Event;
	type Currency = Balances;
	type MaxEndpointLength = MaxEndpointLength;
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

parameter_types! {
	pub const Period: BlockNumber = 5;
	pub const Offset: BlockNumber = 0;
}

sp_runtime::impl_opaque_keys! {
	pub struct SessionKeys {
		pub other: OtherSessionHandler,
	}
}

pub struct StakingBenchmarkingConfig;
impl pallet_staking::BenchmarkingConfig for StakingBenchmarkingConfig {
	type MaxNominators = ConstU32<1000>;
	type MaxValidators = ConstU32<1000>;
}

impl pallet_staking::Config for Test {
	const MAX_NOMINATIONS: u32 = 16;
	type RewardRemainder = ();
	type CurrencyToVote = frame_support::traits::SaturatingCurrencyToVote;
	type Event = Event;
	type Currency = Balances;
	type Slash = ();
	type Reward = ();
	type SessionsPerEra = SessionsPerEra;
	type BondingDuration = BondingDuration;
	type SlashDeferDuration = SlashDeferDuration;
	type SlashCancelOrigin = frame_system::EnsureRoot<Self::AccountId>;
	type SessionInterface = Self;
	type UnixTime = pallet_timestamp::Pallet<Test>;
	type EraPayout = pallet_staking::ConvertCurve<RewardCurve>;
	type MaxNominatorRewardedPerValidator = MaxNominatorRewardedPerValidator;
	type OffendingValidatorsThreshold = OffendingValidatorsThreshold;
	type NextNewSession = ();
	type ElectionProvider = onchain::OnChainSequentialPhragmen<Self>;
	type GenesisElectionProvider = Self::ElectionProvider;
	type SortedListProvider = pallet_staking::UseNominatorsMap<Self>;
	type BenchmarkingConfig = StakingBenchmarkingConfig;
	type WeightInfo = ();
}

impl pallet_session::Config for Test {
	type SessionManager = pallet_session::historical::NoteHistoricalRoot<Test, FrameStaking>;
	type Keys = UintAuthorityId;
	type ShouldEndSession = pallet_session::PeriodicSessions<Period, Offset>;
	type SessionHandler = (OtherSessionHandler,);
	type Event = Event;
	type ValidatorId = AccountId;
	type ValidatorIdOf = ConvertInto;
	type NextSessionRotation = pallet_session::PeriodicSessions<Period, Offset>;
	type WeightInfo = ();
}

impl pallet_session::historical::Config for Test {
	type FullIdentification = pallet_staking::Exposure<AccountId, Balance>;
	type FullIdentificationOf = pallet_staking::ExposureOf<Test>;
}

parameter_types! {
	pub const PruneBlock: u64 = 2;
}

impl pallet_relayer::Config for Test {
	type Event = Event;
	type PruneBlock = PruneBlock;
}

impl pallet_propagation::Config for Test {
	type Event = Event;
	type AuthorityId = pallet_babe::AuthorityId;
}
