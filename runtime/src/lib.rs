// This file is part of Substrate.

// Copyright (C) 2018-2021 Parity Technologies (UK) Ltd.
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

//! The Substrate runtime. This can be compiled with `#[no_std]`, ready for Wasm.

#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]
#![allow(unused_imports)]

use codec::{Decode, Encode, MaxEncodedLen};
use entropy_shared::SIGNING_PARTY_SIZE;
use frame_election_provider_support::{
    onchain, BalancingConfig, ElectionDataProvider, ExtendedBalance, SequentialPhragmen, VoteWeight,
};
use frame_support::{
    construct_runtime,
    dispatch::DispatchClass,
    pallet_prelude::Get,
    parameter_types,
    traits::{
        ConstU16, ConstU32, Contains, Currency, EitherOfDiverse, EqualPrivilegeOnly, Imbalance,
        InstanceFilter, KeyOwnerProofSystem, LockIdentifier, OnUnbalanced, U128CurrencyToVote,
        WithdrawReasons,
    },
    weights::{
        constants::{BlockExecutionWeight, ExtrinsicBaseWeight, RocksDbWeight, WEIGHT_PER_SECOND},
        IdentityFee, Weight,
    },
    PalletId, RuntimeDebug,
};
#[cfg(any(feature = "std", test))]
pub use frame_system::Call as SystemCall;
use frame_system::{
    limits::{BlockLength, BlockWeights},
    EnsureRoot,
};
pub use node_primitives::{AccountId, Signature};
use node_primitives::{AccountIndex, Balance, BlockNumber, Hash, Index, Moment};
#[cfg(any(feature = "std", test))]
pub use pallet_balances::Call as BalancesCall;
use pallet_election_provider_multi_phase::SolutionAccuracyOf;
use pallet_grandpa::{
    fg_primitives, AuthorityId as GrandpaId, AuthorityList as GrandpaAuthorityList,
};
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use pallet_session::historical as pallet_session_historical;
#[cfg(any(feature = "std", test))]
pub use pallet_staking::StakerStatus;
pub use pallet_transaction_payment::{CurrencyAdapter, Multiplier, TargetedFeeAdjustment};
use pallet_transaction_payment::{FeeDetails, RuntimeDispatchInfo};
use sp_api::impl_runtime_apis;
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
pub use sp_consensus_babe::AuthorityId as BabeId;
use sp_core::{crypto::KeyTypeId, OpaqueMetadata};
use sp_inherents::{CheckInherentsResult, InherentData};
#[cfg(any(feature = "std", test))]
pub use sp_runtime::BuildStorage;
use sp_runtime::{
    create_runtime_str,
    curve::PiecewiseLinear,
    generic, impl_opaque_keys,
    traits::{
        self, BlakeTwo256, Block as BlockT, Bounded, ConvertInto, NumberFor, OpaqueKeys,
        SaturatedConversion, StaticLookup,
    },
    transaction_validity::{TransactionPriority, TransactionSource, TransactionValidity},
    ApplyExtrinsicResult, FixedPointNumber, FixedU128, Perbill, Percent, Permill, Perquintill,
};
use sp_std::prelude::*;
#[cfg(any(feature = "std", test))]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;
use static_assertions::const_assert;
/// Implementations of some helper traits passed into runtime modules as associated types.
pub mod impls;
use impls::Author;
mod voter_bags;
mod weights;

/// Constant valus used within the runtime.
pub mod constants;
use constants::{currency::*, time::*};
use sp_runtime::generic::Era;

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

/// Wasm binary unwrapped. If built with `SKIP_WASM_BUILD`, the function panics.
#[cfg(feature = "std")]
pub fn wasm_binary_unwrap() -> &'static [u8] {
    WASM_BINARY.expect(
        "Development wasm binary is not available. This means the client is built with \
         `SKIP_WASM_BUILD` flag and it is only usable for production chains. Please rebuild with \
         the flag disabled.",
    )
}

/// Runtime version.
#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("node"),
    impl_name: create_runtime_str!("substrate-node"),
    authoring_version: 10,
    // Per convention: if the runtime behavior changes, increment spec_version
    // and set impl_version to 0. If only runtime
    // implementation changes and behavior does not, then leave spec_version as
    // is and increment impl_version.
    spec_version: 267,
    impl_version: 1,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 2,
    state_version: 1,
};

/// The BABE epoch configuration at genesis.
pub const BABE_GENESIS_EPOCH_CONFIG: sp_consensus_babe::BabeEpochConfiguration =
    sp_consensus_babe::BabeEpochConfiguration {
        c: PRIMARY_PROBABILITY,
        allowed_slots: sp_consensus_babe::AllowedSlots::PrimaryAndSecondaryPlainSlots,
    };

/// Native version.
#[cfg(any(feature = "std", test))]
pub fn native_version() -> NativeVersion {
    NativeVersion { runtime_version: VERSION, can_author_with: Default::default() }
}

type NegativeImbalance = <Balances as Currency<AccountId>>::NegativeImbalance;

pub struct DealWithFees;
impl OnUnbalanced<NegativeImbalance> for DealWithFees {
    fn on_unbalanceds<B>(mut fees_then_tips: impl Iterator<Item = NegativeImbalance>) {
        if let Some(fees) = fees_then_tips.next() {
            // for fees, 80% to treasury, 20% to author
            let mut split = fees.ration(80, 20);
            if let Some(tips) = fees_then_tips.next() {
                // for tips, if any, 80% to treasury, 20% to author (though this can be anything)
                tips.ration_merge_into(80, 20, &mut split);
            }
            Treasury::on_unbalanced(split.0);
            Author::on_unbalanced(split.1);
        }
    }
}

/// We assume that ~10% of the block weight is consumed by `on_initialize` handlers.
/// This is used to limit the maximal weight of a single extrinsic.
const AVERAGE_ON_INITIALIZE_RATIO: Perbill = Perbill::from_percent(10);
/// We allow `Normal` extrinsics to fill up the block up to 75%, the rest can be used
/// by  Operational  extrinsics.
const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);
/// We allow for 2 seconds of compute with a 6 second average block time.
const MAXIMUM_BLOCK_WEIGHT: Weight = WEIGHT_PER_SECOND.saturating_mul(2).set_proof_size(u64::MAX);

pub const EXISTENTIAL_DEPOSIT: Balance = DOLLARS;

parameter_types! {
  pub const BlockHashCount: BlockNumber = 2400;
  pub const Version: RuntimeVersion = VERSION;
  pub RuntimeBlockLength: BlockLength =
    BlockLength::max_with_normal_ratio(5 * 1024 * 1024, NORMAL_DISPATCH_RATIO);
  pub RuntimeBlockWeights: BlockWeights = BlockWeights::builder()
    .base_block(BlockExecutionWeight::get())
    .for_class(DispatchClass::all(), |weights| {
      weights.base_extrinsic = ExtrinsicBaseWeight::get();
    })
    .for_class(DispatchClass::Normal, |weights| {
      weights.max_total = Some(NORMAL_DISPATCH_RATIO * MAXIMUM_BLOCK_WEIGHT);
    })
    .for_class(DispatchClass::Operational, |weights| {
      weights.max_total = Some(MAXIMUM_BLOCK_WEIGHT);
      // Operational transactions have some extra reserved space, so that they
      // are included even if block reached `MAXIMUM_BLOCK_WEIGHT`.
      weights.reserved = Some(
        MAXIMUM_BLOCK_WEIGHT - NORMAL_DISPATCH_RATIO * MAXIMUM_BLOCK_WEIGHT
      );
    })
    .avg_block_initialization(AVERAGE_ON_INITIALIZE_RATIO)
    .build_or_panic();
  pub const SS58Prefix: u16 = 42;
}

const_assert!(NORMAL_DISPATCH_RATIO.deconstruct() >= AVERAGE_ON_INITIALIZE_RATIO.deconstruct());

pub struct BaseCallFilter;
impl Contains<RuntimeCall> for BaseCallFilter {
    fn contains(call: &RuntimeCall) -> bool {
        let is_core_call = matches!(call, RuntimeCall::System(_) | RuntimeCall::Timestamp(_));
        if is_core_call {
            // always allow core call
            return true;
        }

        let is_paused =
            pallet_transaction_pause::PausedTransactionFilter::<Runtime>::contains(call);
        let system_reject = matches!(
            call,
            RuntimeCall::Staking(pallet_staking::Call::withdraw_unbonded { .. })
                | RuntimeCall::Staking(pallet_staking::Call::validate { .. })
        );
        if is_paused || system_reject {
            // no paused call
            return false;
        }
        true
    }
}

impl frame_system::Config for Runtime {
    type AccountData = pallet_balances::AccountData<Balance>;
    type AccountId = AccountId;
    type BaseCallFilter = BaseCallFilter;
    type BlockHashCount = BlockHashCount;
    type BlockLength = RuntimeBlockLength;
    type BlockNumber = BlockNumber;
    type BlockWeights = RuntimeBlockWeights;
    type DbWeight = RocksDbWeight;
    type Hash = Hash;
    type Hashing = BlakeTwo256;
    type Header = generic::Header<BlockNumber, BlakeTwo256>;
    type Index = Index;
    type Lookup = Indices;
    type MaxConsumers = frame_support::traits::ConstU32<16>;
    type OnKilledAccount = ();
    type OnNewAccount = ();
    type OnSetCode = ();
    type PalletInfo = PalletInfo;
    type RuntimeCall = RuntimeCall;
    type RuntimeEvent = RuntimeEvent;
    type RuntimeOrigin = RuntimeOrigin;
    type SS58Prefix = SS58Prefix;
    type SystemWeightInfo = frame_system::weights::SubstrateWeight<Runtime>;
    type Version = Version;
}

impl pallet_randomness_collective_flip::Config for Runtime {}

impl pallet_utility::Config for Runtime {
    type PalletsOrigin = OriginCaller;
    type RuntimeCall = RuntimeCall;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_utility::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
  // One storage item; key size is 32; value is size 4+4+16+32 bytes = 56 bytes.
  pub const DepositBase: Balance = deposit(1, 88);
  // Additional storage item size of 32 bytes.
  pub const DepositFactor: Balance = deposit(0, 32);
  pub const MaxSignatories: u16 = 100;
}

impl pallet_multisig::Config for Runtime {
    type Currency = Balances;
    type DepositBase = DepositBase;
    type DepositFactor = DepositFactor;
    type MaxSignatories = MaxSignatories;
    type RuntimeCall = RuntimeCall;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_multisig::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
  // One storage item; key size 32, value size 8; .
  pub const ProxyDepositBase: Balance = deposit(1, 8);
  // Additional storage item size of 33 bytes.
  pub const ProxyDepositFactor: Balance = deposit(0, 33);
  pub const MaxProxies: u16 = 32;
  pub const AnnouncementDepositBase: Balance = deposit(1, 8);
  pub const AnnouncementDepositFactor: Balance = deposit(0, 66);
  pub const MaxPending: u16 = 32;
}

/// The type used to represent the kinds of proxying allowed.
#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Encode,
    Decode,
    RuntimeDebug,
    MaxEncodedLen,
    scale_info::TypeInfo,
)]
pub enum ProxyType {
    Any,
    NonTransfer,
    Governance,
    Staking,
}
impl Default for ProxyType {
    fn default() -> Self { Self::Any }
}
impl InstanceFilter<RuntimeCall> for ProxyType {
    fn filter(&self, c: &RuntimeCall) -> bool {
        match self {
            ProxyType::Any => true,
            ProxyType::NonTransfer => !matches!(
                c,
                RuntimeCall::Balances(..)
                    | RuntimeCall::Vesting(pallet_vesting::Call::vested_transfer { .. })
                    | RuntimeCall::Indices(pallet_indices::Call::transfer { .. })
            ),
            ProxyType::Governance => matches!(
                c,
                RuntimeCall::Democracy(..)
                    | RuntimeCall::Council(..)
                    | RuntimeCall::Society(..)
                    | RuntimeCall::TechnicalCommittee(..)
                    | RuntimeCall::Elections(..)
                    | RuntimeCall::Treasury(..)
            ),
            ProxyType::Staking => matches!(c, RuntimeCall::Staking(..)),
        }
    }

    fn is_superset(&self, o: &Self) -> bool {
        match (self, o) {
            (x, y) if x == y => true,
            (ProxyType::Any, _) => true,
            (_, ProxyType::Any) => false,
            (ProxyType::NonTransfer, _) => true,
            _ => false,
        }
    }
}

impl pallet_proxy::Config for Runtime {
    type AnnouncementDepositBase = AnnouncementDepositBase;
    type AnnouncementDepositFactor = AnnouncementDepositFactor;
    type CallHasher = BlakeTwo256;
    type Currency = Balances;
    type MaxPending = MaxPending;
    type MaxProxies = MaxProxies;
    type ProxyDepositBase = ProxyDepositBase;
    type ProxyDepositFactor = ProxyDepositFactor;
    type ProxyType = ProxyType;
    type RuntimeCall = RuntimeCall;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_proxy::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
  // NOTE: Currently it is not possible to change the epoch duration after the chain has started.
  //       Attempting to do so will brick block production.
  pub const EpochDuration: u64 = EPOCH_DURATION_IN_SLOTS;
  pub const ExpectedBlockTime: Moment = MILLISECS_PER_BLOCK;
  pub const ReportLongevity: u64 =
    BondingDuration::get() as u64 * SessionsPerEra::get() as u64 * EpochDuration::get();
}

impl pallet_babe::Config for Runtime {
    type DisabledValidators = Session;
    type EpochChangeTrigger = pallet_babe::ExternalTrigger;
    type EpochDuration = EpochDuration;
    type ExpectedBlockTime = ExpectedBlockTime;
    type HandleEquivocation =
        pallet_babe::EquivocationHandler<Self::KeyOwnerIdentification, Offences, ReportLongevity>;
    type KeyOwnerIdentification = <Self::KeyOwnerProofSystem as KeyOwnerProofSystem<(
        KeyTypeId,
        pallet_babe::AuthorityId,
    )>>::IdentificationTuple;
    type KeyOwnerProof = <Self::KeyOwnerProofSystem as KeyOwnerProofSystem<(
        KeyTypeId,
        pallet_babe::AuthorityId,
    )>>::Proof;
    type KeyOwnerProofSystem = Historical;
    type MaxAuthorities = MaxAuthorities;
    type WeightInfo = ();
}

parameter_types! {
  pub const IndexDeposit: Balance = DOLLARS;
}

impl pallet_indices::Config for Runtime {
    type AccountIndex = AccountIndex;
    type Currency = Balances;
    type Deposit = IndexDeposit;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_indices::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
  pub const ExistentialDeposit: Balance = EXISTENTIAL_DEPOSIT;
  // For weight estimation, we assume that the most locks on an individual account will be 50.
  // This number may need to be adjusted in the future if this assumption no longer holds true.
  pub const MaxLocks: u32 = 50;
  pub const MaxReserves: u32 = 50;
}

impl pallet_balances::Config for Runtime {
    type AccountStore = frame_system::Pallet<Runtime>;
    type Balance = Balance;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type MaxLocks = MaxLocks;
    type MaxReserves = MaxReserves;
    type ReserveIdentifier = [u8; 8];
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
  pub const TransactionByteFee: Balance = 10 * MILLICENTS;
  pub const OperationalFeeMultiplier: u8 = 5;
  pub const TargetBlockFullness: Perquintill = Perquintill::from_percent(25);
  pub AdjustmentVariable: Multiplier = Multiplier::saturating_from_rational(1, 100_000);
  pub MinimumMultiplier: Multiplier = Multiplier::saturating_from_rational(1, 1_000_000_000u128);
  pub MaximumMultiplier: Multiplier = Bounded::max_value();
}

impl pallet_transaction_payment::Config for Runtime {
    type FeeMultiplierUpdate = TargetedFeeAdjustment<
        Self,
        TargetBlockFullness,
        AdjustmentVariable,
        MinimumMultiplier,
        MaximumMultiplier,
    >;
    type LengthToFee = IdentityFee<Balance>;
    type OnChargeTransaction = CurrencyAdapter<Balances, DealWithFees>;
    type OperationalFeeMultiplier = OperationalFeeMultiplier;
    type RuntimeEvent = RuntimeEvent;
    type WeightToFee = IdentityFee<Balance>;
}

parameter_types! {
  pub const MinimumPeriod: Moment = SLOT_DURATION / 2;
}

impl pallet_timestamp::Config for Runtime {
    type MinimumPeriod = MinimumPeriod;
    type Moment = Moment;
    type OnTimestampSet = Babe;
    type WeightInfo = pallet_timestamp::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
  pub const UncleGenerations: BlockNumber = 5;
}

impl pallet_authorship::Config for Runtime {
    type EventHandler = (Staking, ImOnline);
    type FilterUncle = ();
    type FindAuthor = pallet_session::FindAccountFromAuthorIndex<Self, Babe>;
    type UncleGenerations = UncleGenerations;
}

impl_opaque_keys! {
  pub struct SessionKeys {
    pub grandpa: Grandpa,
    pub babe: Babe,
    pub im_online: ImOnline,
    pub authority_discovery: AuthorityDiscovery,
  }
}

impl pallet_session::Config for Runtime {
    type Keys = SessionKeys;
    type NextSessionRotation = Babe;
    type RuntimeEvent = RuntimeEvent;
    type SessionHandler = <SessionKeys as OpaqueKeys>::KeyTypeIdProviders;
    type SessionManager = pallet_staking_extension::SessionManager<
        pallet_session::historical::NoteHistoricalRoot<Self, Staking>,
        Runtime,
    >;
    type ShouldEndSession = Babe;
    type ValidatorId = <Self as frame_system::Config>::AccountId;
    type ValidatorIdOf = pallet_staking::StashOf<Self>;
    type WeightInfo = pallet_session::weights::SubstrateWeight<Runtime>;
}

impl pallet_session::historical::Config for Runtime {
    type FullIdentification = pallet_staking::Exposure<AccountId, Balance>;
    type FullIdentificationOf = pallet_staking::ExposureOf<Runtime>;
}

pallet_staking_reward_curve::build! {
  const REWARD_CURVE: PiecewiseLinear<'static> = curve!(
    min_inflation: 0_025_000,
    max_inflation: 0100_000,
    ideal_stake: 0_500_000,
    falloff: 0_050_000,
    max_piece_count: 40,
    test_precision: 0_005_000,
  );
}

parameter_types! {
  pub const SessionsPerEra: sp_staking::SessionIndex = 6;
  pub const BondingDuration: sp_staking::EraIndex = 24 * 28;
  pub const SlashDeferDuration: sp_staking::EraIndex = 24 * 7; // 1/4 the bonding duration.
  pub const RewardCurve: &'static PiecewiseLinear<'static> = &REWARD_CURVE;
  pub const MaxNominatorRewardedPerValidator: u32 = 256;
  pub const OffendingValidatorsThreshold: Perbill = Perbill::from_percent(17);
  pub OffchainRepeat: BlockNumber = 5;
  pub HistoryDepth: u32 = 84;
}

pub struct OnChainSeqPhragmen;
impl onchain::Config for OnChainSeqPhragmen {
    type DataProvider = <Runtime as pallet_election_provider_multi_phase::Config>::DataProvider;
    type Solver = SequentialPhragmen<
        AccountId,
        pallet_election_provider_multi_phase::SolutionAccuracyOf<Runtime>,
    >;
    type System = Runtime;
    type WeightInfo = frame_election_provider_support::weights::SubstrateWeight<Runtime>;
}

impl onchain::BoundedConfig for OnChainSeqPhragmen {
    type TargetsBound = ConstU32<2_000>;
    type VotersBound = ConstU32<20_000>;
}

impl pallet_election_provider_multi_phase::MinerConfig for Runtime {
    type AccountId = AccountId;
    type MaxLength = MinerMaxLength;
    type MaxVotesPerVoter =
	<<Self as pallet_election_provider_multi_phase::Config>::DataProvider as ElectionDataProvider>::MaxVotesPerVoter;
    type MaxWeight = MinerMaxWeight;
    type Solution = NposSolution16;

    // The unsigned submissions have to respect the weight of the submit_unsigned call, thus their
    // weight estimate function is wired to this call's weight.
    fn solution_weight(v: u32, t: u32, a: u32, d: u32) -> Weight {
        <
			<Self as pallet_election_provider_multi_phase::Config>::WeightInfo
			as
			pallet_election_provider_multi_phase::WeightInfo
		>::submit_unsigned(v, t, a, d)
    }
}

pub struct StakingBenchmarkingConfig;
impl pallet_staking::BenchmarkingConfig for StakingBenchmarkingConfig {
    type MaxNominators = ConstU32<1000>;
    type MaxValidators = ConstU32<1000>;
}

impl pallet_staking::Config for Runtime {
    type BenchmarkingConfig = StakingBenchmarkingConfig;
    type BondingDuration = BondingDuration;
    type Currency = Balances;
    type CurrencyBalance = Balance;
    type CurrencyToVote = U128CurrencyToVote;
    type ElectionProvider = ElectionProviderMultiPhase;
    type EraPayout = pallet_staking::ConvertCurve<RewardCurve>;
    type GenesisElectionProvider = onchain::UnboundedExecution<OnChainSeqPhragmen>;
    type HistoryDepth = HistoryDepth;
    type MaxNominations = MaxNominations;
    type MaxNominatorRewardedPerValidator = MaxNominatorRewardedPerValidator;
    type MaxUnlockingChunks = ConstU32<32>;
    type NextNewSession = Session;
    type OffendingValidatorsThreshold = OffendingValidatorsThreshold;
    type OnStakerSlash = ();
    // send the slashed funds to the treasury.
    type Reward = ();
    type RewardRemainder = Treasury;
    type RuntimeEvent = RuntimeEvent;
    type SessionInterface = Self;
    // rewards are minted from the void
    type SessionsPerEra = SessionsPerEra;
    type Slash = Treasury;
    /// A super-majority of the council can cancel the slash.
    type SlashCancelOrigin = EitherOfDiverse<
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 3, 4>,
    >;
    type SlashDeferDuration = SlashDeferDuration;
    type TargetList = pallet_staking::UseValidatorsMap<Self>;
    type UnixTime = Timestamp;
    type VoterList = BagsList;
    type WeightInfo = pallet_staking::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
  pub const MaxEndpointLength: u32 = 100;
}
impl pallet_staking_extension::Config for Runtime {
    type Currency = Balances;
    type MaxEndpointLength = MaxEndpointLength;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = weights::pallet_staking_extension::WeightInfo<Runtime>;
}

parameter_types! {
    // phase durations. 1/4 of the last session for each.
    pub const SignedPhase: u32 = EPOCH_DURATION_IN_BLOCKS / 4;
    pub const UnsignedPhase: u32 = EPOCH_DURATION_IN_BLOCKS / 4;

    // signed config
    pub const SignedRewardBase: Balance = DOLLARS;
    pub const SignedDepositBase: Balance = DOLLARS;
    pub const SignedDepositByte: Balance = CENTS;

    pub BetterUnsignedThreshold: Perbill = Perbill::from_rational(1u32, 10_000);

    // miner configs
    pub const MultiPhaseUnsignedPriority: TransactionPriority = StakingUnsignedPriority::get() - 1u64;
    pub MinerMaxWeight: Weight = RuntimeBlockWeights::get()
        .get(DispatchClass::Normal)
        .max_extrinsic.expect("Normal extrinsics have a weight limit configured; qed")
        .saturating_sub(BlockExecutionWeight::get());
    // Solution can occupy 90% of normal block size
    pub MinerMaxLength: u32 = Perbill::from_rational(9u32, 10) *
        *RuntimeBlockLength::get()
        .max
        .get(DispatchClass::Normal);
}

frame_election_provider_support::generate_solution_type!(
  #[compact]
  pub struct NposSolution16::<
    VoterIndex = u32,
    TargetIndex = u16,
    Accuracy = sp_runtime::PerU16,
    MaxVoters = MaxElectingVoters,
  >(16)
);

parameter_types! {
  pub MaxNominations: u32 = <NposSolution16 as frame_election_provider_support::NposSolution>::LIMIT as u32;
  pub MaxElectingVoters: u32 = 10_000;
}
/// The numbers configured here should always be more than the the maximum limits of staking pallet
/// to ensure election snapshot will not run out of memory.
pub struct BenchmarkConfig;
impl pallet_election_provider_multi_phase::BenchmarkingConfig for BenchmarkConfig {
    const ACTIVE_VOTERS: [u32; 2] = [1000, 4_000];
    const DESIRED_TARGETS: [u32; 2] = [400, 800];
    const MAXIMUM_TARGETS: u32 = 2000;
    const MINER_MAXIMUM_VOTERS: u32 = 15_000;
    const SNAPSHOT_MAXIMUM_VOTERS: u32 = 25_000;
    const TARGETS: [u32; 2] = [1_000, 2_000];
    const VOTERS: [u32; 2] = [5_000, 10_000];
}

/// Maximum number of iterations for balancing that will be executed in the embedded OCW
/// miner of election provider multi phase.
pub const MINER_MAX_ITERATIONS: u32 = 10;

/// A source of random balance for NposSolver, which is meant to be run by the OCW election miner.
pub struct OffchainRandomBalancing;
impl Get<Option<BalancingConfig>> for OffchainRandomBalancing {
    fn get() -> Option<BalancingConfig> {
        use sp_runtime::traits::TrailingZeroInput;
        let iterations = match MINER_MAX_ITERATIONS {
            0 => 0,
            max => {
                let seed = sp_io::offchain::random_seed();
                let random = <u32>::decode(&mut TrailingZeroInput::new(&seed))
                    .expect("input is padded with zeroes; qed")
                    % max.saturating_add(1);
                random as usize
            },
        };

        let config = BalancingConfig { iterations, tolerance: 0 };
        Some(config)
    }
}

impl pallet_election_provider_multi_phase::Config for Runtime {
    type BenchmarkingConfig = BenchmarkConfig;
    type BetterSignedThreshold = ();
    type BetterUnsignedThreshold = BetterUnsignedThreshold;
    type Currency = Balances;
    // nothing to do upon rewards
    type DataProvider = Staking;
    type EstimateCallFee = TransactionPayment;
    type Fallback = onchain::BoundedExecution<OnChainSeqPhragmen>;
    type ForceOrigin = EnsureRootOrHalfCouncil;
    type GovernanceFallback = onchain::BoundedExecution<OnChainSeqPhragmen>;
    type MaxElectableTargets = ConstU16<{ u16::MAX }>;
    type MaxElectingVoters = MaxElectingVoters;
    type MinerConfig = Self;
    type MinerTxPriority = MultiPhaseUnsignedPriority;
    type OffchainRepeat = OffchainRepeat;
    // burn slashes
    type RewardHandler = ();
    type RuntimeEvent = RuntimeEvent;
    type SignedDepositBase = SignedDepositBase;
    type SignedDepositByte = SignedDepositByte;
    type SignedDepositWeight = ();
    type SignedMaxRefunds = ConstU32<3>;
    type SignedMaxSubmissions = ConstU32<10>;
    type SignedMaxWeight = MinerMaxWeight;
    type SignedPhase = SignedPhase;
    type SignedRewardBase = SignedRewardBase;
    type SlashHandler = ();
    type Solver = SequentialPhragmen<AccountId, SolutionAccuracyOf<Self>, OffchainRandomBalancing>;
    type UnsignedPhase = UnsignedPhase;
    type WeightInfo = pallet_election_provider_multi_phase::weights::SubstrateWeight<Self>;
}

parameter_types! {
    pub const LaunchPeriod: BlockNumber = 28 * 24 * 60 * MINUTES;
    pub const VotingPeriod: BlockNumber = 28 * 24 * 60 * MINUTES;
    pub const FastTrackVotingPeriod: BlockNumber = 3 * 24 * 60 * MINUTES;
    pub const MinimumDeposit: Balance = 100 * DOLLARS;
    pub const EnactmentPeriod: BlockNumber = 30 * 24 * 60 * MINUTES;
    pub const CooloffPeriod: BlockNumber = 28 * 24 * 60 * MINUTES;
    pub const MaxProposals: u32 = 100;
}

impl pallet_democracy::Config for Runtime {
    type BlacklistOrigin = EnsureRoot<AccountId>;
    // To cancel a proposal before it has been passed, the technical committee must be unanimous or
    // Root must agree.
    type CancelProposalOrigin = EitherOfDiverse<
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<AccountId, TechnicalCollective, 1, 1>,
    >;
    // To cancel a proposal which has been passed, 2/3 of the council must agree to it.
    type CancellationOrigin =
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 2, 3>;
    type CooloffPeriod = CooloffPeriod;
    type Currency = Balances;
    type EnactmentPeriod = EnactmentPeriod;
    /// A unanimous council can have the next scheduled referendum be a straight default-carries
    /// (NTB) vote.
    type ExternalDefaultOrigin =
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 1, 1>;
    /// A super-majority can have the next scheduled referendum be a straight majority-carries vote.
    type ExternalMajorityOrigin =
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 3, 4>;
    /// A straight majority of the council can decide what their next motion is.
    type ExternalOrigin =
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 1, 2>;
    /// Two thirds of the technical committee can have an ExternalMajority/ExternalDefault vote
    /// be tabled immediately and with a shorter voting/enactment period.
    type FastTrackOrigin =
        pallet_collective::EnsureProportionAtLeast<AccountId, TechnicalCollective, 2, 3>;
    type FastTrackVotingPeriod = FastTrackVotingPeriod;
    type InstantAllowed = frame_support::traits::ConstBool<true>;
    type InstantOrigin =
        pallet_collective::EnsureProportionAtLeast<AccountId, TechnicalCollective, 1, 1>;
    type LaunchPeriod = LaunchPeriod;
    type MaxBlacklisted = ConstU32<100>;
    type MaxDeposits = ConstU32<100>;
    type MaxProposals = MaxProposals;
    type MaxVotes = ConstU32<100>;
    // Same as EnactmentPeriod
    type MinimumDeposit = MinimumDeposit;
    type PalletsOrigin = OriginCaller;
    type Preimages = Preimage;
    type RuntimeEvent = RuntimeEvent;
    type Scheduler = Scheduler;
    type Slash = Treasury;
    // Any single technical committee member may veto a coming council proposal, however they can
    // only do it once and it lasts only for the cool-off period.
    type VetoOrigin = pallet_collective::EnsureMember<AccountId, TechnicalCollective>;
    type VoteLockingPeriod = EnactmentPeriod;
    type VotingPeriod = VotingPeriod;
    type WeightInfo = pallet_democracy::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
  pub const CouncilMotionDuration: BlockNumber = 5 * DAYS;
  pub const CouncilMaxProposals: u32 = 100;
  pub const CouncilMaxMembers: u32 = 100;
}

type CouncilCollective = pallet_collective::Instance1;
impl pallet_collective::Config<CouncilCollective> for Runtime {
    type DefaultVote = pallet_collective::PrimeDefaultVote;
    type MaxMembers = CouncilMaxMembers;
    type MaxProposals = CouncilMaxProposals;
    type MotionDuration = CouncilMotionDuration;
    type Proposal = RuntimeCall;
    type RuntimeEvent = RuntimeEvent;
    type RuntimeOrigin = RuntimeOrigin;
    type WeightInfo = pallet_collective::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
  pub const CandidacyBond: Balance = 10 * DOLLARS;
  // 1 storage item created, key size is 32 bytes, value size is 16+16.
  pub const VotingBondBase: Balance = deposit(1, 64);
  // additional data per vote is 32 bytes (account id).
  pub const VotingBondFactor: Balance = deposit(0, 32);
  pub const TermDuration: BlockNumber = 7 * DAYS;
  pub const DesiredMembers: u32 = 13;
  pub const DesiredRunnersUp: u32 = 7;
  pub const ElectionsPhragmenPalletId: LockIdentifier = *b"phrelect";
  pub const MaxCandidates: u32 = 1000;
  pub const MaxVoters: u32 = 10 * 1000;
}

// Make sure that there are no more than `MaxMembers` members elected via elections-phragmen.
const_assert!(DesiredMembers::get() <= CouncilMaxMembers::get());

impl pallet_elections_phragmen::Config for Runtime {
    type CandidacyBond = CandidacyBond;
    type ChangeMembers = Council;
    type Currency = Balances;
    type CurrencyToVote = U128CurrencyToVote;
    type DesiredMembers = DesiredMembers;
    type DesiredRunnersUp = DesiredRunnersUp;
    // NOTE: this implies that council's genesis members cannot be set directly and must come from
    // this module.
    type InitializeMembers = Council;
    type KickedMember = ();
    type LoserCandidate = ();
    type MaxCandidates = MaxCandidates;
    type MaxVoters = MaxVoters;
    type PalletId = ElectionsPhragmenPalletId;
    type RuntimeEvent = RuntimeEvent;
    type TermDuration = TermDuration;
    type VotingBondBase = VotingBondBase;
    type VotingBondFactor = VotingBondFactor;
    type WeightInfo = pallet_elections_phragmen::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
  pub const TechnicalMotionDuration: BlockNumber = 5 * DAYS;
  pub const TechnicalMaxProposals: u32 = 100;
  pub const TechnicalMaxMembers: u32 = 100;
}

type TechnicalCollective = pallet_collective::Instance2;
impl pallet_collective::Config<TechnicalCollective> for Runtime {
    type DefaultVote = pallet_collective::PrimeDefaultVote;
    type MaxMembers = TechnicalMaxMembers;
    type MaxProposals = TechnicalMaxProposals;
    type MotionDuration = TechnicalMotionDuration;
    type Proposal = RuntimeCall;
    type RuntimeEvent = RuntimeEvent;
    type RuntimeOrigin = RuntimeOrigin;
    type WeightInfo = pallet_collective::weights::SubstrateWeight<Runtime>;
}

type EnsureRootOrHalfCouncil = EitherOfDiverse<
    EnsureRoot<AccountId>,
    pallet_collective::EnsureProportionMoreThan<AccountId, CouncilCollective, 1, 2>,
>;
impl pallet_membership::Config<pallet_membership::Instance1> for Runtime {
    type AddOrigin = EnsureRootOrHalfCouncil;
    type MaxMembers = TechnicalMaxMembers;
    type MembershipChanged = TechnicalCommittee;
    type MembershipInitialized = TechnicalCommittee;
    type PrimeOrigin = EnsureRootOrHalfCouncil;
    type RemoveOrigin = EnsureRootOrHalfCouncil;
    type ResetOrigin = EnsureRootOrHalfCouncil;
    type RuntimeEvent = RuntimeEvent;
    type SwapOrigin = EnsureRootOrHalfCouncil;
    type WeightInfo = pallet_membership::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
  pub const ProposalBond: Permill = Permill::from_percent(5);
  pub const ProposalBondMinimum: Balance = DOLLARS;
  pub const SpendPeriod: BlockNumber = DAYS;
  pub const Burn: Permill = Permill::from_percent(50);
  pub const TipCountdown: BlockNumber = DAYS;
  pub const TipFindersFee: Percent = Percent::from_percent(20);
  pub const TipReportDepositBase: Balance = DOLLARS;
  pub const DataDepositPerByte: Balance = CENTS;
  pub const BountyDepositBase: Balance = DOLLARS;
  pub const BountyDepositPayoutDelay: BlockNumber = DAYS;
  pub const TreasuryPalletId: PalletId = PalletId(*b"py/trsry");
  pub const BountyUpdatePeriod: BlockNumber = 14 * DAYS;
  pub const MaximumReasonLength: u32 = 16384;
  pub const BountyCuratorDeposit: Permill = Permill::from_percent(50);
  pub const BountyValueMinimum: Balance = 5 * DOLLARS;
  pub const MaxApprovals: u32 = 100;
  pub const CuratorDepositMultiplier: Permill = Permill::from_percent(50);
  pub const CuratorDepositMin: Balance = DOLLARS;
  pub const CuratorDepositMax: Balance = 100 * DOLLARS;
}

impl pallet_treasury::Config for Runtime {
    type ApproveOrigin = EitherOfDiverse<
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 3, 5>,
    >;
    type Burn = Burn;
    type BurnDestination = ();
    type Currency = Balances;
    type MaxApprovals = MaxApprovals;
    type OnSlash = ();
    type PalletId = TreasuryPalletId;
    type ProposalBond = ProposalBond;
    type ProposalBondMaximum = ();
    type ProposalBondMinimum = ProposalBondMinimum;
    type RejectOrigin = EitherOfDiverse<
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionMoreThan<AccountId, CouncilCollective, 1, 2>,
    >;
    type RuntimeEvent = RuntimeEvent;
    type SpendFunds = Bounties;
    type SpendOrigin = frame_support::traits::NeverEnsureOrigin<u128>;
    type SpendPeriod = SpendPeriod;
    type WeightInfo = pallet_treasury::weights::SubstrateWeight<Runtime>;
}

impl pallet_bounties::Config for Runtime {
    type BountyDepositBase = BountyDepositBase;
    type BountyDepositPayoutDelay = BountyDepositPayoutDelay;
    type BountyUpdatePeriod = BountyUpdatePeriod;
    type BountyValueMinimum = BountyValueMinimum;
    type ChildBountyManager = ();
    type CuratorDepositMax = CuratorDepositMax;
    type CuratorDepositMin = CuratorDepositMin;
    type CuratorDepositMultiplier = CuratorDepositMultiplier;
    type DataDepositPerByte = DataDepositPerByte;
    type MaximumReasonLength = MaximumReasonLength;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_bounties::weights::SubstrateWeight<Runtime>;
}

impl pallet_tips::Config for Runtime {
    type DataDepositPerByte = DataDepositPerByte;
    type MaximumReasonLength = MaximumReasonLength;
    type RuntimeEvent = RuntimeEvent;
    type TipCountdown = TipCountdown;
    type TipFindersFee = TipFindersFee;
    type TipReportDepositBase = TipReportDepositBase;
    type Tippers = Elections;
    type WeightInfo = pallet_tips::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub MaximumSchedulerWeight: Weight = Perbill::from_percent(80) *
        RuntimeBlockWeights::get().max_block;
}

impl pallet_scheduler::Config for Runtime {
    type MaxScheduledPerBlock = ConstU32<512>;
    type MaximumWeight = MaximumSchedulerWeight;
    type OriginPrivilegeCmp = EqualPrivilegeOnly;
    type PalletsOrigin = OriginCaller;
    type Preimages = Preimage;
    type RuntimeCall = RuntimeCall;
    type RuntimeEvent = RuntimeEvent;
    type RuntimeOrigin = RuntimeOrigin;
    type ScheduleOrigin = EnsureRoot<AccountId>;
    type WeightInfo = pallet_scheduler::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
  pub const PreimageMaxSize: u32 = 4096 * 1024;
  pub const PreimageBaseDeposit: Balance = DOLLARS;
  // One cent: $10,000 / MB
  pub const PreimageByteDeposit: Balance = CENTS;
}

impl pallet_preimage::Config for Runtime {
    type BaseDeposit = PreimageBaseDeposit;
    type ByteDeposit = PreimageByteDeposit;
    type Currency = Balances;
    type ManagerOrigin = EnsureRoot<AccountId>;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_preimage::weights::SubstrateWeight<Runtime>;
}

impl pallet_sudo::Config for Runtime {
    type RuntimeCall = RuntimeCall;
    type RuntimeEvent = RuntimeEvent;
}

parameter_types! {
  pub const ImOnlineUnsignedPriority: TransactionPriority = TransactionPriority::max_value();
  /// We prioritize im-online heartbeats over election solution submission.
  pub const StakingUnsignedPriority: TransactionPriority = TransactionPriority::max_value() / 2;
  pub const MaxAuthorities: u32 = 100;
  pub const MaxKeys: u32 = 10_000;
  pub const MaxPeerInHeartbeats: u32 = 10_000;
  pub const MaxPeerDataEncodingSize: u32 = 1_000;
}

impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Runtime
where RuntimeCall: From<LocalCall>
{
    fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
        call: RuntimeCall,
        public: <Signature as traits::Verify>::Signer,
        account: AccountId,
        nonce: Index,
    ) -> Option<(RuntimeCall, <UncheckedExtrinsic as traits::Extrinsic>::SignaturePayload)> {
        let tip = 0;
        // take the biggest period possible.
        let period =
            BlockHashCount::get().checked_next_power_of_two().map(|c| c / 2).unwrap_or(2) as u64;
        let current_block = System::block_number()
			.saturated_into::<u64>()
			// The `System::block_number` is initialized with `n+1`,
			// so the actual block number is `n`.
			.saturating_sub(1);
        let era = Era::mortal(period, current_block);
        let extra = (
            frame_system::CheckSpecVersion::<Runtime>::new(),
            frame_system::CheckTxVersion::<Runtime>::new(),
            frame_system::CheckGenesis::<Runtime>::new(),
            frame_system::CheckEra::<Runtime>::from(era),
            frame_system::CheckNonce::<Runtime>::from(nonce),
            frame_system::CheckWeight::<Runtime>::new(),
            pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(tip),
            pallet_free_tx::ValidateElectricityPayment::<Runtime>::new(),
        );
        let raw_payload = SignedPayload::new(call, extra)
            .map_err(|e| {
                log::warn!("Unable to create signed payload: {:?}", e);
            })
            .ok()?;
        let signature = raw_payload.using_encoded(|payload| C::sign(payload, public))?;
        let address = Indices::unlookup(account);
        let (call, extra, _) = raw_payload.deconstruct();
        Some((call, (address, signature, extra)))
    }
}

impl frame_system::offchain::SigningTypes for Runtime {
    type Public = <Signature as traits::Verify>::Signer;
    type Signature = Signature;
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Runtime
where RuntimeCall: From<C>
{
    type Extrinsic = UncheckedExtrinsic;
    type OverarchingCall = RuntimeCall;
}

impl pallet_im_online::Config for Runtime {
    type AuthorityId = ImOnlineId;
    type MaxKeys = MaxKeys;
    type MaxPeerDataEncodingSize = MaxPeerDataEncodingSize;
    type MaxPeerInHeartbeats = MaxPeerInHeartbeats;
    type NextSessionRotation = Babe;
    type ReportUnresponsiveness = Offences;
    type RuntimeEvent = RuntimeEvent;
    type UnsignedPriority = ImOnlineUnsignedPriority;
    type ValidatorSet = Historical;
    type WeightInfo = pallet_im_online::weights::SubstrateWeight<Runtime>;
}

impl pallet_offences::Config for Runtime {
    type IdentificationTuple = pallet_session::historical::IdentificationTuple<Self>;
    type OnOffenceHandler = Staking;
    type RuntimeEvent = RuntimeEvent;
}

impl pallet_authority_discovery::Config for Runtime {
    type MaxAuthorities = MaxAuthorities;
}

impl pallet_grandpa::Config for Runtime {
    type HandleEquivocation = pallet_grandpa::EquivocationHandler<
        Self::KeyOwnerIdentification,
        Offences,
        ReportLongevity,
    >;
    type KeyOwnerIdentification = <Self::KeyOwnerProofSystem as KeyOwnerProofSystem<(
        KeyTypeId,
        GrandpaId,
    )>>::IdentificationTuple;
    type KeyOwnerProof =
        <Self::KeyOwnerProofSystem as KeyOwnerProofSystem<(KeyTypeId, GrandpaId)>>::Proof;
    type KeyOwnerProofSystem = Historical;
    type MaxAuthorities = MaxAuthorities;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
}

parameter_types! {
  pub const BasicDeposit: Balance = 10 * DOLLARS;       // 258 bytes on-chain
  pub const FieldDeposit: Balance = 250 * CENTS;        // 66 bytes on-chain
  pub const SubAccountDeposit: Balance = 2 * DOLLARS;   // 53 bytes on-chain
  pub const MaxSubAccounts: u32 = 100;
  pub const MaxAdditionalFields: u32 = 100;
  pub const MaxRegistrars: u32 = 20;
}

impl pallet_identity::Config for Runtime {
    type BasicDeposit = BasicDeposit;
    type Currency = Balances;
    type FieldDeposit = FieldDeposit;
    type ForceOrigin = EnsureRootOrHalfCouncil;
    type MaxAdditionalFields = MaxAdditionalFields;
    type MaxRegistrars = MaxRegistrars;
    type MaxSubAccounts = MaxSubAccounts;
    type RegistrarOrigin = EnsureRootOrHalfCouncil;
    type RuntimeEvent = RuntimeEvent;
    type Slashed = Treasury;
    type SubAccountDeposit = SubAccountDeposit;
    type WeightInfo = pallet_identity::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
  pub const ConfigDepositBase: Balance = 5 * DOLLARS;
  pub const FriendDepositFactor: Balance = 50 * CENTS;
  pub const MaxFriends: u16 = 9;
  pub const RecoveryDeposit: Balance = 5 * DOLLARS;
}

impl pallet_recovery::Config for Runtime {
    type ConfigDepositBase = ConfigDepositBase;
    type Currency = Balances;
    type FriendDepositFactor = FriendDepositFactor;
    type MaxFriends = MaxFriends;
    type RecoveryDeposit = RecoveryDeposit;
    type RuntimeCall = RuntimeCall;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_recovery::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
  pub const CandidateDeposit: Balance = 10 * DOLLARS;
  pub const WrongSideDeduction: Balance = 2 * DOLLARS;
  pub const MaxStrikes: u32 = 10;
  pub const RotationPeriod: BlockNumber = 80 * HOURS;
  pub const PeriodSpend: Balance = 500 * DOLLARS;
  pub const MaxLockDuration: BlockNumber = 36 * 30 * DAYS;
  pub const ChallengePeriod: BlockNumber = 7 * DAYS;
  pub const MaxCandidateIntake: u32 = 10;
  pub const SocietyPalletId: PalletId = PalletId(*b"py/socie");
}

impl pallet_society::Config for Runtime {
    type CandidateDeposit = CandidateDeposit;
    type ChallengePeriod = ChallengePeriod;
    type Currency = Balances;
    type FounderSetOrigin =
        pallet_collective::EnsureProportionMoreThan<AccountId, CouncilCollective, 1, 2>;
    type MaxCandidateIntake = MaxCandidateIntake;
    type MaxLockDuration = MaxLockDuration;
    type MaxStrikes = MaxStrikes;
    type MembershipChanged = ();
    type PalletId = SocietyPalletId;
    type PeriodSpend = PeriodSpend;
    type Randomness = RandomnessCollectiveFlip;
    type RotationPeriod = RotationPeriod;
    type RuntimeEvent = RuntimeEvent;
    type SuspensionJudgementOrigin = pallet_society::EnsureFounder<Runtime>;
    type WrongSideDeduction = WrongSideDeduction;
}

parameter_types! {
    pub const MinVestedTransfer: Balance = 100 * DOLLARS;
    pub UnvestedFundsAllowedWithdrawReasons: WithdrawReasons =
        WithdrawReasons::except(WithdrawReasons::TRANSFER | WithdrawReasons::RESERVE);
}

impl pallet_vesting::Config for Runtime {
    type BlockNumberToBalance = ConvertInto;
    type Currency = Balances;
    type MinVestedTransfer = MinVestedTransfer;
    type RuntimeEvent = RuntimeEvent;
    type UnvestedFundsAllowedWithdrawReasons = UnvestedFundsAllowedWithdrawReasons;
    type WeightInfo = pallet_vesting::weights::SubstrateWeight<Runtime>;

    // `VestingInfo` encode length is 36bytes. 28 schedules gets encoded as 1009 bytes, which is the
    // highest number of schedules that encodes less than 2^10.
    const MAX_VESTING_SCHEDULES: u32 = 28;
}

impl pallet_transaction_storage::Config for Runtime {
    type Currency = Balances;
    type FeeDestination = ();
    type MaxBlockTransactions =
        ConstU32<{ pallet_transaction_storage::DEFAULT_MAX_BLOCK_TRANSACTIONS }>;
    type MaxTransactionSize =
        ConstU32<{ pallet_transaction_storage::DEFAULT_MAX_TRANSACTION_SIZE }>;
    type RuntimeCall = RuntimeCall;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_transaction_storage::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const BagThresholds: &'static [u64] = &voter_bags::THRESHOLDS;
}
type VoterBagsListInstance = pallet_bags_list::Instance1;
impl pallet_bags_list::Config<VoterBagsListInstance> for Runtime {
    type BagThresholds = BagThresholds;
    type RuntimeEvent = RuntimeEvent;
    type Score = VoteWeight;
    /// The voter bags-list is loosely kept up to date, and the real source of truth for the score
    /// of each node is the staking pallet.
    type ScoreProvider = Staking;
    type WeightInfo = pallet_bags_list::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
  pub const PostUnbondPoolsWindow: u32 = 4;
  pub const NominationPoolsPalletId: PalletId = PalletId(*b"py/nopls");
  pub const MaxPointsToBalance: u8 = 10;
}

use sp_runtime::traits::Convert;
pub struct BalanceToU256;
impl Convert<Balance, sp_core::U256> for BalanceToU256 {
    fn convert(balance: Balance) -> sp_core::U256 { sp_core::U256::from(balance) }
}
pub struct U256ToBalance;
impl Convert<sp_core::U256, Balance> for U256ToBalance {
    fn convert(n: sp_core::U256) -> Balance { n.try_into().unwrap_or(Balance::max_value()) }
}

impl pallet_nomination_pools::Config for Runtime {
    type BalanceToU256 = BalanceToU256;
    type Currency = Balances;
    type CurrencyBalance = Balance;
    type MaxMetadataLen = ConstU32<256>;
    type MaxPointsToBalance = MaxPointsToBalance;
    type MaxUnbonding = ConstU32<8>;
    type PalletId = NominationPoolsPalletId;
    type PostUnbondingPoolsWindow = PostUnbondPoolsWindow;
    type RewardCounter = FixedU128;
    type RuntimeEvent = RuntimeEvent;
    type StakingInterface = pallet_staking::Pallet<Self>;
    type U256ToBalance = U256ToBalance;
    type WeightInfo = ();
}

impl pallet_propagation::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
}

parameter_types! {
  pub const MinValidators: u32 = 10;
}

impl pallet_slashing::Config for Runtime {
    type AuthorityId = pallet_babe::AuthorityId;
    type MinValidators = MinValidators;
    type ReportBad = Offences;
    type RuntimeEvent = RuntimeEvent;
    type ValidatorIdOf = pallet_staking::StashOf<Self>;
    type ValidatorSet = Historical;
}

parameter_types! {
  pub const PruneBlock: BlockNumber = 10;
  pub const SigningPartySize: usize = SIGNING_PARTY_SIZE;
}

impl pallet_relayer::Config for Runtime {
    type PruneBlock = PruneBlock;
    type RuntimeEvent = RuntimeEvent;
    type SigningPartySize = SigningPartySize;
    type WeightInfo = weights::pallet_relayer::WeightInfo<Runtime>;
}

parameter_types! {
  pub const MaxAclLength: u32 = 25;
  // 1mb max
  pub const MaxV2Constraint: u32 = 1_000_000;
  pub const V2ConstraintsDepositPerByte: Balance = 1 * MILLICENTS;
}

impl pallet_constraints::Config for Runtime {
    type Currency = Balances;
    type MaxAclLength = MaxAclLength;
    type MaxV2Constraint = MaxV2Constraint;
    type RuntimeEvent = RuntimeEvent;
    type V2ConstraintsDepositPerByte = V2ConstraintsDepositPerByte;
    type WeightInfo = weights::pallet_constraints::WeightInfo<Runtime>;
}

impl pallet_transaction_pause::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type UpdateOrigin = EitherOfDiverse<
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 2, 3>,
    >;
    type WeightInfo = weights::pallet_transaction_pause::WeightInfo<Runtime>;
}

impl pallet_free_tx::Config for Runtime {
    type RuntimeCall = RuntimeCall;
    type RuntimeEvent = RuntimeEvent;
    type UpdateOrigin = EitherOfDiverse<
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 2, 3>,
    >;
    type WeightInfo = weights::pallet_free_tx::WeightInfo<Runtime>;
}

construct_runtime!(
  pub enum Runtime where
    Block = Block,
    NodeBlock = node_primitives::Block,
    UncheckedExtrinsic = UncheckedExtrinsic
  {
    System: frame_system = 1,
    Utility: pallet_utility = 2,
    Babe: pallet_babe = 3,
    Timestamp: pallet_timestamp = 4,
    Authorship: pallet_authorship = 5,
    Indices: pallet_indices = 6,
    Balances: pallet_balances = 7,
    TransactionPayment: pallet_transaction_payment = 8,
    ElectionProviderMultiPhase: pallet_election_provider_multi_phase = 9,

    // staking with our extra staking extension
    Staking: pallet_staking = 11,
    StakingExtension: pallet_staking_extension = 12,

    Session: pallet_session = 20,
    Democracy: pallet_democracy = 21,
    Council: pallet_collective::<Instance1> = 22,
    TechnicalCommittee: pallet_collective::<Instance2> = 23,
    Elections: pallet_elections_phragmen = 24,
    TechnicalMembership: pallet_membership::<Instance1> = 25,

    Grandpa: pallet_grandpa = 30,
    Treasury: pallet_treasury = 31,
    Sudo: pallet_sudo = 32,
    ImOnline: pallet_im_online = 33,
    AuthorityDiscovery: pallet_authority_discovery =34,
    Offences: pallet_offences = 35,
    Historical: pallet_session_historical = 36,
    RandomnessCollectiveFlip: pallet_randomness_collective_flip = 37,
    Identity: pallet_identity = 38,
    Society: pallet_society = 39,

    Recovery: pallet_recovery = 40,
    Vesting: pallet_vesting = 41,
    Scheduler: pallet_scheduler = 42,
    Preimage: pallet_preimage = 43,
    Proxy: pallet_proxy = 44,
    Multisig: pallet_multisig = 45,
    Bounties: pallet_bounties = 46,
    Tips: pallet_tips = 47,
    TransactionStorage: pallet_transaction_storage = 48,
    BagsList: pallet_bags_list::<Instance1> = 49,
    NominationPools: pallet_nomination_pools = 50,

    // custom pallets
    Propagation: pallet_propagation = 51,
    Relayer: pallet_relayer = 52,
    Slashing: pallet_slashing = 53,
    Constraints: pallet_constraints = 54,
    TransactionPause: pallet_transaction_pause = 55,
    FreeTx: pallet_free_tx = 56,


  }
);

/// The address format for describing accounts.
pub type Address = sp_runtime::MultiAddress<AccountId, AccountIndex>;
/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;
/// BlockId type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;
/// The SignedExtension to the basic transaction logic.
///
/// When you change this, you **MUST** modify [`sign`] in `bin/node/testing/src/keyring.rs`!
///
/// [`sign`]: <../../testing/src/keyring.rs.html>
pub type SignedExtra = (
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckEra<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
    pallet_free_tx::ValidateElectricityPayment<Runtime>,
);
/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
    generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;
/// The payload being signed in transactions.
pub type SignedPayload = generic::SignedPayload<RuntimeCall, SignedExtra>;
/// Extrinsic type that has already been checked.
pub type CheckedExtrinsic = generic::CheckedExtrinsic<AccountId, RuntimeCall, SignedExtra>;
/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
    // TODO JH fix this
    Migrations,
>;

type Migrations = (pallet_nomination_pools::migration::v2::MigrateToV2<Runtime>,);

#[cfg(feature = "runtime-benchmarks")]
#[macro_use]
extern crate frame_benchmarking;

#[cfg(feature = "runtime-benchmarks")]
mod benches {
    define_benchmarks!(
      [frame_benchmarking, BaselineBench::<Runtime>]
      [pallet_babe, Babe]
      [pallet_bags_list, BagsList]
      [pallet_balances, Balances]
      [pallet_bounties, Bounties]
      [pallet_collective, Council]
      [pallet_constraints, Constraints]
      [pallet_democracy, Democracy]
      [pallet_election_provider_multi_phase, ElectionProviderMultiPhase]
      [pallet_election_provider_support_benchmarking, EPSBench::<Runtime>]
      [pallet_elections_phragmen, Elections]
      [pallet_free_tx, FreeTx]
      [pallet_staking_extension, StakingExtension]
      [pallet_grandpa, Grandpa]
      [pallet_im_online, ImOnline]
      [pallet_indices, Indices]
      [pallet_membership, TechnicalMembership]
      [pallet_nomination_pools, NominationPoolsBench::<Runtime>]
      [pallet_multisig, Multisig]
      [pallet_offences, OffencesBench::<Runtime>]
      [pallet_preimage, Preimage]
      [pallet_proxy, Proxy]
      [pallet_relayer, Relayer]
      [pallet_scheduler, Scheduler]
      [pallet_session, SessionBench::<Runtime>]
      [pallet_staking, Staking]
      [frame_system, SystemBench::<Runtime>]
      [pallet_timestamp, Timestamp]
      [pallet_tips, Tips]
      [pallet_transaction_pause, TransactionPause]
      [pallet_transaction_storage, TransactionStorage]
      [pallet_treasury, Treasury]
      [pallet_utility, Utility]
      [pallet_vesting, Vesting]
    );
}

impl_runtime_apis! {
  impl sp_api::Core<Block> for Runtime {
    fn version() -> RuntimeVersion {
      VERSION
    }

    fn execute_block(block: Block) {
      Executive::execute_block(block);
    }

    fn initialize_block(header: &<Block as BlockT>::Header) {
      Executive::initialize_block(header)
    }
  }

  impl sp_api::Metadata<Block> for Runtime {
    fn metadata() -> OpaqueMetadata {
      OpaqueMetadata::new(Runtime::metadata().into())
    }
  }


  impl sp_block_builder::BlockBuilder<Block> for Runtime {
    fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
      Executive::apply_extrinsic(extrinsic)
    }

    fn finalize_block() -> <Block as BlockT>::Header {
      Executive::finalize_block()
    }

    fn inherent_extrinsics(data: InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
      data.create_extrinsics()
    }

    fn check_inherents(block: Block, data: InherentData) -> CheckInherentsResult {
      data.check_extrinsics(&block)
    }
  }

  impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
    fn validate_transaction(
      source: TransactionSource,
      tx: <Block as BlockT>::Extrinsic,
      block_hash: <Block as BlockT>::Hash,
    ) -> TransactionValidity {
      Executive::validate_transaction(source, tx, block_hash)
    }
  }

    impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
        fn offchain_worker(header: &<Block as BlockT>::Header) {
            Executive::offchain_worker(header)
        }
    }

  impl fg_primitives::GrandpaApi<Block> for Runtime {
    fn grandpa_authorities() -> GrandpaAuthorityList {
      Grandpa::grandpa_authorities()
    }

    fn current_set_id() -> fg_primitives::SetId {
      Grandpa::current_set_id()
    }

    fn submit_report_equivocation_unsigned_extrinsic(
      equivocation_proof: fg_primitives::EquivocationProof<
        <Block as BlockT>::Hash,
        NumberFor<Block>,
      >,
      key_owner_proof: fg_primitives::OpaqueKeyOwnershipProof,
    ) -> Option<()> {
      let key_owner_proof = key_owner_proof.decode()?;

      Grandpa::submit_unsigned_equivocation_report(
        equivocation_proof,
        key_owner_proof,
      )
    }

    fn generate_key_ownership_proof(
      _set_id: fg_primitives::SetId,
      authority_id: GrandpaId,
    ) -> Option<fg_primitives::OpaqueKeyOwnershipProof> {
      use codec::Encode;

      Historical::prove((fg_primitives::KEY_TYPE, authority_id))
        .map(|p| p.encode())
        .map(fg_primitives::OpaqueKeyOwnershipProof::new)
    }
  }

  impl sp_consensus_babe::BabeApi<Block> for Runtime {
        fn configuration() -> sp_consensus_babe::BabeConfiguration {
            let epoch_config = Babe::epoch_config().unwrap_or(BABE_GENESIS_EPOCH_CONFIG);
            sp_consensus_babe::BabeConfiguration {
                slot_duration: Babe::slot_duration(),
                epoch_length: EpochDuration::get(),
                c: epoch_config.c,
                authorities: Babe::authorities().to_vec(),
                randomness: Babe::randomness(),
                allowed_slots: epoch_config.allowed_slots,
            }
        }

    fn current_epoch_start() -> sp_consensus_babe::Slot {
      Babe::current_epoch_start()
    }

    fn current_epoch() -> sp_consensus_babe::Epoch {
      Babe::current_epoch()
    }

    fn next_epoch() -> sp_consensus_babe::Epoch {
      Babe::next_epoch()
    }

    fn generate_key_ownership_proof(
      _slot: sp_consensus_babe::Slot,
      authority_id: sp_consensus_babe::AuthorityId,
    ) -> Option<sp_consensus_babe::OpaqueKeyOwnershipProof> {
      use codec::Encode;

      Historical::prove((sp_consensus_babe::KEY_TYPE, authority_id))
        .map(|p| p.encode())
        .map(sp_consensus_babe::OpaqueKeyOwnershipProof::new)
    }

    fn submit_report_equivocation_unsigned_extrinsic(
      equivocation_proof: sp_consensus_babe::EquivocationProof<<Block as BlockT>::Header>,
      key_owner_proof: sp_consensus_babe::OpaqueKeyOwnershipProof,
    ) -> Option<()> {
      let key_owner_proof = key_owner_proof.decode()?;

      Babe::submit_unsigned_equivocation_report(
        equivocation_proof,
        key_owner_proof,
      )
    }
  }

  impl sp_authority_discovery::AuthorityDiscoveryApi<Block> for Runtime {
    fn authorities() -> Vec<AuthorityDiscoveryId> {
      AuthorityDiscovery::authorities()
    }
  }

  impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Index> for Runtime {
    fn account_nonce(account: AccountId) -> Index {
      System::account_nonce(account)
    }
  }


  impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<
    Block,
    Balance,
  > for Runtime {
    fn query_info(uxt: <Block as BlockT>::Extrinsic, len: u32) -> RuntimeDispatchInfo<Balance> {
      TransactionPayment::query_info(uxt, len)
    }
    fn query_fee_details(uxt: <Block as BlockT>::Extrinsic, len: u32) -> FeeDetails<Balance> {
      TransactionPayment::query_fee_details(uxt, len)
    }
  }


  impl sp_session::SessionKeys<Block> for Runtime {
    fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
      SessionKeys::generate(seed)
    }

    fn decode_session_keys(
      encoded: Vec<u8>,
    ) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
      SessionKeys::decode_into_raw_public_keys(&encoded)
    }
  }

  #[cfg(feature = "try-runtime")]
  impl frame_try_runtime::TryRuntime<Block> for Runtime {
    fn on_runtime_upgrade() -> Result<(Weight, Weight), sp_runtime::RuntimeString> {
      let weight = Executive::try_runtime_upgrade()?;
      Ok((weight, RuntimeBlockWeights::get().max_block))
    }
  }

  #[cfg(feature = "runtime-benchmarks")]
  impl frame_benchmarking::Benchmark<Block> for Runtime {
    fn benchmark_metadata(extra: bool) -> (
            Vec<frame_benchmarking::BenchmarkList>,
            Vec<frame_support::traits::StorageInfo>,
        ) {
            use frame_benchmarking::{baseline, Benchmarking, BenchmarkList};
            use frame_support::traits::StorageInfoTrait;

            // Trying to add benchmarks directly to the Session Pallet caused cyclic dependency
            // issues. To get around that, we separated the Session benchmarks into its own crate,
            // which is why we need these two lines below.
            use pallet_session_benchmarking::Pallet as SessionBench;
            use pallet_offences_benchmarking::Pallet as OffencesBench;
            use pallet_election_provider_support_benchmarking::Pallet as EPSBench;
            use frame_system_benchmarking::Pallet as SystemBench;
            use baseline::Pallet as BaselineBench;
            use pallet_nomination_pools_benchmarking::Pallet as NominationPoolsBench;

            let mut list = Vec::<BenchmarkList>::new();
            list_benchmarks!(list, extra);

            let storage_info = AllPalletsWithSystem::storage_info();

            (list, storage_info)
        }

        fn dispatch_benchmark(
          config: frame_benchmarking::BenchmarkConfig
        ) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, sp_runtime::RuntimeString> {
          use frame_benchmarking::{baseline, Benchmarking, BenchmarkBatch,  TrackedStorageKey};

          // Trying to add benchmarks directly to the Session Pallet caused cyclic dependency
          // issues. To get around that, we separated the Session benchmarks into its own crate,
          // which is why we need these two lines below.
          use pallet_session_benchmarking::Pallet as SessionBench;
          use pallet_offences_benchmarking::Pallet as OffencesBench;
          use pallet_election_provider_support_benchmarking::Pallet as EPSBench;
          use frame_system_benchmarking::Pallet as SystemBench;
          use baseline::Pallet as BaselineBench;
          use pallet_nomination_pools_benchmarking::Pallet as NominationPoolsBench;

          impl pallet_session_benchmarking::Config for Runtime {}
          impl pallet_offences_benchmarking::Config for Runtime {}
          impl pallet_election_provider_support_benchmarking::Config for Runtime {}
          impl frame_system_benchmarking::Config for Runtime {}
          impl baseline::Config for Runtime {}
          impl pallet_nomination_pools_benchmarking::Config for Runtime {}

          use frame_support::traits::WhitelistedStorageKeys;
          let mut whitelist: Vec<TrackedStorageKey> = AllPalletsWithSystem::whitelisted_storage_keys();

          // Treasury Account
          // TODO: this is manual for now, someday we might be able to use a
          // macro for this particular key
          let treasury_key = frame_system::Account::<Runtime>::hashed_key_for(Treasury::account_id());
          whitelist.push(treasury_key.to_vec().into());

          let mut batches = Vec::<BenchmarkBatch>::new();
          let params = (&config, &whitelist);
          add_benchmarks!(params, batches);
          Ok(batches)
        }
      }
}

#[cfg(test)]
mod tests {
    use frame_election_provider_support::NposSolution;
    use frame_system::offchain::CreateSignedTransaction;
    use sp_runtime::UpperOf;

    use super::*;

    #[test]
    fn validate_transaction_submitter_bounds() {
        fn is_submit_signed_transaction<T>()
        where T: CreateSignedTransaction<RuntimeCall> {
        }

        is_submit_signed_transaction::<Runtime>();
    }

    #[test]
    fn perbill_as_onchain_accuracy() {
        type OnChainAccuracy =
        <<Runtime as pallet_election_provider_multi_phase::MinerConfig>::Solution as NposSolution>::Accuracy;
        let maximum_chain_accuracy: Vec<UpperOf<OnChainAccuracy>> = (0..MaxNominations::get())
            .map(|_| <UpperOf<OnChainAccuracy>>::from(OnChainAccuracy::one().deconstruct()))
            .collect();
        let _: UpperOf<OnChainAccuracy> =
            maximum_chain_accuracy.iter().fold(0, |acc, x| acc.checked_add(*x).unwrap());
    }

    #[test]
    fn call_size() {
        assert!(
            core::mem::size_of::<RuntimeCall>() <= 200,
            "size of Call is more than 200 bytes: some calls have too big arguments, use Box to \
             reduce the
			size of Call.
			If the limit is too strong, maybe consider increase the limit to 300.",
        );
    }
}
