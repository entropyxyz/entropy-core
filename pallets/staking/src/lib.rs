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

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::useless_conversion)]
//! # Staking Pallet
//!
//!
//! ## Overview
//!
//! An extention on normal staking that adds the ability to add a threshold signer key
//! and an IP address for validators
//!
//! ### Public Functions
//!
//! change_endpoint - allows a user to change their designated endpoint (needed so signing nodes can
//! find coms manager) change_threshold_accounts - allows a user to change their threshold account
//! (needed so comms manager can confirm done) withdraw_unbonded - wraps substrate's call but clears
//! endpoint and threshold key if all is unbonded validate - wraps substrate's call but forces a
//! threshold key and endpoint

use core::convert::TryInto;

pub use pallet::*;
use pallet_staking::{MaxNominationsOf, ValidatorPrefs};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

pub use crate::weights::WeightInfo;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;

pub mod weights;
use core::convert::TryFrom;

use sp_staking::SessionIndex;

#[frame_support::pallet]
pub mod pallet {
    use entropy_shared::{
        attestation::{AttestationHandler, QuoteContext, VerifyQuoteError},
        ValidatorInfo, X25519PublicKey, MAX_SIGNERS, PREGENERATED_NETWORK_VERIFYING_KEY,
        VERIFICATION_KEY_LENGTH,
    };
    use frame_support::{
        dispatch::{DispatchResult, DispatchResultWithPostInfo},
        pallet_prelude::*,
        traits::{Currency, Randomness},
        DefaultNoBound,
    };
    use frame_system::pallet_prelude::*;
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaCha20Rng, ChaChaRng,
    };
    use sp_runtime::traits::TrailingZeroInput;
    use sp_staking::StakingAccount;
    use sp_std::vec;
    use sp_std::vec::Vec;

    use super::*;

    pub type VerifyingKey = BoundedVec<u8, ConstU32<VERIFICATION_KEY_LENGTH>>;

    #[pallet::config]
    pub trait Config:
        pallet_session::Config
        + frame_system::Config
        + pallet_staking::Config
        + pallet_parameters::Config
        + pallet_slashing::Config
    {
        /// Because this pallet emits events, it depends on the runtime's definition of an event.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// The weight information of this pallet.
        type WeightInfo: WeightInfo;

        /// Something that provides randomness in the runtime.
        type Randomness: Randomness<Self::Hash, BlockNumberFor<Self>>;

        /// The currency mechanism, used to take storage deposits for example.
        type Currency: Currency<Self::AccountId>;

        /// The maximum length of a threshold server's endpoint address, in bytes.
        type MaxEndpointLength: Get<u32>;

        /// The handler to use when issuing and verifying attestations.
        type AttestationHandler: AttestationHandler<Self::AccountId>;
    }

    /// Endpoint where a threshold server can be reached at
    pub type TssServerURL = Vec<u8>;

    // The balance type of this pallet.
    pub type BalanceOf<T> = <T as pallet_staking::Config>::CurrencyBalance;

    /// Information about a threshold server
    #[derive(
        Encode, Decode, Clone, Eq, PartialEq, RuntimeDebug, DecodeWithMemTracking, TypeInfo,
    )]
    #[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
    pub struct ServerInfo<AccountId> {
        pub tss_account: AccountId,
        pub x25519_public_key: X25519PublicKey,
        pub endpoint: TssServerURL,
        /// The most recent TDX quote provided
        pub tdx_quote: Vec<u8>,
    }

    /// Info that is requiered to do a proactive refresh
    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo, Default)]
    pub struct RefreshInfo {
        pub validators_info: Vec<ValidatorInfo>,
        pub proactive_refresh_keys: Vec<Vec<u8>>,
    }

    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo, Default)]
    pub struct ReshareInfo<BlockNumber> {
        pub new_signers: Vec<Vec<u8>>,
        pub block_number: BlockNumber,
    }

    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
    pub struct NextSignerInfo<ValidatorId> {
        pub next_signers: Vec<ValidatorId>,
        pub confirmations: Vec<ValidatorId>,
    }
    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Stores the relationship between a validator's stash account and the information about their
    /// threshold server.
    ///
    /// # Note
    ///
    /// This mapping doesn't only include information about validators in the active set, but also
    /// information about validator candidates (i.e, those _might_ be part of the active set in the
    /// following era).
    #[pallet::storage]
    #[pallet::getter(fn threshold_server)]
    pub type ThresholdServers<T: Config> =
        StorageMap<_, Blake2_128Concat, T::ValidatorId, ServerInfo<T::AccountId>, OptionQuery>;

    /// A mapping between a threshold server's Account ID and its corresponding validator's stash
    /// account (i.e the reverse of [ThresholdServers]).
    ///
    /// # Note
    ///
    /// This mapping doesn't only include information about validators in the active set, but also
    /// information about validator candidates (i.e, those _might_ be part of the active set in the
    /// following era).
    #[pallet::storage]
    #[pallet::getter(fn threshold_to_stash)]
    pub type ThresholdToStash<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, T::ValidatorId, OptionQuery>;

    #[derive(
        Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default,
    )]
    pub enum JumpStartStatus {
        #[default]
        Ready,
        // u32 is block number process was started, after X blocks we assume failed and retry
        InProgress(u32),
        Done,
    }

    /// Details of status of jump starting the network
    #[derive(
        Clone,
        Encode,
        Decode,
        Eq,
        PartialEqNoBound,
        RuntimeDebug,
        TypeInfo,
        frame_support::DefaultNoBound,
    )]
    #[scale_info(skip_type_params(T))]
    pub struct JumpStartDetails<T: Config> {
        pub jump_start_status: JumpStartStatus,
        pub confirmations: Vec<T::ValidatorId>,
        pub verifying_key: Option<VerifyingKey>,
        pub parent_key_threshold: u8,
    }

    /// A trigger for the proactive refresh OCW
    #[pallet::storage]
    #[pallet::getter(fn proactive_refresh)]
    pub type ProactiveRefresh<T: Config> = StorageValue<_, RefreshInfo, ValueQuery>;

    /// Current validators in the network that hold the parent key and are expected to sign
    #[pallet::storage]
    #[pallet::getter(fn signers)]
    pub type Signers<T: Config> = StorageValue<_, Vec<T::ValidatorId>, ValueQuery>;

    /// The next signers ready to take the Signers place when a reshare is done
    #[pallet::storage]
    #[pallet::getter(fn next_signers)]
    pub type NextSigners<T: Config> = StorageValue<_, NextSignerInfo<T::ValidatorId>, OptionQuery>;

    /// The next time a reshare should happen
    #[pallet::storage]
    #[pallet::getter(fn reshare_data)]
    pub type ReshareData<T: Config> = StorageValue<_, ReshareInfo<BlockNumberFor<T>>, ValueQuery>;

    /// A concept of what progress status the jumpstart is
    #[pallet::storage]
    #[pallet::getter(fn jump_start_progress)]
    pub type JumpStartProgress<T: Config> = StorageValue<_, JumpStartDetails<T>, ValueQuery>;

    /// Tell Signers to rotate keyshare
    #[pallet::storage]
    #[pallet::getter(fn rotate_keyshares)]
    pub type RotateKeyshares<T: Config> = StorageValue<_, BlockNumberFor<T>, ValueQuery>;

    /// A type used to simplify the genesis configuration definition.
    pub type ThresholdServersConfig<T> = (
        <T as pallet_session::Config>::ValidatorId,
        (<T as frame_system::Config>::AccountId, X25519PublicKey, TssServerURL, Vec<u8>),
    );

    #[pallet::genesis_config]
    #[derive(DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub threshold_servers: Vec<ThresholdServersConfig<T>>,
        /// validator info and accounts to take part in proactive refresh
        pub proactive_refresh_data: (Vec<ValidatorInfo>, Vec<Vec<u8>>),
        /// Whether to begin in an already jumpstarted state in order to be able to test signing
        /// using pre-generated keyshares
        pub jump_started_signers: Option<Vec<T::ValidatorId>>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            let _ = self
                .threshold_servers
                .clone()
                .into_iter()
                .map(|x| assert!(x.1 .2.len() as u32 <= T::MaxEndpointLength::get()));

            for (validator_stash, server_info_tuple) in &self.threshold_servers {
                let server_info = ServerInfo {
                    tss_account: server_info_tuple.0.clone(),
                    x25519_public_key: server_info_tuple.1,
                    endpoint: server_info_tuple.2.clone(),
                    tdx_quote: server_info_tuple.3.clone(),
                };

                ThresholdServers::<T>::insert(validator_stash, server_info.clone());
                ThresholdToStash::<T>::insert(&server_info.tss_account, validator_stash);
            }

            let refresh_info = RefreshInfo {
                validators_info: self.proactive_refresh_data.0.clone(),
                proactive_refresh_keys: self.proactive_refresh_data.1.clone(),
            };
            ProactiveRefresh::<T>::put(refresh_info);

            if let Some(jump_started_signers) = &self.jump_started_signers {
                Signers::<T>::put(jump_started_signers.clone());
                JumpStartProgress::<T>::put(JumpStartDetails {
                    jump_start_status: JumpStartStatus::Done,
                    confirmations: jump_started_signers.clone(),
                    verifying_key: Some(
                        BoundedVec::try_from(PREGENERATED_NETWORK_VERIFYING_KEY.to_vec()).unwrap(),
                    ),
                    parent_key_threshold: 2,
                });
            }
        }
    }

    // Errors inform users that something went wrong.
    #[pallet::error]
    pub enum Error<T> {
        EndpointTooLong,
        NoBond,
        NotController,
        NoThresholdKey,
        InvalidValidatorId,
        SigningGroupError,
        TssAccountAlreadyExists,
        NotSigner,
        NotNextSigner,
        ReshareNotInProgress,
        AlreadyConfirmed,
        TooManyPendingAttestations,
        NoUnbondingWhenSigner,
        NoUnbondingWhenNextSigner,
        NoUnnominatingWhenSigner,
        NoUnnominatingWhenNextSigner,
        NoChangingThresholdAccountWhenSigner,
        /// Quote could not be parsed or verified
        BadQuote,
        /// Attestation extrinsic submitted when not requested
        UnexpectedAttestation,
        /// Hashed input data does not match what was expected
        IncorrectInputData,
        /// Unacceptable VM image running
        BadMeasurementValue,
        /// Cannot encode verifying key (PCK)
        CannotEncodeVerifyingKey,
        /// Cannot decode verifying key (PCK)
        CannotDecodeVerifyingKey,
        /// PCK certificate chain cannot be parsed
        PckCertificateParse,
        /// PCK certificate chain cannot be verified
        PckCertificateVerify,
        /// PCK certificate chain public key is not well formed
        PckCertificateBadPublicKey,
        /// Pck certificate could not be extracted from quote
        PckCertificateNoCertificate,
    }

    impl<T> From<VerifyQuoteError> for Error<T> {
        /// As there are many reasons why quote verification can fail we want these error types to
        /// be reflected in the dispatch errors from extrinsics in this pallet which do quote
        /// verification
        fn from(error: VerifyQuoteError) -> Self {
            match error {
                VerifyQuoteError::BadQuote => Error::<T>::BadQuote,
                VerifyQuoteError::UnexpectedAttestation => Error::<T>::UnexpectedAttestation,
                VerifyQuoteError::IncorrectInputData => Error::<T>::IncorrectInputData,
                VerifyQuoteError::BadMeasurementValue => Error::<T>::BadMeasurementValue,
                VerifyQuoteError::CannotEncodeVerifyingKey => Error::<T>::CannotEncodeVerifyingKey,
                VerifyQuoteError::PckCertificateParse => Error::<T>::PckCertificateParse,
                VerifyQuoteError::PckCertificateVerify => Error::<T>::PckCertificateVerify,
                VerifyQuoteError::PckCertificateBadPublicKey => {
                    Error::<T>::PckCertificateBadPublicKey
                },
                VerifyQuoteError::PckCertificateNoCertificate => {
                    Error::<T>::PckCertificateNoCertificate
                },
                VerifyQuoteError::CannotDecodeVerifyingKey => Error::<T>::CannotDecodeVerifyingKey,
            }
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// An endpoint has been added or edited. [who, endpoint]
        EndpointChanged(T::AccountId, Vec<u8>),
        /// The caller has been accepted as a validator candidate/runner up. [who, validator ID, threshold_account, endpoint]
        ValidatorCandidateAccepted(T::AccountId, T::ValidatorId, T::AccountId, Vec<u8>),
        /// A threshold account has been added or edited. [validator, threshold_account]
        ThresholdAccountChanged(
            <T as pallet_session::Config>::ValidatorId,
            ServerInfo<T::AccountId>,
        ),
        /// Node Info has been removed \[who\]
        NodeInfoRemoved(T::AccountId),
        /// Validator sync status changed [who, sync_status]
        ValidatorSyncStatus(<T as pallet_session::Config>::ValidatorId, bool),
        /// Validators subgroups rotated [old, new]
        ValidatorSubgroupsRotated(
            Vec<Vec<<T as pallet_session::Config>::ValidatorId>>,
            Vec<Vec<<T as pallet_session::Config>::ValidatorId>>,
        ),
        /// Validators in new signer group [new_signers]
        SignerConfirmed(<T as pallet_session::Config>::ValidatorId),
        /// Validators subgroups rotated [old, new]
        SignersRotation(Vec<<T as pallet_session::Config>::ValidatorId>),
        /// A TSS account has been queued up for an attestation check.
        AttestationCheckQueued(T::AccountId),
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Allows a validator to change the endpoint used by their Threshold Siganture Scheme
        /// (TSS) server.
        ///
        /// # Expects TDX Quote
        ///
        /// A valid TDX quote must be passed along in order to ensure that the validator is running
        /// TDX hardware. In order for the chain to be aware that a quote is expected from the
        /// validator `pallet_attestation::request_attestation()` must be called first.
        ///
        /// The quote format is specified in:
        /// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
        #[pallet::call_index(0)]
        #[pallet::weight(<T as Config>::WeightInfo::change_endpoint())]
        pub fn change_endpoint(
            origin: OriginFor<T>,
            endpoint: Vec<u8>,
            quote: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            ensure!(
                endpoint.len() as u32 <= T::MaxEndpointLength::get(),
                Error::<T>::EndpointTooLong
            );

            let ledger = pallet_staking::Pallet::<T>::ledger(StakingAccount::Stash(who.clone()))
                .map_err(|_| Error::<T>::NoBond)?;
            let validator_id = <T as pallet_session::Config>::ValidatorId::try_from(ledger.stash)
                .or(Err(Error::<T>::InvalidValidatorId))?;

            ThresholdServers::<T>::try_mutate(&validator_id, |maybe_server_info| {
                if let Some(server_info) = maybe_server_info {
                    // Before we modify the `server_info`, we want to check that the validator is
                    // still running TDX hardware.
                    <T::AttestationHandler as entropy_shared::attestation::AttestationHandler<
                        _,
                    >>::verify_quote(
                        &server_info.tss_account.clone(),
                        server_info.x25519_public_key,
                        quote.clone(),
                        QuoteContext::ChangeEndpoint,
                    )?;

                    server_info.endpoint.clone_from(&endpoint);
                    server_info.tdx_quote = quote;

                    Ok(())
                } else {
                    Err(Error::<T>::NoBond)
                }
            })?;

            Self::deposit_event(Event::EndpointChanged(who, endpoint));
            Ok(())
        }

        /// Allows a validator to change their associated threshold server AccountID and X25519
        /// public key.
        ///
        /// # Expects TDX Quote
        ///
        /// A valid TDX quote must be passed along in order to ensure that the validator is running
        /// TDX hardware. In order for the chain to be aware that a quote is expected from the
        /// validator `pallet_attestation::request_attestation()` must be called first.
        ///
        /// The **new** TSS AccountID must be used when requesting this quote.
        ///
        /// The quote format is specified in:
        /// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
        #[pallet::call_index(1)]
        #[pallet::weight(<T as Config>::WeightInfo::change_threshold_accounts(MAX_SIGNERS as u32))]
        pub fn change_threshold_accounts(
            origin: OriginFor<T>,
            tss_account: T::AccountId,
            x25519_public_key: X25519PublicKey,
            quote: Vec<u8>,
        ) -> DispatchResultWithPostInfo {
            let who = ensure_signed(origin)?;

            ensure!(
                !ThresholdToStash::<T>::contains_key(&tss_account),
                Error::<T>::TssAccountAlreadyExists
            );

            let stash = Self::get_stash(&who)?;
            let validator_id = <T as pallet_session::Config>::ValidatorId::try_from(stash)
                .or(Err(Error::<T>::InvalidValidatorId))?;

            let signers = Self::signers();
            ensure!(
                !signers.contains(&validator_id),
                Error::<T>::NoChangingThresholdAccountWhenSigner
            );

            let new_server_info: ServerInfo<T::AccountId> = ThresholdServers::<T>::try_mutate(
                &validator_id,
                |maybe_server_info| {
                    if let Some(server_info) = maybe_server_info {
                        // Before we modify the `server_info`, we want to check that the validator is
                        // still running TDX hardware.
                        let _provisioning_certification_key =
                            <T::AttestationHandler as entropy_shared::attestation::AttestationHandler<_>>::verify_quote(
                                &tss_account.clone(),
                                x25519_public_key,
                                quote.clone(),
                                QuoteContext::ChangeThresholdAccounts,
                            )?;

                        server_info.tss_account = tss_account;
                        server_info.x25519_public_key = x25519_public_key;
                        server_info.tdx_quote = quote;

                        ThresholdToStash::<T>::insert(&server_info.tss_account, &validator_id);

                        Ok(server_info.clone())
                    } else {
                        Err(Error::<T>::NoBond)
                    }
                },
            )?;

            Self::deposit_event(Event::ThresholdAccountChanged(validator_id, new_server_info));

            let actual_weight =
                <T as Config>::WeightInfo::change_threshold_accounts(signers.len() as u32);
            Ok(Some(actual_weight).into())
        }

        /// Wraps's Substrate's `unbond` extrinsic but checks to make sure targeted account is not a signer or next signer
        #[pallet::call_index(2)]
        #[pallet::weight(<T as Config>::WeightInfo::unbond(MAX_SIGNERS as u32, MaxNominationsOf::<T>::get()))]
        pub fn unbond(
            origin: OriginFor<T>,
            #[pallet::compact] value: BalanceOf<T>,
        ) -> DispatchResultWithPostInfo {
            let controller = ensure_signed(origin.clone())?;
            let ledger =
                pallet_staking::Pallet::<T>::ledger(StakingAccount::Controller(controller.clone()))
                    .map_err(|_| Error::<T>::NoThresholdKey)?;

            let (signers_length, nominators_length) =
                Self::ensure_not_signer_or_next_signer_or_nominating(&ledger.stash)?;

            pallet_staking::Pallet::<T>::unbond(origin, value)?;

            Ok(Some(<T as Config>::WeightInfo::unbond(signers_length, nominators_length)).into())
        }

        /// Wraps's Substrate's `chill` extrinsic but checks to make sure the targeted account is not a signer or next signer
        #[pallet::call_index(3)]
        #[pallet::weight(<T as Config>::WeightInfo::chill(MAX_SIGNERS as u32, MaxNominationsOf::<T>::get()))]
        pub fn chill(origin: OriginFor<T>) -> DispatchResultWithPostInfo {
            let controller = ensure_signed(origin.clone())?;
            let ledger =
                pallet_staking::Pallet::<T>::ledger(StakingAccount::Controller(controller.clone()))
                    .map_err(|_| Error::<T>::NoThresholdKey)?;

            let (signers_length, nominators_length) =
                Self::ensure_not_signer_or_next_signer_or_nominating(&ledger.stash)?;

            pallet_staking::Pallet::<T>::chill(origin)?;

            Ok(Some(<T as Config>::WeightInfo::chill(signers_length, nominators_length)).into())
        }

        /// Wraps's Substrate's `withdraw_unbonded` extrinsic but clears extra state if fully unbonded
        #[pallet::call_index(4)]
        #[pallet::weight(<T as Config>::WeightInfo::withdraw_unbonded(MAX_SIGNERS as u32, MaxNominationsOf::<T>::get()))]
        pub fn withdraw_unbonded(
            origin: OriginFor<T>,
            num_slashing_spans: u32,
        ) -> DispatchResultWithPostInfo {
            let controller = ensure_signed(origin.clone())?;
            let ledger =
                pallet_staking::Pallet::<T>::ledger(StakingAccount::Controller(controller.clone()))
                    .map_err(|_| Error::<T>::NoThresholdKey)?;

            let validator_id =
                <T as pallet_session::Config>::ValidatorId::try_from(ledger.stash.clone())
                    .or(Err(Error::<T>::InvalidValidatorId))?;

            let (signers_length, nominators_length) =
                Self::ensure_not_signer_or_next_signer_or_nominating(&ledger.stash)?;

            pallet_staking::Pallet::<T>::withdraw_unbonded(origin, num_slashing_spans)?;
            // TODO: do not allow unbonding of validator if not enough validators https://github.com/entropyxyz/entropy-core/issues/942
            if pallet_staking::Pallet::<T>::bonded(&controller).is_none() {
                let server_info =
                    ThresholdServers::<T>::take(&validator_id).ok_or(Error::<T>::NoThresholdKey)?;
                ThresholdToStash::<T>::remove(&server_info.tss_account);
                Self::deposit_event(Event::NodeInfoRemoved(controller));
            }
            Ok(Some(<T as Config>::WeightInfo::withdraw_unbonded(
                signers_length,
                nominators_length,
            ))
            .into())
        }

        /// Wrap's Substrate's `staking_pallet::validate()` extrinsic, but enforces that
        /// information about a validator's threshold server is provided.
        ///
        /// # Expects TDX Quote
        ///
        /// A valid TDX quote must be passed along in order to ensure that the validator candidate
        /// is running TDX hardware. In order for the chain to be aware that a quote is expected
        /// from the candidate `pallet_attestation::request_attestation()` must be called first.
        ///
        /// The quote format is specified in:
        /// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
        ///
        /// # Note
        ///
        /// Just like the original `validate()` extrinsic the effects of this are only applied in
        /// the following era.
        #[pallet::call_index(5)]
        #[pallet::weight(<T as Config>::WeightInfo::validate())]
        pub fn validate(
            origin: OriginFor<T>,
            prefs: ValidatorPrefs,
            server_info: ServerInfo<T::AccountId>,
        ) -> DispatchResult {
            let who = ensure_signed(origin.clone())?;

            ensure!(
                server_info.endpoint.len() as u32 <= T::MaxEndpointLength::get(),
                Error::<T>::EndpointTooLong
            );

            ensure!(
                !ThresholdToStash::<T>::contains_key(&server_info.tss_account),
                Error::<T>::TssAccountAlreadyExists
            );

            let _provisioning_certification_key =
                <T::AttestationHandler as entropy_shared::attestation::AttestationHandler<_>>::verify_quote(
                    &server_info.tss_account.clone(),
                    server_info.x25519_public_key,
                    server_info.tdx_quote.clone(),
                    QuoteContext::Validate,
                )
                .map_err(<VerifyQuoteError as Into<Error<T>>>::into)?;

            pallet_staking::Pallet::<T>::validate(origin, prefs)?;

            let stash = Self::get_stash(&who)?;
            let validator_id =
                T::ValidatorId::try_from(stash).or(Err(Error::<T>::InvalidValidatorId))?;

            ThresholdToStash::<T>::insert(&server_info.tss_account, &validator_id);
            ThresholdServers::<T>::insert(&validator_id, server_info.clone());

            Self::deposit_event(Event::ValidatorCandidateAccepted(
                who,
                validator_id,
                server_info.tss_account,
                server_info.endpoint,
            ));

            Ok(())
        }

        #[pallet::call_index(6)]
        #[pallet::weight(({
            <T as Config>::WeightInfo::confirm_key_reshare_confirmed(MAX_SIGNERS as u32)
            .max(<T as Config>::WeightInfo::confirm_key_reshare_completed())
        }, DispatchClass::Operational))]
        pub fn confirm_key_reshare(origin: OriginFor<T>) -> DispatchResultWithPostInfo {
            let ts_server_account = ensure_signed(origin)?;
            let validator_stash =
                Self::threshold_to_stash(&ts_server_account).ok_or(Error::<T>::NoThresholdKey)?;

            let mut signers_info =
                NextSigners::<T>::take().ok_or(Error::<T>::ReshareNotInProgress)?;
            ensure!(
                signers_info.next_signers.contains(&validator_stash),
                Error::<T>::NotNextSigner
            );

            ensure!(
                !signers_info.confirmations.contains(&validator_stash),
                Error::<T>::AlreadyConfirmed
            );

            let current_signer_length = signers_info.next_signers.len();
            let is_last_confirmation =
                signers_info.confirmations.len() == (current_signer_length - 1);

            // TODO (#927): Add another check, such as a signature or a verifying key comparison, to
            // ensure that rotation was indeed successful.
            if is_last_confirmation {
                Signers::<T>::put(signers_info.next_signers.clone());
                RotateKeyshares::<T>::put(
                    <frame_system::Pallet<T>>::block_number() + sp_runtime::traits::One::one(),
                );

                Self::deposit_event(Event::SignersRotation(signers_info.next_signers));
            } else {
                signers_info.confirmations.push(validator_stash.clone());
                NextSigners::<T>::put(signers_info);

                Self::deposit_event(Event::SignerConfirmed(validator_stash));
            }

            // TODO: Weight is `Pays::No` but want a more accurate weight for max signers vs current
            // signers see https://github.com/entropyxyz/entropy-core/issues/985
            Ok(Pays::No.into())
        }

        /// An on-chain hook for TSS servers in the signing committee to report other TSS servers in
        /// the committee for misbehaviour.
        ///
        /// Any "conequences" are handled by the configured Slashing pallet and not this pallet
        /// itself.
        #[pallet::call_index(7)]
        #[pallet::weight(<T as Config>::WeightInfo::report_unstable_peer(MAX_SIGNERS as u32))]
        pub fn report_unstable_peer(
            origin: OriginFor<T>,
            offender_tss_account: T::AccountId,
        ) -> DispatchResultWithPostInfo {
            let reporter_tss_account = ensure_signed(origin)?;

            // For reporting purposes we need to know the validator account tied to the TSS account.
            let reporter_validator_id = Self::threshold_to_stash(&reporter_tss_account)
                .ok_or(Error::<T>::NoThresholdKey)?;
            let offender_validator_id = Self::threshold_to_stash(&offender_tss_account)
                .ok_or(Error::<T>::NoThresholdKey)?;

            // Note: This operation is O(n), but with a small enough Signer group this should be
            // fine to do on-chain.
            let signers = Self::signers();
            ensure!(signers.contains(&reporter_validator_id), Error::<T>::NotSigner);
            ensure!(signers.contains(&offender_validator_id), Error::<T>::NotSigner);

            // We do a bit of a weird conversion here since we want the validator's underlying
            // `AccountId` for the reporting mechanism, not their `ValidatorId`.
            //
            // The Session pallet should have this configured to be the same thing, but we can't
            // prove that to the compiler.
            let encoded_validator_id = T::ValidatorId::encode(&reporter_validator_id);
            let reporter_validator_account = T::AccountId::decode(&mut &encoded_validator_id[..])
                .expect("A `ValidatorId` should be equivalent to an `AccountId`.");

            let encoded_validator_id = T::ValidatorId::encode(&offender_validator_id);
            let offending_peer_validator_account =
                T::AccountId::decode(&mut &encoded_validator_id[..])
                    .expect("A `ValidatorId` should be equivalent to an `AccountId`.");

            // We don't actually take any action here, we offload the reporting to the Slashing
            // pallet.
            pallet_slashing::Pallet::<T>::note_report(
                reporter_validator_account,
                offending_peer_validator_account,
            )?;

            let actual_weight =
                <T as Config>::WeightInfo::report_unstable_peer(signers.len() as u32);
            Ok(Some(actual_weight).into())
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn get_stash(controller: &T::AccountId) -> Result<T::AccountId, DispatchError> {
            let ledger =
                pallet_staking::Pallet::<T>::ledger(StakingAccount::Controller(controller.clone()))
                    .map_err(|_| Error::<T>::NotController)?;
            Ok(ledger.stash)
        }

        /// Ensures that the current validator is not a signer or a next signer
        pub fn ensure_not_signer_or_next_signer_or_nominating(
            stash: &T::AccountId,
        ) -> Result<(u32, u32), DispatchError> {
            let nominations = pallet_staking::Nominators::<T>::get(stash)
                .map_or_else(Vec::new, |x| x.targets.into_inner());

            let signers = Self::signers();

            // Check if the validator_id or any nominated validator is in signers
            let in_signers = |id: &T::AccountId| {
                let validator_id = <T as pallet_session::Config>::ValidatorId::try_from(id.clone());
                match validator_id {
                    Ok(v_id) => signers.contains(&v_id),
                    Err(_) => false,
                }
            };

            ensure!(!in_signers(stash), Error::<T>::NoUnbondingWhenSigner);
            ensure!(!nominations.iter().any(in_signers), Error::<T>::NoUnnominatingWhenSigner);

            if let Some(next_signers) = Self::next_signers() {
                let next_signers_contains = |id: &T::AccountId| {
                    let validator_id =
                        <T as pallet_session::Config>::ValidatorId::try_from(id.clone());
                    match validator_id {
                        Ok(v_id) => next_signers.next_signers.contains(&v_id),
                        Err(_) => false,
                    }
                };

                ensure!(!next_signers_contains(stash), Error::<T>::NoUnbondingWhenNextSigner);
                ensure!(
                    !nominations.iter().any(next_signers_contains),
                    Error::<T>::NoUnnominatingWhenNextSigner
                );
            }

            Ok((signers.len() as u32, nominations.len() as u32))
        }

        pub fn get_randomness() -> ChaCha20Rng {
            let phrase = b"signer_rotation";
            // TODO: Is randomness freshness an issue here
            // https://github.com/paritytech/substrate/issues/8312
            let (seed, _) = T::Randomness::random(phrase);
            // seed needs to be guaranteed to be 32 bytes.
            let seed = <[u8; 32]>::decode(&mut TrailingZeroInput::new(seed.as_ref()))
                .expect("input is padded with zeroes; qed");
            ChaChaRng::from_seed(seed)
        }

        pub fn new_session_handler(
            validators: &[<T as pallet_session::Config>::ValidatorId],
        ) -> Result<Weight, DispatchError> {
            let mut current_signers = Self::signers();
            let current_signers_length = current_signers.len();
            let signers_info = pallet_parameters::Pallet::<T>::signers_info();

            let mut weight: Weight =
                <T as Config>::WeightInfo::new_session_base_weight(current_signers_length as u32);

            // Since not enough validators do not allow rotation
            // TODO: https://github.com/entropyxyz/entropy-core/issues/943
            if validators.len() <= current_signers_length {
                return Ok(weight);
            }

            // Network not jumpstarted
            if current_signers_length == 0 {
                return Ok(weight);
            }

            let mut new_signers: Vec<Vec<u8>> = vec![];
            let mut count = 0u32;
            let mut remove_indicies_len = 0;
            let mut removed_signers = vec![];
            // removes first signer and pushes new signer to back if total signers not increased
            if current_signers_length >= signers_info.total_signers as usize {
                let mut remove_indicies = vec![];
                // Finds signers that are no longer validators to remove
                for (i, current_signer) in current_signers.clone().into_iter().enumerate() {
                    if !validators.contains(&current_signer) {
                        remove_indicies.push(i);
                    }
                }
                if remove_indicies.is_empty() {
                    removed_signers.push(current_signers[0].clone());
                    current_signers.remove(0);
                } else {
                    remove_indicies_len = remove_indicies.len();
                    // reverses vec so as signers removed it does not change location
                    let remove_indicies_reversed: Vec<_> = remove_indicies.iter().rev().collect();
                    // truncated as a current limitation see issue: https://github.com/entropyxyz/entropy-core/issues/1114
                    let truncated = if remove_indicies_reversed.len()
                        >= (signers_info.total_signers as usize - signers_info.threshold as usize)
                    {
                        remove_indicies_reversed[..(signers_info.total_signers as usize
                            - signers_info.threshold as usize)]
                            .to_vec()
                    } else {
                        remove_indicies_reversed
                    };

                    for remove_index in truncated {
                        removed_signers.push(current_signers[*remove_index].clone());
                        current_signers.remove(*remove_index);
                    }
                }
            }

            while current_signers.len() < signers_info.total_signers as usize {
                let mut randomness = Self::get_randomness();
                // grab a current signer to initiate value
                let mut next_signer_up = &current_signers[0].clone();
                let mut index;
                // loops to find signer in validator that is not already signer
                while current_signers.contains(next_signer_up)
                    || removed_signers.contains(next_signer_up)
                {
                    index = randomness.next_u32() % validators.len() as u32;
                    next_signer_up = &validators[index as usize];
                    count += 1;
                }

                current_signers.push(next_signer_up.clone());
                new_signers.push(next_signer_up.encode());
            }
            NextSigners::<T>::put(NextSignerInfo {
                next_signers: current_signers.clone(),
                confirmations: vec![],
            });

            // trigger reshare at next block
            let current_block_number = <frame_system::Pallet<T>>::block_number();
            let reshare_info = ReshareInfo {
                block_number: current_block_number - sp_runtime::traits::One::one(),
                new_signers,
            };

            ReshareData::<T>::put(reshare_info);
            JumpStartProgress::<T>::mutate(|jump_start_details| {
                jump_start_details.parent_key_threshold = signers_info.threshold
            });

            weight = <T as Config>::WeightInfo::new_session(
                current_signers.len() as u32,
                count,
                validators.len() as u32,
                remove_indicies_len as u32,
            );

            Ok(weight)
        }
    }

    pub struct SessionManager<I, T: Config>(
        sp_std::marker::PhantomData<I>,
        sp_std::marker::PhantomData<T>,
    );
    impl<
            I: pallet_session::SessionManager<ValidatorId>,
            ValidatorId,
            T: Config + pallet::Config<ValidatorId = ValidatorId>,
        > pallet_session::SessionManager<ValidatorId> for SessionManager<I, T>
    {
        fn new_session(new_index: SessionIndex) -> Option<Vec<ValidatorId>> {
            let new_session = I::new_session(new_index);
            if let Some(validators) = &new_session {
                let weight = Pallet::<T>::new_session_handler(validators);

                match weight {
                    Ok(weight) => {
                        frame_system::Pallet::<T>::register_extra_weight_unchecked(
                            weight,
                            DispatchClass::Mandatory,
                        );
                    },
                    Err(why) => {
                        log::warn!(
                            "Error splitting validators, Session: {new_index:?}, reason: {why:?}"
                        )
                    },
                }
            }
            new_session
        }

        fn new_session_genesis(new_index: SessionIndex) -> Option<Vec<ValidatorId>> {
            I::new_session_genesis(new_index)
        }

        fn end_session(end_index: SessionIndex) {
            I::end_session(end_index);
        }

        fn start_session(start_index: SessionIndex) {
            I::start_session(start_index);
        }
    }
}
