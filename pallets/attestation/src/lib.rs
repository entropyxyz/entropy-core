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

//! # Attestation Pallet
//!
//! This handles attestations that the TS servers are running on TDX hardware and that the binary
//! from our release is correctly loaded.
//!
//! It stores the nonces of all pending (requested) attestations, storing them under the associated
//! TSS account ID. So there may be at most one pending attestation per TS server. The nonce is just
//! a random 32 bytes, which is included in the input data to the TDX quote, to prove that this is
//! a freshly made quote.
//!
//! An attestation request is responded to by submitting the quote using the attest extrinsic. If
//! there was a pending attestation for the caller, the quote is verified. Verification currently
//! just means checking that the quote parses correctly and has a valid signature.
//!
//! It also stores a mapping of block number to TSS account IDs of nodes for who an attestation
//! request should be initiated. This is used by the propagation pallet to make a POST request to
//! the TS server's /attest endpoint whenever there are requests to be made.

#![cfg_attr(not(feature = "std"), no_std)]
pub use pallet::*;

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;

pub mod weights;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use entropy_shared::{AttestationQueue, QuoteInputData, X25519KeyProvider};
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_std::vec::Vec;
    use tdx_quote::{decode_verifying_key, Quote};

    pub use crate::weights::WeightInfo;

    /// A nonce included as input for a TDX quote
    type Nonce = [u8; 32];

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_parameters::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// Describes the weights of the dispatchables exposed by this pallet.
        type WeightInfo: WeightInfo;
        /// A type used to get an X25519 key for a given account ID.
        type KeyProvider: entropy_shared::X25519KeyProvider<Self::AccountId>;
        /// A type used to describe a queue of attestations.
        type AttestationQueue: entropy_shared::AttestationQueue<Self::AccountId>;
    }

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub initial_pending_attestations: Vec<(T::AccountId, [u8; 32])>,
        pub initial_attestation_requests: Vec<(BlockNumberFor<T>, Vec<Vec<u8>>)>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            for (account_id, nonce) in &self.initial_pending_attestations {
                PendingAttestations::<T>::insert(account_id, nonce);
            }
            for (block_number, account_ids) in &self.initial_attestation_requests {
                AttestationRequests::<T>::insert(block_number, account_ids);
            }
        }
    }

    /// A map of TSS Account ID to quote nonce for pending attestations
    #[pallet::storage]
    #[pallet::getter(fn pending_attestations)]
    pub type PendingAttestations<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, Nonce, OptionQuery>;

    /// A mapping between block numbers and TSS nodes for who we want to make a request for
    /// attestation, used to make attestation requests via an offchain worker
    #[pallet::storage]
    #[pallet::getter(fn attestation_requests)]
    pub type AttestationRequests<T: Config> =
        StorageMap<_, Blake2_128Concat, BlockNumberFor<T>, Vec<Vec<u8>>, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        AttestationMade,
    }

    /// Errors related to the attestation pallet
    #[pallet::error]
    pub enum Error<T> {
        /// Quote could not be parsed or verified
        BadQuote,
        /// Attestation extrinsic submitted when not requested
        UnexpectedAttestation,
        /// Hashed input data does not match what was expected
        IncorrectInputData,
        /// The given account doesn't have a registered X25519 public key.
        NoX25519KeyForAccount,
        /// Unacceptable VM image running
        BadMrtdValue,
        /// Cannot decode verifying key (PCK)
        CannotDecodeVerifyingKey,
        /// Could not verify PCK signature
        PckVerification,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// A TDX quote given in response to an attestation request.
        /// The quote format is specified in:
        /// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
        #[pallet::call_index(0)]
        #[pallet::weight({
            <T as Config>::WeightInfo::attest()
        })]
        pub fn attest(origin: OriginFor<T>, quote: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Check that we were expecting a quote from this validator by getting the associated
            // nonce from PendingAttestations.
            let nonce =
                PendingAttestations::<T>::get(&who).ok_or(Error::<T>::UnexpectedAttestation)?;

            // Parse the quote (which internally verifies the attestation key signature)
            let quote = Quote::from_bytes(&quote).map_err(|_| Error::<T>::BadQuote)?;

            // Get associated x25519 public key from staking pallet
            let x25519_public_key =
                T::KeyProvider::x25519_public_key(&who).ok_or(Error::<T>::NoX25519KeyForAccount)?;

            // Get associated server info from staking pallet
            // let server_info = {
            //     let stash_account = pallet_staking_extension::Pallet::<T>::threshold_to_stash(&who)
            //         .ok_or(Error::<T>::NoStashAccount)?;
            //     pallet_staking_extension::Pallet::<T>::threshold_server(&stash_account)
            //         .ok_or(Error::<T>::NoServerInfo)?
            // };

            // Get current block number
            let block_number: u32 = {
                let block_number = <frame_system::Pallet<T>>::block_number();
                BlockNumberFor::<T>::try_into(block_number).unwrap_or_default()
            };

            // Check report input data matches the nonce, TSS details and block number
            let expected_input_data =
                QuoteInputData::new(&who, server_info.x25519_public_key, nonce, block_number);
            ensure!(
                quote.report_input_data() == expected_input_data.0,
                Error::<T>::IncorrectInputData
            );

            // Check build-time measurement matches a current-supported release of entropy-tss
            let mrtd_value = BoundedVec::try_from(quote.mrtd().to_vec())
                .map_err(|_| Error::<T>::BadMrtdValue)?;
            let accepted_mrtd_values = pallet_parameters::Pallet::<T>::accepted_mrtd_values();
            ensure!(accepted_mrtd_values.contains(&mrtd_value), Error::<T>::BadMrtdValue);

            // Check that the attestation public key is signed with the PCK
            let provisioning_certification_key = decode_verifying_key(
                &server_info
                    .provisioning_certification_key
                    .to_vec()
                    .try_into()
                    .map_err(|_| Error::<T>::CannotDecodeVerifyingKey)?,
            )
            .map_err(|_| Error::<T>::CannotDecodeVerifyingKey)?;
            quote
                .verify_with_pck(provisioning_certification_key)
                .map_err(|_| Error::<T>::PckVerification)?;

            PendingAttestations::<T>::remove(&who);
            T::AttestationQueue::confirm_attestation(&who);

            // TODO #982 If anything fails, don't just return an error - do something mean

            Self::deposit_event(Event::AttestationMade);

            Ok(())
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(now: BlockNumberFor<T>) -> Weight {
            let pending_validators = T::AttestationQueue::pending_attestations();
            let num_pending_attestations = pending_validators.len() as u32;
            let mut requests = AttestationRequests::<T>::get(now).unwrap_or_default();

            for account_id in pending_validators {
                let nonce = [0; 32]; // TODO (Nando): Fill this out properly
                PendingAttestations::<T>::insert(&account_id, nonce);
                requests.push(account_id.encode());
            }

            AttestationRequests::<T>::insert(now, requests);

            <T as Config>::WeightInfo::on_initialize(num_pending_attestations)
        }
    }
}
