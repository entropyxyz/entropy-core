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
    use entropy_shared::{AttestationHandler, QuoteContext, QuoteInputData};
    use frame_support::pallet_prelude::*;
    use frame_support::traits::Randomness;
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::TrailingZeroInput;
    use sp_std::vec::Vec;

    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaCha20Rng, ChaChaRng,
    };
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
        /// Something that provides randomness in the runtime.
        type Randomness: Randomness<Self::Hash, BlockNumberFor<Self>>;
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
        AttestationIssued(Vec<u8>, BlockNumberFor<T>),
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
        /// The given account doesn't have a registered provisioning certification key.
        NoPCKForAccount,
        /// Unacceptable VM image running
        BadMrtdValue,
        /// Cannot decode verifying key (PCK)
        CannotDecodeVerifyingKey,
        /// Could not verify PCK signature
        PckVerification,
        /// There's an existing attestation request for this account ID.
        OutstandingAttestationRequest,
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
        pub fn attest(origin: OriginFor<T>, _quote: Vec<u8>) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            Self::deposit_event(Event::AttestationMade);

            Ok(())
        }

        /// Indicates to the chain that the caller wants to make an attestation.
        ///
        /// Once the chain is aware of this request, other extrinsics will be able to determine
        /// whether or not the caller has provided a valid attestation.
        #[pallet::call_index(1)]
        #[pallet::weight({
            <T as Config>::WeightInfo::request_attestation()
        })]
        pub fn request_attestation(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // We only want one pending attestation request per account.
            ensure!(
                !PendingAttestations::<T>::contains_key(&who),
                Error::<T>::OutstandingAttestationRequest
            );

            let mut nonce = [0; 32];
            Self::get_randomness().fill_bytes(&mut nonce[..]);
            Self::request_quote(&who, nonce);

            let block_number = <frame_system::Pallet<T>>::block_number();
            Self::deposit_event(Event::AttestationIssued(nonce.to_vec(), block_number));

            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn get_randomness() -> ChaCha20Rng {
            let phrase = b"quote_creation";
            // TODO: Is randomness freshness an issue here
            // https://github.com/paritytech/substrate/issues/8312
            let (seed, _) = T::Randomness::random(phrase);
            // seed needs to be guaranteed to be 32 bytes.
            let seed = <[u8; 32]>::decode(&mut TrailingZeroInput::new(seed.as_ref()))
                .expect("input is padded with zeroes; qed");
            ChaChaRng::from_seed(seed)
        }
    }

    impl<T: Config> entropy_shared::AttestationHandler<T::AccountId> for Pallet<T> {
        fn verify_quote(
            attestee: &T::AccountId,
            x25519_public_key: entropy_shared::X25519PublicKey,
            provisioning_certification_key: entropy_shared::BoundedVecEncodedVerifyingKey,
            quote: Vec<u8>,
            context: QuoteContext,
        ) -> Result<(), DispatchError> {
            // Check that we were expecting a quote from this validator by getting the associated
            // nonce from PendingAttestations.
            let nonce =
                PendingAttestations::<T>::get(attestee).ok_or(Error::<T>::UnexpectedAttestation)?;

            // Parse the quote (which internally verifies the attestation key signature)
            let quote = Quote::from_bytes(&quote).map_err(|_| Error::<T>::BadQuote)?;

            // Check report input data matches the nonce, TSS details and block number
            let expected_input_data =
                QuoteInputData::new(attestee, x25519_public_key, nonce, context);
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
                &provisioning_certification_key
                    .to_vec()
                    .try_into()
                    .map_err(|_| Error::<T>::CannotDecodeVerifyingKey)?,
            )
            .map_err(|_| Error::<T>::CannotDecodeVerifyingKey)?;

            quote
                .verify_with_pck(provisioning_certification_key)
                .map_err(|_| Error::<T>::PckVerification)?;

            PendingAttestations::<T>::remove(attestee);

            // TODO #982 If anything fails, don't just return an error - do something mean

            Ok(())
        }

        fn request_quote(who: &T::AccountId, nonce: [u8; 32]) {
            PendingAttestations::<T>::insert(who, nonce)
        }
    }
}
