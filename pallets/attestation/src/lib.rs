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

#![cfg_attr(not(feature = "std"), no_std)]
pub use pallet::*;

// #[cfg(feature = "runtime-benchmarks")]
// pub mod benchmarking;

// pub mod weights;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use entropy_shared::QuoteInputData;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use tdx_quote::Quote;

    // pub use crate::weights::WeightInfo;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_staking_extension::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
    }

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub initial_pending_attestations: Vec<(T::AccountId, [u8; 32])>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            for (account_id, nonce) in &self.initial_pending_attestations {
                PendingAttestations::<T>::insert(account_id, nonce);
            }
        }
    }

    /// A map of TSS account id to quote nonce for pending attestations
    #[pallet::storage]
    #[pallet::getter(fn pending_attestations)]
    pub type PendingAttestations<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, [u8; 32], OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        AttestationMade,
    }

    #[pallet::error]
    pub enum Error<T> {
        BadQuote,
        UnexpectedAttestation,
        IncorrectInputData,
        NoStashAccount,
        NoServerInfo,
    }

    // Add hooks to define some logic that should be executed
    // in a specific context, for example on_initialize.
    //  #[pallet::hooks]
    //  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> { ... }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight({100})]
        pub fn attest(origin: OriginFor<T>, quote: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            // Check that we were expecting a quote from this validator by getting the associated
            // nonce from PendingAttestations.
            let nonce =
                PendingAttestations::<T>::get(&who).ok_or(Error::<T>::UnexpectedAttestation)?;

            // Parse the quote (which internally verifies the signature)
            let quote = Quote::from_bytes(&quote).map_err(|_| Error::<T>::BadQuote)?;

            // Get associated x25519 public key from staking pallet
            let x25519_public_key = {
                let stash_account = pallet_staking_extension::Pallet::<T>::threshold_to_stash(&who)
                    .ok_or(Error::<T>::NoStashAccount)?;
                let server_info =
                    pallet_staking_extension::Pallet::<T>::threshold_server(&stash_account)
                        .ok_or(Error::<T>::NoServerInfo)?;
                server_info.x25519_public_key
            };

            // Get current block number
            let block_number: u32 = {
                let block_number = <frame_system::Pallet<T>>::block_number();
                BlockNumberFor::<T>::try_into(block_number).unwrap_or_default()
            };

            // TODO this should be `who` but not sure how to convert it to [u8; 32] in a way that
            // will work with the mock setup
            let tss_account_id = [0; 32];

            // Check report input data matches the nonce, TSS details and block number
            let expected_input_data =
                QuoteInputData::new(tss_account_id, x25519_public_key, nonce, block_number);
            ensure!(
                quote.report_input_data() == expected_input_data.0,
                Error::<T>::IncorrectInputData
            );

            // Remove the entry from PendingAttestations
            PendingAttestations::<T>::remove(&who);

            // TODO Check measurements match current release of entropy-tss
            let _mrtd = quote.mrtd();

            // TODO Check that the attestation public key matches that from PCK certificate
            let _attestation_key = quote.attestation_key;

            // TODO If anything fails, don't just return an error - do something mean

            Self::deposit_event(Event::AttestationMade);
            Ok(())
        }
    }
}