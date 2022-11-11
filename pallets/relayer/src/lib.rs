//! # Relayer Pallet
//!
//!
//! ## Overview
//!
//! Allows a user to ask to sign, register with the network and allows a node to confirm
//! signing was completed properly.
//!
//! ### Public Functions
//!
//! prep_transaction - declares intent to sign, this gets relayed to thereshold network
//! register - register's a user and that they have created and distributed entropy shards
//! confirm_done - allows a node to confirm signing has happened and if a failure occured
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::new_without_default)]
#![allow(clippy::derive_partial_eq_without_eq)] // Substrate confuses clippy
pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub mod weights;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::{
        dispatch::{DispatchResult, Pays},
        inherent::Vec,
        pallet_prelude::*,
        traits::IsSubType,
    };
    use frame_system::pallet_prelude::*;
    use helpers::unwrap_or_return;
    use scale_info::TypeInfo;
    use sp_runtime::{
        traits::{Convert, DispatchInfoOf, Saturating, SignedExtension},
        transaction_validity::{TransactionValidity, TransactionValidityError, ValidTransaction},
    };
    use sp_std::{fmt::Debug, vec};
    use substrate_common::{Message, SigRequest, SIGNING_PARTY_SIZE};

    pub use crate::weights::WeightInfo;
    /// Configure the pallet by specifying the parameters and types on which it depends.
    #[pallet::config]
    pub trait Config:
        frame_system::Config + pallet_authorship::Config + pallet_staking_extension::Config
    {
        /// Because this pallet emits events, it depends on the runtime's definition of an event.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type PruneBlock: Get<Self::BlockNumber>;
        type SigningPartySize: Get<usize>;
        /// The weight information of this pallet.
        type WeightInfo: WeightInfo;
    }

    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
    pub struct RegisteringDetails {
        pub is_registering: bool,
        pub confirmations: Vec<u8>,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(block_number: T::BlockNumber) -> Weight {
            let target_block = block_number.saturating_sub(2u32.into());
            let messages = Messages::<T>::take(target_block);

            let prune_block = block_number.saturating_sub(T::PruneBlock::get());
            let prune_failures = Self::failures(prune_block);
            let is_prune_failures = prune_failures.is_some();
            Self::move_active_to_pending(
                target_block,
                prune_block,
                messages.clone(),
                is_prune_failures,
            );
            Self::note_responsibility(block_number);
            if is_prune_failures {
                <T as Config>::WeightInfo::move_active_to_pending_failure(messages.len() as u64)
            } else {
                <T as Config>::WeightInfo::move_active_to_pending_no_failure(messages.len() as u64)
            }
        }
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn messages)]
    pub type Messages<T: Config> =
        StorageMap<_, Blake2_128Concat, T::BlockNumber, Vec<Message>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn pending)]
    pub type Pending<T: Config> =
        StorageMap<_, Blake2_128Concat, T::BlockNumber, Vec<Message>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn failures)]
    pub type Failures<T: Config> =
        StorageMap<_, Blake2_128Concat, T::BlockNumber, Vec<u32>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn unresponsive)]
    pub type Unresponsive<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u32, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn responsibility)]
    pub type Responsibility<T: Config> =
        StorageMap<_, Blake2_128Concat, T::BlockNumber, T::AccountId, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn registering)]
    pub type Registering<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, RegisteringDetails, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn registered)]
    pub type Registered<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, bool, OptionQuery>;

    // Pallets use events to inform users when important changes are made.
    // https://substrate.dev/docs/en/knowledgebase/runtime/events
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A transaction has been propagated to the network. [who]
        TransactionPropagated(T::AccountId),
        /// An account has signaled to be registered. [who]
        SignalRegister(T::AccountId),
        /// An account has been registered. [who, signing_group]
        AccountRegistering(T::AccountId, u8),
        /// An account has been registered. [who]
        AccountRegistered(T::AccountId),
        /// An account has been registered. [who, block_number, failures]
        ConfirmedDone(T::AccountId, T::BlockNumber, Vec<u32>),
    }

    // Errors inform users that something went wrong.
    #[pallet::error]
    pub enum Error<T> {
        Test,
        NotYourResponsibility,
        NoResponsibility,
        AlreadySubmitted,
        NoThresholdKey,
        NotRegistering,
        InvalidSubgroup,
        AlreadyConfirmed,
        NotInSigningGroup,
        InvalidValidatorId,
        IpAddressError,
        SigningGroupError,
    }

    /// Allows a user to kick off signing process
    /// `sig_request`: signature request for user
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight((<T as Config>::WeightInfo::prep_transaction(), Pays::No))]
        pub fn prep_transaction(origin: OriginFor<T>, sig_request: SigRequest) -> DispatchResult {
            log::warn!("relayer::prep_transaction::sig_request: {:?}", sig_request);
            let who = ensure_signed(origin)?;
            let ip_addresses = Self::get_ip_addresses()?;
            let message = Message { sig_request, account: who.encode(), ip_addresses };
            let block_number = <frame_system::Pallet<T>>::block_number();
            Messages::<T>::try_mutate(block_number, |request| -> Result<_, DispatchError> {
                request.push(message);
                Ok(())
            })?;

            Self::deposit_event(Event::TransactionPropagated(who));
            Ok(())
        }

        /// Signals a user wants to register an account with the entropy-network
        /// accounts are identified by the public group key of the user.
        #[pallet::weight(<T as Config>::WeightInfo::register())]
        pub fn register(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let registering_info =
                RegisteringDetails { is_registering: true, confirmations: vec![] };
            Registering::<T>::insert(&who, registering_info);
            Self::deposit_event(Event::SignalRegister(who));
            Ok(())
        }

        // TODO(Jake): This is an insecure way to do a free transaction.
        // secure it, please. :)
        #[pallet::weight((T::DbWeight::get().writes(1), Pays::No))]
        pub fn confirm_register(
            origin: OriginFor<T>,
            registerer: T::AccountId,
            signing_subgroup: u8,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let stash_key = pallet_staking_extension::Pallet::<T>::threshold_to_stash(&who)
                .ok_or(Error::<T>::NoThresholdKey)?;
            let mut registering_info =
                Self::registering(&registerer).ok_or(Error::<T>::NotRegistering)?;
            ensure!(
                !registering_info.confirmations.contains(&signing_subgroup),
                Error::<T>::AlreadyConfirmed
            );
            let signing_subgroup_addresses =
                pallet_staking_extension::Pallet::<T>::signing_groups(signing_subgroup)
                    .ok_or(Error::<T>::InvalidSubgroup)?;

            let validator_id_res = <T as pallet_session::Config>::ValidatorIdOf::convert(stash_key);
            ensure!(validator_id_res.is_some(), Error::<T>::InvalidValidatorId);
            let validator_id = validator_id_res.unwrap();
            ensure!(
                signing_subgroup_addresses.contains(&validator_id),
                Error::<T>::NotInSigningGroup
            );
            if registering_info.confirmations.len() == T::SigningPartySize::get() - 1 {
                Registered::<T>::insert(&registerer, true);
                Registering::<T>::remove(&registerer);
                Self::deposit_event(Event::AccountRegistered(registerer));
            } else {
                registering_info.confirmations.push(signing_subgroup);
                Registering::<T>::insert(&registerer, registering_info);
                Self::deposit_event(Event::AccountRegistering(registerer, signing_subgroup));
            }
            Ok(())
        }

        /// Allows a node to signal they have completed a signing batch
        /// `block_number`: block number for signing batch
        /// `failure`: index of any failures in all sig request arrays
        #[pallet::weight((T::DbWeight::get().writes(1), Pays::No))]
        pub fn confirm_done(
            origin: OriginFor<T>,
            block_number: T::BlockNumber,
            failures: Vec<u32>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let responsibility =
                Self::responsibility(block_number).ok_or(Error::<T>::NoResponsibility)?;
            let threshold_key =
                pallet_staking_extension::Pallet::<T>::threshold_account(&responsibility)
                    .ok_or(Error::<T>::NoThresholdKey)?;
            ensure!(who == threshold_key.0, Error::<T>::NotYourResponsibility);

            let current_failures = Self::failures(block_number);

            ensure!(current_failures.is_none(), Error::<T>::AlreadySubmitted);
            Failures::<T>::insert(block_number, &failures);
            Self::deposit_event(Event::ConfirmedDone(who, block_number, failures));
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn get_ip_addresses() -> Result<Vec<Vec<u8>>, Error<T>> {
            let mut ip_addresses: Vec<Vec<u8>> = vec![];
            // TODO: JA simple hacky way to do this, get the first address from each signing group
            // need good algorithim for this
            for i in 0..SIGNING_PARTY_SIZE {
                let addresses = pallet_staking_extension::Pallet::<T>::signing_groups(i as u8)
                    .ok_or(Error::<T>::SigningGroupError)?;
                let ip_address =
                    pallet_staking_extension::Pallet::<T>::endpoint_register(&addresses[0])
                        .ok_or(Error::<T>::IpAddressError)?;
                ip_addresses.push(ip_address);
            }
            Ok(ip_addresses)
        }

        pub fn move_active_to_pending(
            target_block: T::BlockNumber,
            prune_block: T::BlockNumber,
            messages: Vec<Message>,
            is_prune_failures: bool,
        ) {
            let responsibility = unwrap_or_return!(
                Self::responsibility(target_block),
                "active to pending, responsibility warning"
            );
            if !is_prune_failures {
                Unresponsive::<T>::mutate(responsibility, |dings| *dings += 1);

            // TODO slash or point for failure then slash after pointed a few times
            // If someone is slashed they probably should reset their unresponsive dings
            // let _result = pallet_slashing::Pallet::<T>::do_offence(responsibility,
            // vec![responsibility]);
            } else {
                Failures::<T>::remove(prune_block);
                Unresponsive::<T>::remove(responsibility);
            }

            if !messages.is_empty() {
                Pending::<T>::insert(target_block, messages);
            }

            Pending::<T>::remove(prune_block);
        }

        pub fn note_responsibility(block_number: T::BlockNumber) {
            let target_block = block_number.saturating_sub(1u32.into());
            let block_author = unwrap_or_return!(
                pallet_authorship::Pallet::<T>::author(),
                "note responsibility block author warning"
            );

            Responsibility::<T>::insert(target_block, block_author);

            let prune_block = block_number.saturating_sub(T::PruneBlock::get());
            Responsibility::<T>::remove(prune_block);
        }
    }

    /// Validate `attest` calls prior to execution. Needed to avoid a DoS attack since they are
    #[derive(Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
    #[scale_info(skip_type_params(T))]
    pub struct PrevalidateRelayer<T: Config + Send + Sync>(sp_std::marker::PhantomData<T>)
    where <T as frame_system::Config>::RuntimeCall: IsSubType<Call<T>>;

    impl<T: Config + Send + Sync> Debug for PrevalidateRelayer<T>
    where <T as frame_system::Config>::RuntimeCall: IsSubType<Call<T>>
    {
        #[cfg(feature = "std")]
        fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
            write!(f, "PrevalidateRelayer")
        }

        #[cfg(not(feature = "std"))]
        fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result { Ok(()) }
    }

    impl<T: Config + Send + Sync> PrevalidateRelayer<T>
    where <T as frame_system::Config>::RuntimeCall: IsSubType<Call<T>>
    {
        /// Create new `SignedExtension` to check runtime version.
        pub fn new() -> Self { Self(sp_std::marker::PhantomData) }
    }

    impl<T: Config + Send + Sync> SignedExtension for PrevalidateRelayer<T>
    where <T as frame_system::Config>::RuntimeCall: IsSubType<Call<T>>
    {
        type AccountId = T::AccountId;
        type AdditionalSigned = ();
        type Call = <T as frame_system::Config>::RuntimeCall;
        type Pre = ();

        const IDENTIFIER: &'static str = "PrevalidateRelayer";

        fn additional_signed(&self) -> Result<Self::AdditionalSigned, TransactionValidityError> {
            Ok(())
        }

        fn pre_dispatch(
            self,
            who: &Self::AccountId,
            call: &Self::Call,
            info: &DispatchInfoOf<Self::Call>,
            len: usize,
        ) -> Result<Self::Pre, TransactionValidityError> {
            self.validate(who, call, info, len).map(|_| ())
        }

        // <weight>
        // The weight of this logic is included in the `attest` dispatchable.
        // </weight>
        fn validate(
            &self,
            who: &Self::AccountId,
            call: &Self::Call,
            _info: &DispatchInfoOf<Self::Call>,
            _len: usize,
        ) -> TransactionValidity {
            if let Some(local_call) = call.is_sub_type() {
                if let Call::prep_transaction { .. } = local_call {
                    Registered::<T>::get(who).ok_or(InvalidTransaction::Custom(1))?;
                    // TODO apply filter logic
                }

                if let Call::register { .. } = local_call {
                    // TODO ensure proof
                }

                if let Call::confirm_done { block_number, .. } = local_call {
                    let responsibility = Responsibility::<T>::get(block_number)
                        .ok_or(InvalidTransaction::Custom(2))?;
                    let threshold_key =
                        pallet_staking_extension::Pallet::<T>::threshold_account(&responsibility)
                            .ok_or(InvalidTransaction::Custom(3))?;
                    ensure!(*who == threshold_key.0, InvalidTransaction::Custom(4));
                    let current_failures = Failures::<T>::get(block_number);
                    ensure!(current_failures.is_none(), InvalidTransaction::Custom(5));
                }
            }
            Ok(ValidTransaction::default())
        }
    }
}
