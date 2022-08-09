use frame_support::traits::{ConstU16, ConstU64};

use sp_core::H256;
use sp_runtime::{
  testing::Header,
  traits::{BlakeTwo256, IdentityLookup},
};

use crate as pallet_free_tx;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

#[frame_support::pallet]
pub mod pallet_example {
  use frame_support::pallet_prelude::*;
  use frame_system::pallet_prelude::*;

  /// Configure the pallet by specifying the parameters and types on which it depends.
  #[pallet::config]
  pub trait Config: frame_system::Config {
    /// Because this pallet emits events, it depends on the runtime's definition of an event.
    type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
  }

  #[pallet::pallet]
  #[pallet::generate_store(pub(super) trait Store)]
  pub struct Pallet<T>(_);

  // The pallet's runtime storage items.
  // https://docs.substrate.io/main-docs/build/runtime-storage/
  #[pallet::storage]
  #[pallet::getter(fn something)]
  // Learn more about declaring storage items:
  // https://docs.substrate.io/main-docs/build/runtime-storage/#declaring-storage-items
  pub type Something<T> = StorageValue<_, u32>;

  // Pallets use events to inform users when important changes are made.
  // https://docs.substrate.io/main-docs/build/events-errors/
  #[pallet::event]
  #[pallet::generate_deposit(pub(super) fn deposit_event)]
  pub enum Event<T: Config> {
    /// Event documentation should end with an array that provides descriptive names for event
    /// parameters. [something, who]
    SomethingStored(u32, T::AccountId),
  }

  // Errors inform users that something went wrong.
  #[pallet::error]
  pub enum Error<T> {
    /// Error names should be descriptive.
    NoneValue,
    /// Errors should have helpful documentation associated with them.
    StorageOverflow,
  }

  // Dispatchable functions allows users to interact with the pallet and invoke state changes.
  // These functions materialize as "extrinsics", which are often compared to transactions.
  // Dispatchable functions must be annotated with a weight and must return a DispatchResult.
  #[pallet::call]
  impl<T: Config> Pallet<T> {
    /// An example dispatchable that takes a singles value as a parameter, writes the value to
    /// storage and emits an event. This function must be dispatched by a signed extrinsic.
    #[pallet::weight(10_000 + T::DbWeight::get().writes(1))]
    pub fn do_something(origin: OriginFor<T>, something: u32) -> DispatchResult {
      // Check that the extrinsic was signed and get the signer.
      // This function will return an error if the extrinsic is not signed.
      // https://docs.substrate.io/main-docs/build/origins/
      let who = ensure_signed(origin)?;

      // Update storage.
      <Something<T>>::put(something);

      // Emit an event.
      Self::deposit_event(Event::SomethingStored(something, who));
      // Return a successful DispatchResultWithPostInfo
      Ok(())
    }

    /// An example dispatchable that may throw a custom error.
    #[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
    pub fn cause_error(origin: OriginFor<T>) -> DispatchResult {
      let _who = ensure_signed(origin)?;

      // Read a value from storage.
      match <Something<T>>::get() {
        // Return an error if the value has not been set.
        None => Err(Error::<T>::NoneValue.into()),
        Some(old) => {
          // Increment the value read from storage; will error in the event of overflow.
          let new = old.checked_add(1).ok_or(Error::<T>::StorageOverflow)?;
          // Update the value in storage with the incremented result.
          <Something<T>>::put(new);
          Ok(())
        },
      }
    }
  }
}

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
  pub enum Test where
    Block = Block,
    NodeBlock = Block,
    UncheckedExtrinsic = UncheckedExtrinsic,
  {
    System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
    Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
    Example: pallet_example::{Pallet, Call, Storage, Event<T>},
    FreeTx: pallet_free_tx::{Pallet, Call, Storage, Event<T>},
  }
);

impl frame_system::Config for Test {
  type AccountData = pallet_balances::AccountData<u64>;
  type AccountId = u64;
  type BaseCallFilter = frame_support::traits::Everything;
  type BlockHashCount = ConstU64<250>;
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
  type SS58Prefix = ConstU16<42>;
  type SystemWeightInfo = ();
  type Version = ();
}

impl pallet_balances::Config for Test {
  type AccountStore = System;
  type Balance = u64;
  type DustRemoval = ();
  type Event = Event;
  type ExistentialDeposit = ConstU64<1>;
  type MaxLocks = ();
  type MaxReserves = ();
  type ReserveIdentifier = [u8; 8];
  type WeightInfo = ();
}

impl pallet_example::Config for Test {
  type Event = Event;
}

impl pallet_free_tx::Config for Test {
  type Call = Call;
  type Event = Event;
}

pub type ExampleCall = pallet_example::Call<Test>;

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
  let mut t = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();
  pallet_balances::GenesisConfig::<Test> {
    balances: vec![(1, 10), (2, 10), (3, 10), (4, 10), (5, 2)],
  }
  .assimilate_storage(&mut t)
  .unwrap();
  let mut ext = sp_io::TestExternalities::new(t);
  ext.execute_with(|| System::set_block_number(1));
  ext
}
