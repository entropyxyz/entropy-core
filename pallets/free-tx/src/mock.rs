use frame_support::{
  pallet_prelude::GenesisBuild,
  traits::{ConstU16, ConstU64},
};
use sp_core::H256;
use sp_runtime::{
  testing::Header,
  traits::{BlakeTwo256, IdentityLookup},
};

use crate as pallet_free_tx;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
  pub enum Test where
    Block = Block,
    NodeBlock = Block,
    UncheckedExtrinsic = UncheckedExtrinsic,
  {
    System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
    Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
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

impl pallet_free_tx::Config for Test {
  type Call = Call;
  type Event = Event;
  type WeightInfo = ();
}

pub type SystemCall = frame_system::Call<Test>;

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
  let mut t = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();
  pallet_balances::GenesisConfig::<Test> {
    balances: vec![(1, 10), (2, 10), (3, 10), (4, 10), (5, 2)],
  }
  .assimilate_storage(&mut t)
  .unwrap();

  <pallet_free_tx::GenesisConfig as GenesisBuild<Test>>::assimilate_storage(
    &pallet_free_tx::GenesisConfig { free_calls_left: 1 },
    &mut t,
  )
  .unwrap();

  let mut ext = sp_io::TestExternalities::new(t);
  ext.execute_with(|| System::set_block_number(1));
  ext
}
