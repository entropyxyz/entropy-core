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

use frame_benchmarking::v2::*;
use frame_system::{EventRecord, RawOrigin};
use sp_std::vec;

use super::*;
#[allow(unused)]
use crate::Pallet as Outtie;

const NULL_ARR: [u8; 32] = [0; 32];

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len() - 1];
    assert_eq!(event, &system_event);
}

#[benchmarks]
mod benchmarks {
    use super::*;
    #[benchmark]
    fn add_box() {
        let caller: T::AccountId = whitelisted_caller();
        let x25519_public_key = NULL_ARR;
        let endpoint = vec![];

        let server_info = OuttieServerInfo { x25519_public_key, endpoint };
        #[extrinsic_call]
        _(RawOrigin::Signed(caller.clone()), server_info.clone());

        assert_last_event::<T>(Event::<T>::BoxAdded { box_account: caller, server_info }.into());
    }
    impl_benchmark_test_suite!(Outtie, crate::mock::new_test_ext(), crate::mock::Test);
}
