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
use frame_system::EventRecord;
use sp_std::vec;

use super::*;
#[allow(unused)]
use crate::Pallet as Parameters;

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
    fn change_request_limit() {
        let origin = T::UpdateOrigin::try_successful_origin().unwrap();

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, 15.clone());

        assert_last_event::<T>(Event::RequestLimitChanged { request_limit: 15 }.into());
    }

    #[benchmark]
    fn change_max_instructions_per_programs() {
        let origin = T::UpdateOrigin::try_successful_origin().unwrap();

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, 15.clone());

        assert_last_event::<T>(
            Event::MaxInstructionsPerProgramsChanged { max_instructions_per_programs: 15 }.into(),
        );
    }

    #[benchmark]
    fn change_signers_info() {
        let origin = T::UpdateOrigin::try_successful_origin().unwrap();
        pallet_session::CurrentIndex::<T>::put(1);

        let SignersSize {
            threshold: old_threshold,
            total_signers: old_total_signers,
            last_session_change: old_last_session_change,
        } = SignersInfo::<T>::get();

        let signer_info = SignersSize {
            total_signers: old_total_signers + 1,
            threshold: old_threshold + 1,
            last_session_change: old_last_session_change + 1,
        };

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, signer_info.total_signers, signer_info.threshold);

        assert_last_event::<T>(Event::SignerInfoChanged { signer_info }.into());
    }

    #[benchmark]
    fn change_accepted_measurement_values() {
        let origin = T::UpdateOrigin::try_successful_origin().unwrap();
        let accepted_measurement_values = vec![
            (
                SupportedCvmServices::EntropyTss,
                vec![BoundedVec::try_from([0; 32].to_vec()).unwrap()],
            ),
            (
                SupportedCvmServices::TreeService,
                vec![BoundedVec::try_from([1; 32].to_vec()).unwrap()],
            ),
        ];

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, accepted_measurement_values.clone());

        assert_last_event::<T>(
            Event::AcceptedMeasurementValuesChanged { accepted_measurement_values }.into(),
        );
    }

    impl_benchmark_test_suite!(Parameters, crate::mock::new_test_ext(), crate::mock::Runtime);
}
