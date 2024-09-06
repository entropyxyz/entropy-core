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

// //! Benchmarking setup for pallet-propgation

use super::*;

#[allow(unused)]
use crate::Pallet as Propgation;
use frame_benchmarking::benchmarks;
use frame_support::traits::OnInitialize;
use pallet_staking_extension::RefreshInfo;
use scale_info::prelude::vec;

benchmarks! {
  on_initialize {
    let block_number = 50u32;

    <pallet_staking_extension::ProactiveRefresh<T>>::put(RefreshInfo {
        validators_info: vec![],
        proactive_refresh_keys: vec![vec![10]]
    });
  }: {
    Propgation::<T>::on_initialize(block_number.into());
    } verify {
    assert_eq!(<pallet_staking_extension::ProactiveRefresh<T>>::get().proactive_refresh_keys.len(), 0);
    }

  impl_benchmark_test_suite!(Propgation, crate::mock::new_test_ext(), crate::mock::Test);
}
