// Copyright (C) 2023 Entropy Cryptography Inc.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// //! Benchmarking setup for pallet-oracle

use super::*;

#[allow(unused)]
use crate::Pallet as Oracle;
use frame_benchmarking::benchmarks;

benchmarks! {
  on_initialize {
  }: {
    Oracle::<T>::on_initialize(50u32.into());
    } verify {
    assert_eq!(OracleData::<T>::get(BoundedVec::try_from("block_number_entropy".encode()).unwrap()).unwrap().oracle_data[0], 50);
    }

  impl_benchmark_test_suite!(Oracle, crate::mock::new_test_ext(), crate::mock::Test);
}
