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

// use frame_support::{assert_noop, assert_ok, traits::Currency};
// use pallet_balances::Error as BalancesError;
// use sp_runtime::traits::Hash;
//
use crate::mock::*;

#[test]
fn attest() {
    new_test_ext().execute_with(|| {
        let nonce = Attestation::pending_attestations(0).unwrap();
        assert_eq!(nonce, [0; 32]);
    })
}
