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
use frame_support::assert_ok;
use rand_core::OsRng;

const ATTESTEE: u64 = 0;

#[test]
fn attest() {
    new_test_ext().execute_with(|| {
        let nonce = Attestation::pending_attestations(ATTESTEE).unwrap();
        assert_eq!(nonce, [0; 32]);

        let signing_key = tdx_quote::SigningKey::random(&mut OsRng);
        // let signing_key = tdx_quote::SigningKey::from_slice(&[0; 32]).unwrap();

        let input_data = entropy_shared::QuoteInputData::new(
            [0; 32], // Account ID
            [0; 32], // x25519 public key
            nonce, 0, // Block number
        );

        let quote = tdx_quote::Quote::mock(signing_key.clone(), input_data.0);
        assert_ok!(
            Attestation::attest(RuntimeOrigin::signed(ATTESTEE), quote.as_bytes().to_vec(),)
        );
    })
}
