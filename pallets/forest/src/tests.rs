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

//! Unit tests for the forest pallet.

#![cfg(test)]

use super::*;
use crate::ForestServerInfo;
use frame_support::{assert_noop, assert_ok};
use mock::*;

const NULL_ARR: [u8; 32] = [0; 32];

#[test]
fn add_tree() {
    new_test_ext().execute_with(|| {
        let mut server_info = ForestServerInfo {
            x25519_public_key: NULL_ARR,
            endpoint: vec![20],
            tdx_quote: VALID_QUOTE.to_vec(),
        };

        assert_ok!(Forest::add_tree(RuntimeOrigin::signed(1), server_info.clone(),));

        assert_noop!(
            Forest::add_tree(RuntimeOrigin::signed(1), server_info.clone()),
            Error::<Test>::TreeAccountAlreadyExists
        );

        server_info.tdx_quote = INVALID_QUOTE.to_vec();
        assert_noop!(
            Forest::add_tree(RuntimeOrigin::signed(2), server_info.clone()),
            Error::<Test>::BadQuote
        );

        server_info.tdx_quote = VALID_QUOTE.to_vec();
        server_info.endpoint = [20; (crate::tests::MaxEndpointLength::get() + 1) as usize].to_vec();
        assert_noop!(
            Forest::add_tree(RuntimeOrigin::signed(3), server_info),
            Error::<Test>::EndpointTooLong
        );
    });
}
