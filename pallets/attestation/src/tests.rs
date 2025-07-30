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

use crate::{mock::*, GlobalNonces};
use entropy_shared::attestation::{
    AttestationHandler, QuoteContext, QuoteInputData, VerifyQuoteError,
};
use frame_support::{assert_noop, assert_ok, traits::OnInitialize};
use rand_core::OsRng;

const ATTESTEE: u64 = 0;

#[test]
fn verify_quote_works() {
    new_test_ext().execute_with(|| {
        // We start with an existing pending attestation at genesis - get its nonce
        let nonce = Attestation::pending_attestations(ATTESTEE).unwrap();
        assert_eq!(nonce, [0; 32]);

        let attestation_key = tdx_quote::SigningKey::random(&mut OsRng);
        let pck = tdx_quote::SigningKey::from_bytes(&PCK.into()).unwrap();
        let pck_encoded = tdx_quote::encode_verifying_key(pck.verifying_key()).unwrap();

        let x25519_public_key = [0; 32];

        let input_data = QuoteInputData::new(
            ATTESTEE, // TSS Account ID
            x25519_public_key,
            nonce,
            QuoteContext::Validate,
        );

        let quote = tdx_quote::Quote::mock(
            attestation_key.clone(),
            pck,
            input_data.0,
            pck_encoded.to_vec(),
        );
        assert_ok!(Attestation::verify_quote(
            &ATTESTEE,
            x25519_public_key,
            quote.as_bytes().to_vec(),
            QuoteContext::Validate,
            None,
        ));
    })
}
#[test]
fn verify_quote_works_global_nonce() {
    new_test_ext().execute_with(|| {
        let nonce = [0; 32];

        let attestation_key = tdx_quote::SigningKey::random(&mut OsRng);
        let pck = tdx_quote::SigningKey::from_bytes(&PCK.into()).unwrap();
        let pck_encoded = tdx_quote::encode_verifying_key(pck.verifying_key()).unwrap();

        let x25519_public_key = [0; 32];

        let input_data = QuoteInputData::new(
            ATTESTEE, // TSS Account ID
            x25519_public_key,
            nonce,
            QuoteContext::Validate,
        );

        let quote = tdx_quote::Quote::mock(
            attestation_key.clone(),
            pck,
            input_data.0,
            pck_encoded.to_vec(),
        );
        // not a global nonce so fails
        assert_noop!(
            Attestation::verify_quote(
                &ATTESTEE,
                x25519_public_key,
                quote.as_bytes().to_vec(),
                QuoteContext::Validate,
                Some(nonce.clone()),
            ),
            VerifyQuoteError::NotGlobalNonce,
        );

        GlobalNonces::<Test>::put(vec![nonce.clone()]);

        assert_ok!(Attestation::verify_quote(
            &ATTESTEE,
            x25519_public_key,
            quote.as_bytes().to_vec(),
            QuoteContext::Validate,
            Some(nonce.clone()),
        ));
    })
}

#[test]
fn verify_quote_fails_with_mismatched_input_data() {
    new_test_ext().execute_with(|| {
        // We start with an existing pending attestation at genesis - get it's nonce
        let nonce = Attestation::pending_attestations(ATTESTEE).unwrap();
        assert_eq!(nonce, [0; 32]);

        let attestation_key = tdx_quote::SigningKey::random(&mut OsRng);
        let pck = tdx_quote::SigningKey::from_bytes(&PCK.into()).unwrap();
        let pck_encoded = tdx_quote::encode_verifying_key(pck.verifying_key()).unwrap();

        let x25519_public_key = [0; 32];

        let input_data = QuoteInputData::new(
            ATTESTEE, // TSS Account ID
            x25519_public_key,
            nonce,
            QuoteContext::Validate,
        );

        let quote = tdx_quote::Quote::mock(
            attestation_key.clone(),
            pck.clone(),
            input_data.0,
            pck_encoded.to_vec(),
        );

        // We want to test that our quote verification fails if we commit to data that doesn't match
        // the `quote`.
        let mismatched_attestee = ATTESTEE + 1;
        assert_noop!(
            Attestation::verify_quote(
                &mismatched_attestee,
                x25519_public_key,
                quote.as_bytes().to_vec(),
                QuoteContext::Validate,
                None,
            ),
            VerifyQuoteError::UnexpectedAttestation,
        );

        // The X25519 public key we're comitting to here doesn't match what we used to generate the
        // quote.
        let mismatched_x25519_public_key = [1; 32];
        assert_noop!(
            Attestation::verify_quote(
                &ATTESTEE,
                mismatched_x25519_public_key,
                quote.as_bytes().to_vec(),
                QuoteContext::Validate,
                None,
            ),
            VerifyQuoteError::IncorrectInputData,
        );
    })
}

#[test]
fn global_nonce_test() {
    new_test_ext().execute_with(|| {
        <Attestation as OnInitialize<u64>>::on_initialize(0);
        let mut global_nonces = Attestation::global_nonces();
        assert_eq!(global_nonces.len(), 1);

        <Attestation as OnInitialize<u64>>::on_initialize(1);
        global_nonces = Attestation::global_nonces();
        assert_eq!(global_nonces.len(), 2);

        <Attestation as OnInitialize<u64>>::on_initialize(3);
        global_nonces = Attestation::global_nonces();
        assert_eq!(global_nonces.len(), 3);

        <Attestation as OnInitialize<u64>>::on_initialize(4);
        global_nonces = Attestation::global_nonces();
        assert_eq!(global_nonces.len(), 3);
    })
}
