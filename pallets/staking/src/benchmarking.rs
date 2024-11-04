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

//! Benchmarking setup for pallet-propgation
#![allow(unused_imports)]
use super::*;
use crate::pck::{signing_key_from_seed, MOCK_PCK_DERIVED_FROM_NULL_ARRAY};
#[allow(unused_imports)]
use crate::Pallet as Staking;
use entropy_shared::{AttestationHandler, MAX_SIGNERS};
use frame_benchmarking::{account, benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_support::{
    assert_ok, ensure,
    sp_runtime::traits::StaticLookup,
    traits::{Currency, Defensive, Get},
    BoundedVec,
};
use frame_system::{EventRecord, RawOrigin};
use pallet_parameters::{SignersInfo, SignersSize};
use pallet_staking::{
    Event as FrameStakingEvent, MaxNominationsOf, MaxValidatorsCount, Nominations,
    Pallet as FrameStaking, RewardDestination, ValidatorPrefs,
};
use sp_std::{vec, vec::Vec};

const NULL_ARR: [u8; 32] = [0; 32];
const SEED: u32 = 0;

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len() - 1];
    assert_eq!(event, &system_event);
}

fn assert_last_event_frame_staking<T: Config>(
    generic_event: <T as pallet_staking::Config>::RuntimeEvent,
) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len() - 1];
    assert_eq!(event, &system_event);
}

pub fn create_validators<T: Config>(
    count: u32,
    seed: u32,
) -> Vec<<T as pallet_session::Config>::ValidatorId> {
    let candidates =
        (0..count).map(|c| account::<T::AccountId>("validator", c, seed)).collect::<Vec<_>>();
    let mut validators = vec![];
    for who in candidates {
        let validator_id_res = <T as pallet_session::Config>::ValidatorId::try_from(who.clone())
            .or(Err(Error::<T>::InvalidValidatorId))
            .unwrap();
        validators.push(validator_id_res);
    }
    validators
}

/// Sets up a mock quote and requests an attestation in preparation for calling the `validate`
/// extrinsic
fn prepare_attestation_for_validate<T: Config>(
    threshold: T::AccountId,
    x25519_public_key: [u8; 32],
    endpoint: Vec<u8>,
    block_number: u32,
) -> (Vec<u8>, JoiningServerInfo<T::AccountId>) {
    let nonce = NULL_ARR;
    let quote = {
        let pck = signing_key_from_seed(NULL_ARR);
        /// This is a randomly generated secret p256 ECDSA key - for mocking attestation
        const ATTESTATION_KEY: [u8; 32] = [
            167, 184, 203, 130, 240, 249, 191, 129, 206, 9, 200, 29, 99, 197, 64, 81, 135, 166, 59,
            73, 31, 27, 206, 207, 69, 248, 56, 195, 64, 92, 109, 46,
        ];

        let attestation_key = tdx_quote::SigningKey::from_bytes(&ATTESTATION_KEY.into()).unwrap();

        let input_data =
            entropy_shared::QuoteInputData::new(&threshold, x25519_public_key, nonce, block_number);

        tdx_quote::Quote::mock(attestation_key.clone(), pck, input_data.0).as_bytes().to_vec()
    };

    let joining_server_info = JoiningServerInfo {
        tss_account: threshold.clone(),
        x25519_public_key,
        endpoint,
        // Since we are using the mock PckCertChainVerifier, this needs to be the same seed for
        // generating the PCK as we used to sign the quote above
        pck_certificate_chain: vec![NULL_ARR.to_vec()],
    };

    // We need to tell the attestation handler that we want a quote. This will let the system to
    // know to expect one back when we call `validate()`.
    T::AttestationHandler::request_quote(&threshold, nonce);
    (quote, joining_server_info)
}

fn prep_bond_and_validate<T: Config>(
    validate_also: bool,
    caller: T::AccountId,
    bonder: T::AccountId,
    threshold: T::AccountId,
    x25519_public_key: [u8; 32],
) {
    let reward_destination = RewardDestination::Account(caller.clone());
    let bond = <T as pallet_staking::Config>::Currency::minimum_balance() * 10u32.into();
    <T as Config>::Currency::make_free_balance_be(
        &bonder,
        <T as Config>::Currency::minimum_balance() * 10u32.into(),
    );
    assert_ok!(<FrameStaking<T>>::bond(
        RawOrigin::Signed(bonder.clone()).into(),
        bond,
        reward_destination,
    ));

    if validate_also {
        let block_number = 0;
        let endpoint = b"http://localhost:3001".to_vec();
        let (quote, joining_server_info) = prepare_attestation_for_validate::<T>(
            threshold,
            x25519_public_key,
            endpoint,
            block_number,
        );

        assert_ok!(<Staking<T>>::validate(
            RawOrigin::Signed(bonder.clone()).into(),
            ValidatorPrefs::default(),
            joining_server_info.clone(),
            quote,
        ));

        let validator_id = <T as pallet_session::Config>::ValidatorId::try_from(bonder)
            .or(Err(Error::<T>::InvalidValidatorId))
            .unwrap();

        ThresholdToStash::<T>::insert(&joining_server_info.tss_account, &validator_id);

        let server_info = ServerInfo {
            tss_account: joining_server_info.tss_account,
            x25519_public_key: joining_server_info.x25519_public_key,
            endpoint: joining_server_info.endpoint,
            provisioning_certification_key: MOCK_PCK_DERIVED_FROM_NULL_ARRAY
                .to_vec()
                .try_into()
                .unwrap(),
        };
        ThresholdServers::<T>::insert(&validator_id, server_info);
    }
}

benchmarks! {
  change_endpoint {
    let caller: T::AccountId = whitelisted_caller();
    let bonder: T::AccountId = account("bond", 0, SEED);
    let threshold: T::AccountId = account("threshold", 0, SEED);

    let endpoint = b"http://localhost:3001";
    let x25519_public_key = NULL_ARR;

    let validate_also = true;
    prep_bond_and_validate::<T>(
        validate_also,
        caller.clone(),
        bonder.clone(),
        threshold.clone(),
        x25519_public_key.clone(),
    );

    // For quote verification this needs to be the _next_ block, and right now we're at block `0`.
    let block_number = 1;
    let quote = prepare_attestation_for_validate::<T>(
        threshold,
        x25519_public_key,
        endpoint.clone().to_vec(),
        block_number,
    )
    .0;
  }:  _(RawOrigin::Signed(bonder.clone()), endpoint.to_vec(), quote)
  verify {
    assert_last_event::<T>(Event::<T>::EndpointChanged(bonder, endpoint.to_vec()).into());
  }

  change_threshold_accounts {
    let s in 0 .. MAX_SIGNERS as u32;

    let caller: T::AccountId = whitelisted_caller();
    let _bonder: T::AccountId = account("bond", 0, SEED);

    let validator_id_res = <T as pallet_session::Config>::ValidatorId::try_from(_bonder.clone())
        .or(Err(Error::<T>::InvalidValidatorId));
    let validator_id_signers = <T as pallet_session::Config>::ValidatorId::try_from(caller.clone())
        .or(Err(Error::<T>::InvalidValidatorId))
        .unwrap();
    let bonder: T::ValidatorId =
        validator_id_res.expect("Issue converting account id into validator id");

    let threshold: T::AccountId = account("threshold", 0, SEED);
    let new_threshold: T::AccountId = account("new_threshold", 0, SEED);

    let x25519_public_key: [u8; 32] = NULL_ARR;
    let endpoint = b"http://localhost:3001".to_vec();
    let pck = BoundedVec::try_from(MOCK_PCK_DERIVED_FROM_NULL_ARRAY.to_vec()).unwrap();

    let validate_also = true;
    prep_bond_and_validate::<T>(
        validate_also,
        caller.clone(),
        _bonder.clone(),
        threshold.clone(),
        x25519_public_key.clone(),
    );

    // For quote verification this needs to be the _next_ block, and right now we're at block `0`.
    let block_number = 1;
    let quote = prepare_attestation_for_validate::<T>(
        new_threshold.clone(),
        x25519_public_key,
        endpoint.clone().to_vec(),
        block_number,
    )
    .0;

    let signers = vec![validator_id_signers.clone(); s as usize];
    Signers::<T>::put(signers.clone());
  }:  _(RawOrigin::Signed(_bonder.clone()), new_threshold.clone(), x25519_public_key.clone(), pck,
        quote)
  verify {
    let server_info = ServerInfo {
      endpoint: b"http://localhost:3001".to_vec(),
      tss_account: new_threshold.clone(),
      x25519_public_key: NULL_ARR,
      provisioning_certification_key: MOCK_PCK_DERIVED_FROM_NULL_ARRAY.to_vec().try_into().unwrap(),
    };
    assert_last_event::<T>(Event::<T>::ThresholdAccountChanged(bonder, server_info).into());
  }

  unbond {
    let s in 0 .. MAX_SIGNERS as u32;
    let n in 0 .. MaxNominationsOf::<T>::get();

    let caller: T::AccountId = whitelisted_caller();
    let validator_id_res = <T as pallet_session::Config>::ValidatorId::try_from(caller.clone()).or(Err(Error::<T>::InvalidValidatorId)).unwrap();
    let bonder: T::AccountId = account("bond", 0, SEED);
    let threshold: T::AccountId = account("threshold", 0, SEED);

    let signers = vec![validator_id_res.clone(); s as usize];
    Signers::<T>::put(signers.clone());
    NextSigners::<T>::put(NextSignerInfo {
      next_signers: signers,
      confirmations: vec![],
    });

    prep_bond_and_validate::<T>(true, caller.clone(), bonder.clone(), threshold.clone(), NULL_ARR);

    let targets = BoundedVec::try_from(vec![threshold.clone(); n as usize]).unwrap();
    let nominations = Nominations { targets, submitted_in: 0, suppressed: false };
    pallet_staking::Nominators::<T>::insert(bonder.clone(), nominations);
  }:  _(RawOrigin::Signed(bonder.clone()), 10u32.into())
  verify {
    assert_last_event_frame_staking::<T>(FrameStakingEvent::Unbonded{ stash: bonder, amount: 10u32.into() }.into() );

  }

  chill {
    let c in 0 .. MAX_SIGNERS as u32;
    let n in 0 .. MaxNominationsOf::<T>::get();

    let caller: T::AccountId = whitelisted_caller();
    let validator_id_res = <T as pallet_session::Config>::ValidatorId::try_from(caller.clone()).or(Err(Error::<T>::InvalidValidatorId)).unwrap();
    let bonder: T::AccountId = account("bond", 0, SEED);
    let threshold: T::AccountId = account("threshold", 0, SEED);

    let signers = vec![validator_id_res.clone(); c as usize];
    Signers::<T>::put(signers.clone());
    NextSigners::<T>::put(NextSignerInfo {
      next_signers: signers,
      confirmations: vec![],
    });

    prep_bond_and_validate::<T>(true, caller.clone(), bonder.clone(), threshold.clone(), NULL_ARR);
    let bond = <T as pallet_staking::Config>::Currency::minimum_balance() * 10u32.into();

    // assume fully unbonded as slightly more weight, but not enough to handle partial unbond
    assert_ok!(<FrameStaking<T>>::unbond(
      RawOrigin::Signed(bonder.clone()).into(),
      bond,
    ));

    let targets = BoundedVec::try_from(vec![threshold.clone(); n as usize]).unwrap();
    let nominations = Nominations { targets, submitted_in: 0, suppressed: false };
    pallet_staking::Nominators::<T>::insert(bonder.clone(), nominations);

    let _ = pallet_staking::Validators::<T>::clear(100, None);

  }:  _(RawOrigin::Signed(bonder.clone()))
  verify {
    assert_last_event_frame_staking::<T>(FrameStakingEvent::Chilled{ stash: bonder }.into() );

  }


  withdraw_unbonded {
    let c in 0 .. MAX_SIGNERS as u32;
    let n in 0 .. MaxNominationsOf::<T>::get();

    let caller: T::AccountId = whitelisted_caller();
    let bonder: T::AccountId = account("bond", 0, SEED);
    let threshold: T::AccountId = account("threshold", 0, SEED);
    let validator_id_res = <T as pallet_session::Config>::ValidatorId::try_from(caller.clone()).or(Err(Error::<T>::InvalidValidatorId)).unwrap();

    let signers = vec![validator_id_res.clone(); c as usize];
    Signers::<T>::put(signers.clone());
    NextSigners::<T>::put(NextSignerInfo {
      next_signers: signers,
      confirmations: vec![],
    });

    prep_bond_and_validate::<T>(true, caller.clone(), bonder.clone(), threshold.clone(), NULL_ARR);
    let bond = <T as pallet_staking::Config>::Currency::minimum_balance() * 10u32.into();

    // assume fully unbonded as slightly more weight, but not enough to handle partial unbond
    assert_ok!(<FrameStaking<T>>::unbond(
      RawOrigin::Signed(bonder.clone()).into(),
      bond,
    ));

    let targets = BoundedVec::try_from(vec![threshold.clone(); n as usize]).unwrap();
    let nominations = Nominations { targets, submitted_in: 0, suppressed: false };
    pallet_staking::Nominators::<T>::insert(bonder.clone(), nominations);

  }:  _(RawOrigin::Signed(bonder.clone()), 0u32)
  verify {
    // TODO: JA fix, pretty much benching this pathway requiers moving the session forward
    // This is diffcult, from the test we were able to mock it but benchamrks use runtime configs
    // It is fine for now but should come back to it
    // assert_last_event::<T>(Event::NodeInfoRemoved(caller).into());
  }

  validate {
    let caller: T::AccountId = whitelisted_caller();
    let bonder: T::AccountId = account("bond", 0, SEED);
    let threshold_account: T::AccountId = account("threshold", 0, SEED);

    let validator_id =
        <T as pallet_session::Config>::ValidatorId::try_from(bonder.clone())
        .or(Err(Error::<T>::InvalidValidatorId))
        .unwrap();

    let nonce = NULL_ARR;
    let x25519_public_key = NULL_ARR;
    let endpoint = vec![];
    let validate_also = false;

    prep_bond_and_validate::<T>(
        validate_also,
        caller.clone(),
        bonder.clone(),
        threshold_account.clone(),
        x25519_public_key.clone()
    );

    // For quote verification this needs to be the _next_ block, and right now we're at block `0`.
    let block_number = 1;
    let (quote, joining_server_info) =
        prepare_attestation_for_validate::<T>(threshold_account.clone(), x25519_public_key, endpoint.clone(), block_number);
  }:  _(RawOrigin::Signed(bonder.clone()), ValidatorPrefs::default(), joining_server_info, quote)
  verify {
    assert_last_event::<T>(
        Event::<T>::ValidatorCandidateAccepted(
            bonder,
            validator_id,
            threshold_account,
            endpoint
        ).into()
    );
  }

  confirm_key_reshare_confirmed {
    let c in 0 .. MAX_SIGNERS as u32;
    // leave a space for two as not to rotate and only confirm rotation
    let confirmation_num = c.checked_sub(2).unwrap_or(0);
    let signer_num =  MAX_SIGNERS - 1;
    let caller: T::AccountId = whitelisted_caller();
    let validator_id_res = <T as pallet_session::Config>::ValidatorId::try_from(caller.clone()).or(Err(Error::<T>::InvalidValidatorId)).unwrap();
    let second_signer: T::AccountId = account("second_signer", 0, SEED);
    let second_signer_id = <T as pallet_session::Config>::ValidatorId::try_from(second_signer.clone()).or(Err(Error::<T>::InvalidValidatorId)).unwrap();
    ThresholdToStash::<T>::insert(caller.clone(), validator_id_res.clone());

    // full signer list leaving room for one extra validator
    let mut signers = vec![second_signer_id.clone(); signer_num as usize];
    signers.push(validator_id_res.clone());
    Signers::<T>::put(signers.clone());

    NextSigners::<T>::put(NextSignerInfo {
      next_signers: signers,
      confirmations: vec![second_signer_id.clone(); confirmation_num as usize],
  });

  }: confirm_key_reshare(RawOrigin::Signed(caller.clone()))
  verify {
    assert_last_event::<T>(Event::<T>::SignerConfirmed(validator_id_res).into());
  }

  confirm_key_reshare_completed {
    // once less confirmation to always flip to rotate
    let confirmation_num = MAX_SIGNERS as usize - 1;

    let caller: T::AccountId = whitelisted_caller();
    let validator_id_res = <T as pallet_session::Config>::ValidatorId::try_from(caller.clone()).or(Err(Error::<T>::InvalidValidatorId)).unwrap();
    let second_signer: T::AccountId = account("second_signer", 0, SEED);
    let second_signer_id = <T as pallet_session::Config>::ValidatorId::try_from(second_signer.clone()).or(Err(Error::<T>::InvalidValidatorId)).unwrap();
    ThresholdToStash::<T>::insert(caller.clone(), validator_id_res.clone());
    // full signer list leaving room for one extra validator
    let mut signers = vec![second_signer_id.clone(); confirmation_num as usize];
    signers.push(validator_id_res.clone());

    Signers::<T>::put(signers.clone());
    NextSigners::<T>::put(NextSignerInfo {
      next_signers: signers.clone(),
      confirmations: vec![second_signer_id; confirmation_num as usize],
  });

  }:  confirm_key_reshare(RawOrigin::Signed(caller.clone()))
  verify {
    assert_last_event::<T>(Event::<T>::SignersRotation(signers.clone()).into());
  }

  new_session_base_weight {
    let s in 2 .. MAX_SIGNERS as u32;

    let caller: T::AccountId = whitelisted_caller();

    // For the purpose of the bench these values don't actually matter, we just care that there's a
    // storage entry available
    SignersInfo::<T>::put(SignersSize {
        total_signers: MAX_SIGNERS,
        threshold: 3,
        last_session_change: 0,
    });

    let validator_id = <T as pallet_session::Config>::ValidatorId::try_from(caller.clone())
        .or(Err(Error::<T>::InvalidValidatorId))
        .unwrap();

    let signers = vec![validator_id.clone(); s as usize];
    Signers::<T>::put(signers);
  }:  {
    // Note that here we only add one validator, where as `Signers` already contains two as a
    // minimum.
    let _ = Staking::<T>::new_session_handler(&vec![validator_id]);
  }
  verify {
    assert!(NextSigners::<T>::get().is_none());
  }

  new_session {
    let c in 1 .. MAX_SIGNERS as u32 - 1;
    let l in 0 .. MAX_SIGNERS as u32;
    let v in 50 .. 100 as u32;
    let r in 0 .. MAX_SIGNERS as u32;

    // c -> current signer size
    // l -> Add in new_signer rounds so next signer is in current signer re-run checks
    // v -> number of validators, 100 is fine as a bounder, can add more
    // r -> adds remove indexes in

    let caller: T::AccountId = whitelisted_caller();
    let mut validator_ids = create_validators::<T>(v, 1);
    let second_signer: T::AccountId = account("second_signer", 0, 10);
    let second_signer_id =
        <T as pallet_session::Config>::ValidatorId::try_from(second_signer.clone())
            .or(Err(Error::<T>::InvalidValidatorId))
            .unwrap();
    let mut signers = vec![second_signer_id.clone(); c as usize];

    // For the purpose of the bench these values don't actually matter, we just care that there's a
    // storage entry available
    SignersInfo::<T>::put(SignersSize {
        total_signers: 5,
        threshold: 3,
        last_session_change: 0,
    });

    let validator_id = <T as pallet_session::Config>::ValidatorId::try_from(caller.clone())
        .or(Err(Error::<T>::InvalidValidatorId))
        .unwrap();

    // place new signer in the signers struct in different locations to calculate random selection
    // re-run
    // as well validators may be dropped before chosen
    signers[l as usize % c as usize] = validator_ids[l as usize % c as usize].clone();

    // place signers into validators so they won't get dropped
    for i in 0 .. r {
      if i > signers.len() as u32 && i > validator_ids.len() as u32 {
        validator_ids[i as usize] = signers[i as usize].clone();
      }
    }
    Signers::<T>::put(signers.clone());
  }:  {
    let _ = Staking::<T>::new_session_handler(&validator_ids);
  }
  verify {
    assert!(NextSigners::<T>::get().is_some());
  }
}

impl_benchmark_test_suite!(Staking, crate::mock::new_test_ext(), crate::mock::Test);
