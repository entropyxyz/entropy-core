use entropy_protocol::{execute_protocol::PairWrapper, KeyParams, KeyShareWithAuxInfo, PartyId};
use rand_core::OsRng;
use sp_core::{sr25519, Pair};
use subxt::utils::AccountId32;
use synedrion::{
    make_key_resharing_session, AuxInfo, KeyResharingInputs, KeyShare, NewHolder, OldHolder,
};

async fn create_test_keyshares(
    alice: sr25519::Pair,
    bob: sr25519::Pair,
    charlie: sr25519::Pair,
) -> Vec<KeyShareWithAuxInfo> {
    let signers = vec![alice, bob, charlie];
    let shared_randomness = b"12345";
    let all_parties =
        signers.iter().map(|pair| PartyId::new(AccountId32(pair.public().0))).collect::<Vec<_>>();

    let old_holders = all_parties.clone().into_iter().take(2).collect::<Vec<_>>();

    let keyshares = KeyShare::<KeyParams, PartyId>::new_centralized(&mut OsRng, &old_holders, None);
    let aux_infos = AuxInfo::<KeyParams, PartyId>::new_centralized(&mut OsRng, &all_parties);

    let new_holder =
        NewHolder { verifying_key: keyshares[0].verifying_key(), old_threshold: 2, old_holders };

    let mut sessions = (0..2)
        .map(|idx| {
            let inputs = KeyResharingInputs {
                old_holder: Some(OldHolder { key_share: keyshares[idx].to_threshold_key_share() }),
                new_holder: Some(new_holder.clone()),
                new_holders: all_parties.clone(),
                new_threshold: 2,
            };
            make_key_resharing_session(
                &mut OsRng,
                shared_randomness,
                PairWrapper(signers[idx].clone()),
                &all_parties,
                &inputs,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    let charlie_session = {
        let inputs = KeyResharingInputs {
            old_holder: None,
            new_holder: Some(new_holder.clone()),
            new_holders: all_parties.clone(),
            new_threshold: 2,
        };
        make_key_resharing_session(
            &mut OsRng,
            shared_randomness,
            PairWrapper(charlie),
            &all_parties,
            &inputs,
        )
        .unwrap()
    };

    sessions.push(charlie_session);

    let new_t_key_shares = run_nodes(sessions).await;
}
