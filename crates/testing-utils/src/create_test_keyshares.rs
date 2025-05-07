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

//! Simulates 3 TSS nodes running the reshare protocol in order to create keyshares with a
//! pre-defined distributed keypair for testing entropy-tss
use entropy_protocol::{execute_protocol::PairWrapper, EntropySessionParameters, PartyId};
use k256::ecdsa::SigningKey;
use manul::dev::run_sync;
use rand_core::OsRng;
use sp_core::{sr25519, Pair};
use synedrion::{
    k256::ProductionParams112, AuxInfo, KeyResharing, KeyShare, NewHolder, OldHolder,
    ThresholdKeyShare,
};

use std::collections::BTreeSet;

/// Given a secp256k1 secret key and 3 signing keypairs for the TSS parties, generate a set of
/// threshold keyshares with auxiliary info
pub async fn create_test_keyshares(
    distributed_secret_key_bytes: [u8; 32],
    signers: [sr25519::Pair; 3],
) -> Vec<(ThresholdKeyShare<ProductionParams112, PartyId>, AuxInfo<ProductionParams112, PartyId>)> {
    let signing_key = SigningKey::from_bytes(&(distributed_secret_key_bytes).into()).unwrap();
    let all_parties =
        signers.iter().map(|pair| PartyId::from(pair.public())).collect::<BTreeSet<_>>();

    let mut old_holders = all_parties.clone();
    // Remove one member as we initially create 2 of 2 keyshares, then reshare to 2 of 3
    old_holders.remove(&PartyId::from(signers[2].public()));

    let keyshares = KeyShare::<ProductionParams112, PartyId>::new_centralized(
        &mut OsRng,
        &old_holders,
        Some(&signing_key),
    );
    let aux_infos =
        AuxInfo::<ProductionParams112, PartyId>::new_centralized(&mut OsRng, &all_parties);

    let new_holder = NewHolder {
        verifying_key: keyshares.values().next().unwrap().verifying_key(),
        old_threshold: 2,
        old_holders,
    };

    let mut signers_and_entry_points = signers[..2]
        .iter()
        .map(|pair| {
            let entry_point = KeyResharing::new(
                Some(OldHolder {
                    key_share: ThresholdKeyShare::from_key_share(
                        &keyshares[&PartyId::from(pair.public())],
                    ),
                }),
                Some(new_holder.clone()),
                all_parties.clone(),
                2, // The threshold
            );

            (PairWrapper(pair.clone()), entry_point)
        })
        .collect::<Vec<_>>();

    let new_holder_signer_and_entry_point = {
        let entry_point = KeyResharing::new(
            None,
            Some(new_holder.clone()),
            all_parties.clone(),
            2, // The threshold
        );

        (PairWrapper(signers[2].clone()), entry_point)
    };

    signers_and_entry_points.push(new_holder_signer_and_entry_point);

    let new_t_key_shares =
        run_sync::<_, EntropySessionParameters>(&mut OsRng, signers_and_entry_points)
            .unwrap()
            .results()
            .unwrap();

    let mut output = Vec::new();
    for party_id in signers.iter().map(|pair| PartyId::from(pair.public())) {
        output.push((new_t_key_shares[&party_id].clone().unwrap(), aux_infos[&party_id].clone()));
    }
    output
}
