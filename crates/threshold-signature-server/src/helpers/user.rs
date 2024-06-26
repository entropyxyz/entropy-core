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

//! Utilities relating to the user
use std::time::Duration;

use entropy_programs_runtime::Runtime;
use entropy_protocol::{
    execute_protocol::{execute_dkg, Channels},
    KeyShareWithAuxInfo, Listener, SessionId, ValidatorInfo,
};
use entropy_shared::{HashingAlgorithm, SETUP_TIMEOUT_SECONDS};

use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha256Digest, Sha256};
use sha3::{Digest as Sha3Digest, Keccak256, Sha3_256};
use sp_core::{hashing::blake2_256, sr25519, Pair};
use subxt::{backend::legacy::LegacyRpcMethods, tx::PairSigner, utils::AccountId32, OnlineClient};
use tokio::time::timeout;
use x25519_dalek::StaticSecret;

use crate::{
    chain_api::{entropy::runtime_types::pallet_registry::pallet::ProgramInstance, EntropyConfig},
    helpers::substrate::get_program,
    signing_client::{protocol_transport::open_protocol_connections, ListenerState},
    user::errors::UserErr,
};
/// complete the dkg process for a new user
pub async fn do_dkg(
    validators_info: &Vec<entropy_shared::ValidatorInfo>,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    x25519_secret_key: &StaticSecret,
    state: &ListenerState,
    sig_request_account: AccountId32,
    block_number: u32,
) -> Result<KeyShareWithAuxInfo, UserErr> {
    let session_id = SessionId::Dkg { user: sig_request_account.clone(), block_number };
    let account_id = AccountId32(signer.signer().public().0);
    let mut converted_validator_info = vec![];
    let mut tss_accounts = vec![];
    for validator_info in validators_info {
        let address_slice: &[u8; 32] = &validator_info
            .tss_account
            .clone()
            .try_into()
            .map_err(|_| UserErr::AddressConversionError("Invalid Length".to_string()))?;
        let tss_account = AccountId32(*address_slice);
        let validator_info = ValidatorInfo {
            x25519_public_key: validator_info.x25519_public_key,
            ip_address: std::str::from_utf8(&validator_info.ip_address)?.to_string(),
            tss_account: tss_account.clone(),
        };
        converted_validator_info.push(validator_info);
        tss_accounts.push(tss_account);
    }

    // subscribe to all other participating parties. Listener waits for other subscribers.
    let (rx_ready, rx_from_others, listener) =
        Listener::new(converted_validator_info.clone(), &account_id);
    state
        .listeners
        .lock()
        .map_err(|_| UserErr::SessionError("Error getting lock".to_string()))?
        .insert(session_id.clone(), listener);

    open_protocol_connections(
        &converted_validator_info,
        &session_id,
        signer.signer(),
        state,
        x25519_secret_key,
    )
    .await?;
    let channels = {
        let ready = timeout(Duration::from_secs(SETUP_TIMEOUT_SECONDS), rx_ready).await?;
        let broadcast_out = ready??;
        Channels(broadcast_out, rx_from_others)
    };

    // TODO #898 For now we use a fix proportion of the number of validators as the threshold
    let threshold = (tss_accounts.len() as f32 * 0.75) as usize;
    let result =
        execute_dkg(session_id, channels, signer.signer(), tss_accounts, threshold).await?;
    Ok(result)
}

/// Checks if a validator is in the current selected registration committee
pub fn check_in_registration_group(
    validators_info: &[entropy_shared::ValidatorInfo],
    validator_address: &AccountId32,
) -> Result<(), UserErr> {
    let is_proper_signer = validators_info
        .iter()
        .any(|validator_info| validator_info.tss_account == validator_address.0.to_vec());
    if !is_proper_signer {
        return Err(UserErr::InvalidSigner("Invalid Signer in Signing group"));
    }
    Ok(())
}

/// Generate the a hash of `message` to be signed based on the `hash` algorithm
pub async fn compute_hash(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    hashing_algorithm: &HashingAlgorithm,
    runtime: &mut Runtime,
    programs_data: &[ProgramInstance],
    message: &[u8],
) -> Result<[u8; 32], UserErr> {
    match hashing_algorithm {
        HashingAlgorithm::Sha1 => {
            let mut hasher = <Sha1 as Sha1Digest>::new();
            hasher.update(message);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            Ok(hash)
        },
        HashingAlgorithm::Sha2 => {
            let mut hasher = <Sha256 as Sha256Digest>::new();
            hasher.update(message);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            Ok(hash)
        },
        HashingAlgorithm::Sha3 => {
            let mut hasher = <Sha3_256 as Sha3Digest>::new();
            hasher.update(message);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            Ok(hash)
        },
        HashingAlgorithm::Keccak => {
            let mut hasher = <Keccak256 as Sha3Digest>::new();
            hasher.update(message);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            Ok(hash)
        },
        HashingAlgorithm::Blake2_256 => Ok(blake2_256(message)),
        HashingAlgorithm::Custom(i) => {
            let program = get_program(api, rpc, &programs_data[*i].program_pointer).await?;
            runtime.custom_hash(program.as_slice(), message).map_err(|e| e.into())
        },
        _ => Err(UserErr::UnknownHashingAlgorithm),
    }
}
