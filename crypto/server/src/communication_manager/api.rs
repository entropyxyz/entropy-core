use rocket::{http::Status, State};
use tracing::instrument;

use crate::communication_manager::{
	errors::CustomIPError, handle_signing::EncodedBlockData, CommunicationManagerState,
};
use rocket::serde::json::Json;

// TODO(TK): It's unclear what this API should look like, but this method should be the kick-off
// point for the Communication manager's signing-protocol-initiation extrinsic. This method should
// be merged with sign::provide_share, which this method makes redundant.
//
/// The prior Block Proposer's block has been accepted. The BP is now the Communication Manager.
/// Via an extrinsic (this method) the CM must:
/// - Retrieve CMInfo committee information about this user from DB
/// - Selects a signing party
/// - Informs the signers a signing_protocol has begun by calling `new_party` on each node
/// - Reselects and reruns the if one or more signers failed or were offline.
#[instrument]
#[rocket::post("/handle_signing", format = "json", data = "<encoded_data>")]
pub async fn handle_signing(
	encoded_data: Json<EncodedBlockData>,
	state: &State<CommunicationManagerState>,
) -> Result<Status, CustomIPError> {
	// TODO JA do validation on recieved keys and if keys are already had
	// TODO JA figure out optimal node amount
	// TODO JA validate not a duplicated IP
	info!("handling signing with block data: {:?}", encoded_data);
	// let mut block = accepted_block.into_inner();
	// assert!(block.validate_user());

	// let cm_info = handle_signing.get_user_info_from_db(&state.kv_manager).unwrap();
	// let signers = handle_signing.select_signers(&cm_info);
	// if let Err(bad_signer) = handle_signing.post_new_party(&signers, &cm_info).await {
	// 	let _ = handle_signing.punish_and_rerun(signers, bad_signer, cm_info).await;
	// }
	Ok(Status::Ok)
}
