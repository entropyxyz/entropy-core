use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use tracing::instrument;

use super::{UserKvEntry, UserKvEntryUnparsed};
use crate::{signing_client::SignerState, user::NewUserError};
// use crate::signing_client::{new_party::SignInit, NewUserError, SubscribeError};

/// Add a new Keyshare to this node's set of known Keyshares. Store in kvdb.
#[instrument]
#[post("/new", format = "json", data = "<user_input>")]
pub async fn new_user(
  user_input: Json<UserKvEntryUnparsed>,
  state: &State<SignerState>,
) -> Result<Status, NewUserError> {
  // ToDo: JA verify proof
  // ToDo: validate is owner of key address
  // ToDo: JA make sure signed so other key doesn't override own key

  let user_input = UserKvEntry::try_from(user_input.into_inner()).unwrap();
  let kv_manager = &state.kv_manager;
  let reservation = kv_manager.kv().reserve_key(user_input.key.clone()).await.unwrap();
  kv_manager.kv().put(reservation, user_input.value.clone()).await.unwrap();

  Ok(Status::Ok)
}
