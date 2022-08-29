use kvdb::kv_manager::{value::PartyInfo, KvManager};
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use tracing::instrument;

use super::{ParsedUserInputPartyInfo, UserErr, UserInputPartyInfo};
use crate::signing_client::SignerState;

/// Add a new Keyshare to this node's set of known Keyshares. Store in kvdb.
#[instrument(skip(state))]
#[post("/new", format = "json", data = "<user_input>")]
pub async fn new_user(
    user_input: Json<UserInputPartyInfo>,
    state: &State<KvManager>,
) -> Result<Status, UserErr> {
    // ToDo: JA verify proof
    // ToDo: validate is owner of key address
    // ToDo: JA make sure signed so other key doesn't override own key

    // try parsing the input and validate the result
    let parsed_user_input: ParsedUserInputPartyInfo = user_input.into_inner().try_into()?;
    let (key, value) = (parsed_user_input.key.clone(), parsed_user_input.value.clone());
    //   let party_info: PartyInfo = parsed_user_input.clone().try_into()?;

    // store new user data in kvdb
    let reservation = state.kv().reserve_key(key).await?;
    state.kv().put(reservation, value).await?;

    Ok(Status::Ok)
}
