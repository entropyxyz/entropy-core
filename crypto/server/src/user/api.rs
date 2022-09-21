use kvdb::kv_manager::{value::PartyInfo, KvManager};
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use tracing::instrument;
use subxt::{
    sp_runtime::AccountId32
};
use super::{ParsedUserInputPartyInfo, UserErr, UserInputPartyInfo};
use crate::{signing_client::SignerState, chain_api::{get_api, EntropyRuntime, entropy}, Configuration};

/// Add a new Keyshare to this node's set of known Keyshares. Store in kvdb.
#[instrument(skip(state))]
#[post("/new", format = "json", data = "<user_input>")]
pub async fn new_user(
    user_input: Json<UserInputPartyInfo>,
    state: &State<KvManager>,
	config: &State<Configuration>,
) -> Result<Status, UserErr> {
    let api = get_api(&config.endpoint).await.unwrap();
    // ToDo: validate is owner of key address
    // ToDo: JA make sure signed so other key doesn't override own key
    // try parsing the input and validate the result
    let parsed_user_input: ParsedUserInputPartyInfo = user_input.into_inner().try_into()?;
    let (key, value) = (parsed_user_input.key.clone(), parsed_user_input.value.clone());
	let is_registering = is_registering(&api, &key).await.unwrap();
	if !is_registering {
		return Err(UserErr::NotRegistering("Register Onchain first".into()))
	}
    //   let party_info: PartyInfo = parsed_user_input.clone().try_into()?;

    // store new user data in kvdb
    let reservation = state.kv().reserve_key(key.to_string()).await?;
    state.kv().put(reservation, value).await?;

    Ok(Status::Ok)
}


pub async fn is_registering(
    api: &EntropyRuntime,
    who: &AccountId32,
) -> Result<bool, subxt::Error<entropy::DispatchError>> {
    let is_registering =
        api.storage().relayer().registering(who, None).await?.unwrap();
    Ok(is_registering)
}
