mod broadcaster;
mod listener;
mod message;

use futures::{future, stream::BoxStream, StreamExt};
pub(super) use listener::Receiver;
use tokio::time::{sleep, Duration};

pub use self::{broadcaster::Broadcaster, listener::Listener, message::SubscribeMessage};
use super::{new_party::SignContext, SigningErr, SigningMessage};

/// Call `subscribe` on every other node with a reqwest client. Merge the streamed responses
/// into a single stream.
#[allow(unused_variables)]
pub async fn subscribe_to_them(
    ctx: &SignContext,
) -> Result<BoxStream<'static, SigningMessage>, SigningErr> {
    let handles: Vec<_> = ctx
        .sign_init
        .ip_addresses
        .iter()
        .map(|ip| {
            reqwest::Client::new()
                .post(format!("http://{}/signer/subscribe_to_me", ip))
                .header("Content-Type", "application/json")
                .json(&SubscribeMessage::new(ctx.sign_init.party_uid.to_string()))
                .send()
        })
        .collect();
    // 	let party = ctx.party_info.tofnd.index;
    // // 	dbg!(party.clone());
    // 	let mut handle;
    // 	if party == 0 {
    // 		 handle = reqwest::Client::new()
    // 			.post("http://127.0.0.1:3002/signer/subscribe_to_me")
    // 			.header("Content-Type", "application/json")
    // 			.json(&SubscribeMessage::new(ctx.sign_init.party_uid.to_string()))
    // 			.send();
    // 	}
    // 	else {
    // 		handle = reqwest::Client::new()
    // 			.post("http://127.0.0.1:3001/signer/subscribe_to_me")
    // 			.header("Content-Type", "application/json")
    // 			.json(&SubscribeMessage::new(ctx.sign_init.party_uid.to_string()))
    // 			.send();

    // 	}
    //     dbg!("here");
    //   let handles = vec![handle];
    let responses: Vec<reqwest::Response> = future::try_join_all(handles).await?;
    // Filter the streams, map them to messages
    let streams: Vec<_> = responses
        .into_iter()
        .map(|resp: reqwest::Response| {
            let mut merge: String = "".to_string();
            resp.bytes_stream().filter_map(move |result| {
                let bytes = result.unwrap();
                let string = std::str::from_utf8(&bytes).unwrap();

                let full_msg = string.find('\n');
                if full_msg.is_some() && string.len() > 5 {
                    let current = merge.clone();
                    merge = format!("{}{}", merge, string);
                    let msg = SigningMessage::try_from(&merge.to_string())
                        .map_err(|err| {
                            SigningErr::Anyhow(anyhow::Error::msg(format!(
                                "Cannot deserialize SigningMessage from: {}",
                                &merge
                            )))
                        })
                        .unwrap();
                    merge = "".to_string();
                    future::ready(Some(msg))
                } else {
                    let current = merge.clone();
                    merge = format!("{}{}", current, string);
                    future::ready(None)
                }
            })
        })
        .collect();

    // Merge the streams, pin-box them to handle the opaque types
    Ok(Box::pin(futures::stream::select_all(streams)))
}
