mod broadcaster;
mod listener;
mod message;

use futures::{future, stream, stream::BoxStream, StreamExt};
use kvdb::kv_manager::PartyId;
pub(super) use listener::Receiver;
use reqwest_eventsource::{Error, Event, RequestBuilderExt};

pub use self::{broadcaster::Broadcaster, listener::Listener, message::SubscribeMessage};
use super::{new_party::SignContext, SigningErr, SigningMessage};

/// Call `subscribe` on every other node with a reqwest client. Merge the streamed responses
/// into a single stream.
pub async fn subscribe_to_them(
    ctx: &SignContext,
    my_id: &PartyId,
) -> Result<BoxStream<'static, SigningMessage>, SigningErr> {
    let event_sources_init = ctx.sign_init.ip_addresses.iter().map(|ip| async move {
        // TODO: handle errors
        let mut es = reqwest::Client::new()
            .post(format!("http://{ip}/signer/subscribe_to_me"))
            .json(&SubscribeMessage::new(&ctx.sign_init.sig_uid, my_id.clone()))
            .eventsource().map_err(|e| SigningErr::CannotCloneRequest(e.to_string()))?;

        // We need to call this to cause the actual request to be sent,
        // otherwise we're stuck in a deadlock while servers wait for each other to subscribe.
        // The first event we receive is an empty one, so we're not losing any info.
        let first_event = es.next().await.ok_or_else(|| SigningErr::OptionUnwrapError("Problem with first event"))?;

        let first_event = first_event?;

        if !matches!(first_event, Event::Open) {
            return Err(SigningErr::UnexpectedEvent("Unexpected first event".to_string()));
        }

        Ok::<_, SigningErr>(es)
    }).collect::<Vec<_>>();

    let event_sources = future::try_join_all(event_sources_init).await?;

    // Filter the streams, map them to messages
    let deserialized_events = stream::select_all(event_sources).filter_map(
        |maybe_event: Result<Event, Error>| async move {
            if matches!(maybe_event, Err(Error::StreamEnded)) {
                return None;
            }

            match maybe_event.ok()? {
                Event::Open => None, // Shouldn't really happen; raise an error?
                Event::Message(message) => {
                    let msg = SigningMessage::try_from(&message.data).ok()?;
                    Some(msg)
                },
            }
        },
    );

    // Merge the streams, pin-box them to handle the opaque types
    Ok(Box::pin(deserialized_events))
}
