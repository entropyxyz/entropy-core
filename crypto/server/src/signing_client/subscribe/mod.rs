mod broadcaster;
mod listener;
mod message;

use futures::{future, stream::BoxStream};

pub use self::{broadcaster::Broadcaster, listener::Listener, message::SubscribeMessage};
use super::{new_party::SignContext, SigningErr, SigningMessage};

/// Call `subscribe` on every other node with a reqwest client. Merge the streamed responses
/// into a single stream.
#[allow(unused_variables)]
pub async fn subscribe_all(
  // &mut self,
  ctx: &SignContext,
) -> Result<BoxStream<'static, SigningMessage>, SigningErr> {
  let handles: Vec<_> = ctx
    .sign_init
    .ip_addresses
    .iter()
    .map(|ip| {
      reqwest::Client::new()
        .post(format!("http://{}/signer/subscribe", ip))
        .header("Content-Type", "application/json")
        .json(&SubscribeMessage::new(ctx.sign_init.party_uid.to_string()))
        .send()
    })
    .collect();
  let responses: Vec<reqwest::Response> = future::try_join_all(handles).await?;

  // todo:
  // filter_map is pissed off again

  // let streams: Vec<_> = responses // Filter the streams, map them to messages
  //   .into_iter()
  //   .map(|resp: reqwest::Response| {
  //     resp.bytes_stream().filter_map(|result| {
  //       let bytes = result.unwrap();
  //       info!("got bytes: {:?}", bytes);
  //       let msg = SigningMessage::try_from(&*bytes);
  //       info!("got msg: {:?}", msg);
  //       future::ready(msg.ok())
  //     })
  //   })
  //   .collect();
  // // Merge the streams, pin-box them to handle the opaque types
  // let stream: BoxStream<'static, SigningMessage> =
  // Box::pin(futures::stream::select_all(streams)); // self.rx_stream = Some(stream); Ok(stream)
  todo!()
}

// / Wait for other nodes to finish subscribing to this node. SubscriberManager sends a
// broadcast /// channel when all other nodes have subscribed.
// async fn await_subscribers(&mut self) -> anyhow::Result<()> {
// let rx = self.finalized_subscribing_rx.take().unwrap();
// let tx = rx.await?;
// self.broadcast_tx = Some(tx);
// Ok(())
// }
