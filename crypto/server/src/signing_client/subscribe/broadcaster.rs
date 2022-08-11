//! Listener becomes Broadcaster when all other parties have subscribed.

use super::Listener;

#[derive(Debug)]
pub struct Broadcaster(Listener);
