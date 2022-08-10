//! Types that are shared by c-manager and signing-client

mod sign_init;

pub use sign_init::{KvKeyshareInfo, SignInit, SignInitUnchecked};
pub type PartyUid = usize;
