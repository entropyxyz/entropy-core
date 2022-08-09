//! Types that are shared by c-manager and signing-client

mod cm_info;

pub type CMInfo = cm_info::CMInfo;
pub type CMInfoUnchecked = cm_info::CMInfoUnchecked;
pub type KvKeyshareInfo = cm_info::KvKeyshareInfo;
pub type PartyUid = usize;
