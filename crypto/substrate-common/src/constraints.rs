// use frame_support::*;
pub use acl::*;
use codec::{Decode, Encode};
use frame_support::pallet_prelude::*;
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use serde_derive::{Deserialize as DeserializeDerive, Serialize as SerializeDerive};
pub use sp_core::H160;
use sp_core::{bounded::BoundedVec, ConstU32};
use sp_std::vec::Vec;

/// Supported architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub enum Arch {
    Evm,
    Btc,
    Generic,
}

/// Trait that defines types for the architecture for a transaction.
pub trait Architecture: Serialize + for<'de> Deserialize<'de> {
    /// Account type for that chain(SS58, H160, etc)
    type Address: Eq + Serialize + for<'de> Deserialize<'de>;
    type TransactionRequest: HasSender<Self>
        + HasReceiver<Self>
        + Serialize
        + for<'de> Deserialize<'de>;
}

/// Trait for getting the the sender of a transaction.
pub trait HasSender<A: Architecture + ?Sized> {
    fn sender(&self) -> Option<A::Address>;
}

/// Trait for getting the the receiver of a transaction.
pub trait HasReceiver<A: Architecture + ?Sized> {
    fn receiver(&self) -> Option<A::Address>;
}

/// Trait for getting the Arch of a transaction.
pub trait HasArch {
    fn arch() -> Arch;
}

/// Basic transaction that has a sender and receiver with single accounts.
#[derive(Default, Debug, Clone, PartialEq, SerializeDerive, DeserializeDerive)]
pub struct BasicTransaction<A: Architecture> {
    pub from: Option<A::Address>,
    pub to: Option<A::Address>,
}

// TODO Move all EVM architecture stuff in entropy-constraints to substrate-common

/// This includes tpes related to ACL constraints.
mod acl {
    use super::*;

    /// Represents either an allow or deny list.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen)]
    pub enum AclKind {
        Allow,
        Deny,
    }

    /// An access control list (Allow/Deny lists).
    /// acl is the vector of allowed or denied addresses.
    /// acl_type represents if the constraint is either allow/deny.
    /// TODO make this a non-bounded or generic vec
    #[derive(Clone, Debug, Encode, Decode, PartialEq, Eq, scale_info::TypeInfo, MaxEncodedLen)]
    pub struct Acl<Address> {
        pub addresses: BoundedVec<Address, ConstU32<25>>,
        pub kind: AclKind,
        pub allow_null_recipient: bool,
    }

    impl<A: Default> Default for Acl<A> {
        fn default() -> Self {
            let addresses = BoundedVec::<A, ConstU32<25>>::default();
            Self { addresses, kind: AclKind::Allow, allow_null_recipient: false }
        }
    }

    impl<A: Default> Acl<A> {
        /// Try to create a new Allow ACL from a `Vec` of addresses.
        pub fn try_from(addresses: Vec<A>) -> Result<Self, &'static str> {
            let mut new_acl = Acl::<A>::default();
            new_acl.addresses.try_extend(addresses.into_iter()).map_err(|_| "ACL is too long.")?;

            Ok(new_acl)
        }
    }
}
