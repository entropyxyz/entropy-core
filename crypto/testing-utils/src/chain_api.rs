#![allow(clippy::all)]
pub use subxt::config::PolkadotConfig as EntropyConfig;

#[subxt::subxt(
    runtime_metadata_path = "../server/entropy_metadata.scale",
    substitute_type(
        path = "entropy_shared::constraints::acl::Acl<Address>",
        with = "::subxt::utils::Static<::entropy_shared::Acl<Address>>",
    ),
    generate_docs
)]
pub mod entropy {}
