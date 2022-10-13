#![allow(clippy::all)]
use subxt::{
    config::{Config, SubstrateConfig},
    tx::{PairSigner, SubstrateExtrinsicParams},
    OnlineClient,
};
#[subxt::subxt(runtime_metadata_path = "entropy_metadata.scale")]
pub mod entropy {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EntropyConfig;
impl Config for EntropyConfig {
    // This is different from the default `u32`.
    //
    // *Note* that in this example it does differ from the actual `Index` type in the
    // polkadot runtime used, so some operations will fail. Normally when using a custom `Config`
    // impl types MUST match exactly those used in the actual runtime.
    type Index = u64;
    type BlockNumber = <SubstrateConfig as Config>::BlockNumber;
    type Hash = <SubstrateConfig as Config>::Hash;
    type Hashing = <SubstrateConfig as Config>::Hashing;
    type AccountId = <SubstrateConfig as Config>::AccountId;
    type Address = <SubstrateConfig as Config>::Address;
    type Header = <SubstrateConfig as Config>::Header;
    type Signature = <SubstrateConfig as Config>::Signature;
    type Extrinsic = <SubstrateConfig as Config>::Extrinsic;
    // ExtrinsicParams makes use of the index type, so we need to adjust it
    // too to align with our modified index type, above:
    type ExtrinsicParams = SubstrateExtrinsicParams<Self>;
}

/// Creates an api instance to talk to chain
/// Chain endpoint set on launch
pub async fn get_api(url: &str) -> Result<OnlineClient<EntropyConfig>, subxt::Error> {
    let api = OnlineClient::<EntropyConfig>::from_url(url).await?;
    Ok(api)
}
