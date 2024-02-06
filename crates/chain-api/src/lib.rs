// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#![allow(clippy::all)]
use subxt::{
    backend::{legacy::LegacyRpcMethods, rpc::RpcClient},
    OnlineClient,
};
use parity_scale_codec::Encode;
use subxt::client::OfflineClientT;
use subxt::config::signed_extensions;
use subxt::config::{
    Config, DefaultExtrinsicParamsBuilder, ExtrinsicParams, ExtrinsicParamsEncoder,
};

#[subxt::subxt(
    runtime_metadata_path = "entropy_metadata.scale",
    substitute_type(
        path = "entropy_shared::types::KeyVisibility",
        with = "::subxt::utils::Static<::entropy_shared::KeyVisibility>",
    )
)]
pub mod entropy {}


// We don't need to construct this at runtime,
// so an empty enum is appropriate:
pub enum EntropyConfig {}

impl Config for EntropyConfig {
    type Hash = subxt::utils::H256;
    type AccountId = subxt::utils::AccountId32;
    type Address = subxt::utils::MultiAddress<Self::AccountId, ()>;
    type Signature = subxt::utils::MultiSignature;
    type Hasher = subxt::config::substrate::BlakeTwo256;
    type Header = subxt::config::substrate::SubstrateHeader<u32, Self::Hasher>;
    type ExtrinsicParams = signed_extensions::AnyOf<
        Self,
        (
            // Load in the existing signed extensions we're interested in
            // (if the extension isn't actually needed it'll just be ignored):
            signed_extensions::CheckSpecVersion,
            signed_extensions::CheckTxVersion,
            signed_extensions::CheckNonce,
            signed_extensions::CheckGenesis<Self>,
            signed_extensions::CheckMortality<Self>,
            signed_extensions::ChargeAssetTxPayment,
            signed_extensions::ChargeTransactionPayment,
            ValidateElectricityPayment,
            ValidateConfirmRegistered
        ),
    >;
}

// Our custom signed extension doesn't do much:
pub struct ValidateConfirmRegistered;

// Give the extension a name; this allows `AnyOf` to look it
// up in the chain metadata in order to know when and if to use it.
impl<T: Config> signed_extensions::SignedExtension<T> for ValidateConfirmRegistered {
    const NAME: &'static str = "ValidateConfirmRegistered";
}

// Gather together any params we need for our signed extension, here none.
impl<T: Config> ExtrinsicParams<T> for ValidateConfirmRegistered {
    type OtherParams = ();
    type Error = std::convert::Infallible;

    fn new<Client: OfflineClientT<T>>(
        _nonce: u64,
        _client: Client,
        _other_params: Self::OtherParams,
    ) -> Result<Self, Self::Error> {
        Ok(ValidateConfirmRegistered)
    }
}

// Encode whatever the extension needs to provide when asked:
impl ExtrinsicParamsEncoder for ValidateConfirmRegistered {
    fn encode_extra_to(&self, _v: &mut Vec<u8>) {
    }
}

// Our custom signed extension doesn't do much:
pub struct ValidateElectricityPayment;

// Give the extension a name; this allows `AnyOf` to look it
// up in the chain metadata in order to know when and if to use it.
impl<T: Config> signed_extensions::SignedExtension<T> for ValidateElectricityPayment {
    const NAME: &'static str = "ValidateElectricityPayment";
}

// Gather together any params we need for our signed extension, here none.
impl<T: Config> ExtrinsicParams<T> for ValidateElectricityPayment {
    type OtherParams = ();
    type Error = std::convert::Infallible;

    fn new<Client: OfflineClientT<T>>(
        _nonce: u64,
        _client: Client,
        _other_params: Self::OtherParams,
    ) -> Result<Self, Self::Error> {
        Ok(ValidateElectricityPayment)
    }
}

// Encode whatever the extension needs to provide when asked:
impl ExtrinsicParamsEncoder for ValidateElectricityPayment {
    fn encode_additional_to(&self, v: &mut Vec<u8>) {
        true.encode_to(v)
    }
}

// When composing a tuple of signed extensions, the user parameters we need must
// be able to convert `Into` a tuple of corresponding `OtherParams`. Here, we just
// "hijack" the default param builder, but add the `OtherParams` (`()`) for our
// new signed extension at the end, to make the types line up. IN reality you may wish
// to construct an entirely new interface to provide the relevant `OtherParams`.
pub fn custom_params(
    params: DefaultExtrinsicParamsBuilder<EntropyConfig>,
) -> <<EntropyConfig as Config>::ExtrinsicParams as ExtrinsicParams<EntropyConfig>>::OtherParams {
    let (a, b, c, d, e, f, g) = params.build();
    (a, b, c, d, e, f, g, (), ())
}

/// Creates an api instance to talk to chain
/// Chain endpoint set on launch
pub async fn get_api(url: &str) -> Result<OnlineClient<EntropyConfig>, subxt::Error> {
    let api = OnlineClient::<EntropyConfig>::from_url(url).await?;
    Ok(api)
}

/// Creates a rpc instance to talk to chain
/// Chain endpoint set on launch
pub async fn get_rpc(url: &str) -> Result<LegacyRpcMethods<EntropyConfig>, subxt::Error> {
    let rpc_client = RpcClient::from_url(url).await?;
    let rpc_methods = LegacyRpcMethods::<EntropyConfig>::new(rpc_client);
    Ok(rpc_methods)
}
