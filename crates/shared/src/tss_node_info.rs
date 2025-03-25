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
//! Output types used by the TSS `/info` and `/version` routes

use crate::{BoundedVecEncodedVerifyingKey, X25519PublicKey};
use sp_runtime::AccountId32;

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

/// Public signing and encryption keys associated with a TS server
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TssPublicKeys {
    /// Indicates that all prerequisite checks have passed
    pub ready: bool,
    /// The TSS account ID
    pub tss_account: AccountId32,
    /// The public encryption key
    pub x25519_public_key: X25519PublicKey,
    /// The Provisioning Certification Key used in TDX quotes
    pub provisioning_certification_key: BoundedVecEncodedVerifyingKey,
}

/// Version information - the output of the TSS `/version` HTTP endpoint
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(PartialEq, Debug)]
pub struct VersionDetails {
    pub cargo_package_version: String,
    pub git_tag_commit: String,
    pub build: BuildDetails,
}

/// This lets us know this is a production build and gives us the measurement value of the release
/// image
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(PartialEq, Debug)]
pub enum BuildDetails {
    ProductionWithMeasurementValue(String),
    NonProduction,
}
