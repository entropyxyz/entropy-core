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

use bincode::{
    config::{
        BigEndian, Bounded, RejectTrailing, VarintEncoding, WithOtherEndian, WithOtherIntEncoding,
        WithOtherLimit, WithOtherTrailing,
    },
    DefaultOptions, Options,
};
use serde::de::DeserializeOwned;
use tracing::{error, warn};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct KVDBFatal;
pub type KVDBResult<T> = Result<T, KVDBFatal>;
pub type BytesVec = Vec<u8>;
/// Max message length allowed to be (de)serialized
const MAX_MSG_LEN: u64 = 1000 * 1000; // 1 MB

/// Serialize a value using bincode and log errors
pub fn serialize<T: ?Sized>(value: &T) -> KVDBResult<BytesVec>
where
    T: serde::Serialize,
{
    let bincode = bincoder();

    bincode.serialize(value).map_err(|err| {
        error!("serialization failure: {}", err.to_string());
        KVDBFatal
    })
}

/// Deserialize bytes to a type using bincode and log errors.
/// Return an Option type since deserialization isn't treated as a Fatal error
/// for the purposes of fault identification.
pub fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    let bincode = bincoder();

    bincode
        .deserialize(bytes)
        .map_err(|err| {
            warn!("deserialization failure: {}", err.to_string());
        })
        .ok()
}

/// Prepare a `bincode` serde backend with our preferred config
#[allow(clippy::type_complexity)]
fn bincoder() -> WithOtherTrailing<
    WithOtherIntEncoding<
        WithOtherEndian<WithOtherLimit<DefaultOptions, Bounded>, BigEndian>,
        VarintEncoding,
    >,
    RejectTrailing,
> {
    DefaultOptions::new()
        .with_limit(MAX_MSG_LEN)
        .with_big_endian() // do not ignore extra bytes at the end of the buffer
        .with_varint_encoding() // saves a lot of space in smaller messages
        .reject_trailing_bytes() // do not ignore extra bytes at the end of the buffer
}
