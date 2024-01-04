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

use thiserror::Error;
use x25519_chacha20poly1305::SignedMessageErr;

#[derive(Debug, Error)]
pub enum ValidationErr {
    #[error("Encryption or signing error: {0}")]
    Json(#[from] SignedMessageErr),
    #[error("Secret String failure: {0:?}")]
    SecretString(&'static str),
    #[error("Message is too old")]
    StaleMessage,
    #[error("Time subtraction error: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),
}
