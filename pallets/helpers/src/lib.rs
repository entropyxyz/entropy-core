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

#![cfg_attr(not(feature = "std"), no_std)]

pub mod errors {
    #[macro_export]
    macro_rules! unwrap_or_return {
        ($e:expr, $w:expr) => {
            match $e {
                Some(x) => x,
                None => {
                    log::warn!("{}", $w);
                    return;
                },
            }
        };
    }

    #[macro_export]
    macro_rules! unwrap_or_return_db_read {
        ($e:expr, $r:expr, $w:expr) => {
            match $e {
                Some(x) => x,
                None => {
                    return {
                        log::warn!("{}", $w);
                        T::DbWeight::get().reads($r)
                    }
                },
            }
        };
    }
}
