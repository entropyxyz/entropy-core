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

//! Autogenerated weights for `pallet_registry`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 43.0.0
//! DATE: 2025-04-22, STEPS: `5`, REPEAT: `2`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `Jesses-MacBook-Pro.local`, CPU: `<UNKNOWN>`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("dev")`, DB CACHE: 1024

// Executed Command:
// ./target/release/entropy
// benchmark
// pallet
// --chain
// dev
// --pallet=pallet_registry
// --extrinsic=*
// --steps=5
// --repeat=2
// --header=.maintain/AGPL-3.0-header.txt
// --output=./runtime/src/weights/

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `pallet_registry`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_registry::WeightInfo for WeightInfo<T> {
	/// Storage: `Parameters::SignersInfo` (r:1 w:0)
	/// Proof: `Parameters::SignersInfo` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `StakingExtension::JumpStartProgress` (r:1 w:1)
	/// Proof: `StakingExtension::JumpStartProgress` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Session::Validators` (r:1 w:0)
	/// Proof: `Session::Validators` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Babe::NextRandomness` (r:1 w:0)
	/// Proof: `Babe::NextRandomness` (`max_values`: Some(1), `max_size`: Some(32), added: 527, mode: `MaxEncodedLen`)
	/// Storage: `Babe::EpochStart` (r:1 w:0)
	/// Proof: `Babe::EpochStart` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `MaxEncodedLen`)
	/// Storage: `StakingExtension::ThresholdServers` (r:3 w:0)
	/// Proof: `StakingExtension::ThresholdServers` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Registry::JumpstartDkg` (r:0 w:1)
	/// Proof: `Registry::JumpstartDkg` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn jump_start_network() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1220`
		//  Estimated: `9635`
		// Minimum execution time: 37_000_000 picoseconds.
		Weight::from_parts(43_000_000, 0)
			.saturating_add(Weight::from_parts(0, 9635))
			.saturating_add(T::DbWeight::get().reads(8))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `StakingExtension::ThresholdToStash` (r:1 w:0)
	/// Proof: `StakingExtension::ThresholdToStash` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Registry::JumpstartDkg` (r:2 w:0)
	/// Proof: `Registry::JumpstartDkg` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `StakingExtension::JumpStartProgress` (r:1 w:1)
	/// Proof: `StakingExtension::JumpStartProgress` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Parameters::SignersInfo` (r:1 w:0)
	/// Proof: `Parameters::SignersInfo` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `StakingExtension::Signers` (r:0 w:1)
	/// Proof: `StakingExtension::Signers` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// The range of component `c` is `[0, 15]`.
	fn confirm_jump_start_done(c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1925`
		//  Estimated: `7865`
		// Minimum execution time: 32_000_000 picoseconds.
		Weight::from_parts(32_930_939, 0)
			.saturating_add(Weight::from_parts(0, 7865))
			// Standard Error: 245_153
			.saturating_add(Weight::from_parts(273_480, 0).saturating_mul(c.into()))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `StakingExtension::ThresholdToStash` (r:1 w:0)
	/// Proof: `StakingExtension::ThresholdToStash` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Registry::JumpstartDkg` (r:2 w:0)
	/// Proof: `Registry::JumpstartDkg` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `StakingExtension::JumpStartProgress` (r:1 w:1)
	/// Proof: `StakingExtension::JumpStartProgress` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Parameters::SignersInfo` (r:1 w:0)
	/// Proof: `Parameters::SignersInfo` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// The range of component `c` is `[0, 15]`.
	fn confirm_jump_start_confirm(_c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1659`
		//  Estimated: `7599`
		// Minimum execution time: 30_000_000 picoseconds.
		Weight::from_parts(33_406_077, 0)
			.saturating_add(Weight::from_parts(0, 7599))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Programs::Programs` (r:1 w:1)
	/// Proof: `Programs::Programs` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `StakingExtension::JumpStartProgress` (r:1 w:0)
	/// Proof: `StakingExtension::JumpStartProgress` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Registry::CounterForRegistered` (r:1 w:1)
	/// Proof: `Registry::CounterForRegistered` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Registry::Registered` (r:1 w:1)
	/// Proof: `Registry::Registered` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Registry::ModifiableKeys` (r:1 w:1)
	/// Proof: `Registry::ModifiableKeys` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `p` is `[1, 5]`.
	fn register(p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `519`
		//  Estimated: `3984`
		// Minimum execution time: 510_000_000 picoseconds.
		Weight::from_parts(529_300_000, 0)
			.saturating_add(Weight::from_parts(0, 3984))
			// Standard Error: 4_682_480
			.saturating_add(Weight::from_parts(1_000_000, 0).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(4))
	}
	/// Storage: `Programs::Programs` (r:2 w:2)
	/// Proof: `Programs::Programs` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Registry::Registered` (r:1 w:1)
	/// Proof: `Registry::Registered` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `n` is `[1, 5]`.
	/// The range of component `o` is `[1, 5]`.
	fn change_program_instance(n: u32, o: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `541 + o * (33 ±0)`
		//  Estimated: `6481 + o * (33 ±0)`
		// Minimum execution time: 33_000_000 picoseconds.
		Weight::from_parts(19_500_000, 0)
			.saturating_add(Weight::from_parts(0, 6481))
			// Standard Error: 253_623
			.saturating_add(Weight::from_parts(2_380_952, 0).saturating_mul(n.into()))
			// Standard Error: 253_623
			.saturating_add(Weight::from_parts(2_347_619, 0).saturating_mul(o.into()))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(3))
			.saturating_add(Weight::from_parts(0, 33).saturating_mul(o.into()))
	}
	/// Storage: `Registry::Registered` (r:1 w:1)
	/// Proof: `Registry::Registered` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Registry::ModifiableKeys` (r:1 w:1)
	/// Proof: `Registry::ModifiableKeys` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `n` is `[1, 25]`.
	fn change_program_modification_account(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `251 + n * (1 ±0)`
		//  Estimated: `3716 + n * (1 ±0)`
		// Minimum execution time: 16_000_000 picoseconds.
		Weight::from_parts(16_116_666, 0)
			.saturating_add(Weight::from_parts(0, 3716))
			// Standard Error: 62_638
			.saturating_add(Weight::from_parts(83_333, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
			.saturating_add(Weight::from_parts(0, 1).saturating_mul(n.into()))
	}
}
