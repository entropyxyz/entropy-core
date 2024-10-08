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

//! Autogenerated weights for `pallet_attestation`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 33.0.0
//! DATE: 2024-10-03, STEPS: `25`, REPEAT: `10`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `ip-172-31-28-93`, CPU: `Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("dev")`, DB CACHE: 1024

// Executed Command:
// ./target/release/entropy
// benchmark
// pallet
// --chain
// dev
// --wasm-execution=compiled
// --pallet=pallet_attestation
// --extrinsic=*
// --steps=25
// --repeat=10
// --header=.maintain/AGPL-3.0-header.txt
// --template
// .maintain/frame-weight-template.hbs
// --output=./runtime/src/weights/

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `pallet_attestation`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_attestation::WeightInfo for WeightInfo<T> {
	/// Storage: `Attestation::PendingAttestations` (r:1 w:1)
	/// Proof: `Attestation::PendingAttestations` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `StakingExtension::ValidationQueue` (r:2 w:2)
	/// Proof: `StakingExtension::ValidationQueue` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Parameters::AcceptedMrtdValues` (r:1 w:0)
	/// Proof: `Parameters::AcceptedMrtdValues` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `StakingExtension::CounterForValidationQueue` (r:1 w:1)
	/// Proof: `StakingExtension::CounterForValidationQueue` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	fn attest() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `867`
		//  Estimated: `6807`
		// Minimum execution time: 4_202_199_000 picoseconds.
		Weight::from_parts(4_248_856_000, 0)
			.saturating_add(Weight::from_parts(0, 6807))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(4))
	}
	/// Storage: `StakingExtension::ValidationQueue` (r:251 w:0)
	/// Proof: `StakingExtension::ValidationQueue` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Attestation::AttestationRequests` (r:1 w:1)
	/// Proof: `Attestation::AttestationRequests` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Babe::NextRandomness` (r:1 w:0)
	/// Proof: `Babe::NextRandomness` (`max_values`: Some(1), `max_size`: Some(32), added: 527, mode: `MaxEncodedLen`)
	/// Storage: `Babe::EpochStart` (r:1 w:0)
	/// Proof: `Babe::EpochStart` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `MaxEncodedLen`)
	/// Storage: `Attestation::PendingAttestations` (r:0 w:250)
	/// Proof: `Attestation::PendingAttestations` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `s` is `[1, 250]`.
	fn on_initialize(s: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `715 + s * (208 ±0)`
		//  Estimated: `4181 + s * (2684 ±0)`
		// Minimum execution time: 33_792_000 picoseconds.
		Weight::from_parts(15_857_412, 0)
			.saturating_add(Weight::from_parts(0, 4181))
			// Standard Error: 15_260
			.saturating_add(Weight::from_parts(10_380_520, 0).saturating_mul(s.into()))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(s.into())))
			.saturating_add(T::DbWeight::get().writes(1))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(s.into())))
			.saturating_add(Weight::from_parts(0, 2684).saturating_mul(s.into()))
	}
}