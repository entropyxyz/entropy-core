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

//! Autogenerated weights for `pallet_collective`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 33.0.0
//! DATE: 2024-06-26, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `ip-172-31-30-92`, CPU: `Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("dev")`, DB CACHE: 1024

// Executed Command:
// ./target/release/entropy
// benchmark
// pallet
// --chain
// dev
// --wasm-execution=compiled
// --pallet=pallet_collective
// --extrinsic=*
// --steps=50
// --repeat=20
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

/// Weight functions for `pallet_collective`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_collective::WeightInfo for WeightInfo<T> {
	/// Storage: `Council::Members` (r:1 w:1)
	/// Proof: `Council::Members` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Council::Proposals` (r:1 w:0)
	/// Proof: `Council::Proposals` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Council::Voting` (r:100 w:100)
	/// Proof: `Council::Voting` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Council::Prime` (r:0 w:1)
	/// Proof: `Council::Prime` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// The range of component `m` is `[0, 100]`.
	/// The range of component `n` is `[0, 100]`.
	/// The range of component `p` is `[0, 100]`.
	fn set_members(m: u32, _n: u32, p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0 + m * (3232 ±0) + p * (3190 ±0)`
		//  Estimated: `15762 + m * (1967 ±24) + p * (4332 ±24)`
		// Minimum execution time: 19_377_000 picoseconds.
		Weight::from_parts(19_795_000, 0)
			.saturating_add(Weight::from_parts(0, 15762))
			// Standard Error: 65_832
			.saturating_add(Weight::from_parts(4_791_870, 0).saturating_mul(m.into()))
			// Standard Error: 65_832
			.saturating_add(Weight::from_parts(9_603_853, 0).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(p.into())))
			.saturating_add(T::DbWeight::get().writes(2))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(p.into())))
			.saturating_add(Weight::from_parts(0, 1967).saturating_mul(m.into()))
			.saturating_add(Weight::from_parts(0, 4332).saturating_mul(p.into()))
	}
	/// Storage: `Council::Members` (r:1 w:0)
	/// Proof: `Council::Members` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// The range of component `b` is `[2, 1024]`.
	/// The range of component `m` is `[1, 100]`.
	fn execute(b: u32, m: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `103 + m * (32 ±0)`
		//  Estimated: `1589 + m * (32 ±0)`
		// Minimum execution time: 17_856_000 picoseconds.
		Weight::from_parts(17_080_027, 0)
			.saturating_add(Weight::from_parts(0, 1589))
			// Standard Error: 43
			.saturating_add(Weight::from_parts(1_816, 0).saturating_mul(b.into()))
			// Standard Error: 449
			.saturating_add(Weight::from_parts(16_602, 0).saturating_mul(m.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(Weight::from_parts(0, 32).saturating_mul(m.into()))
	}
	/// Storage: `Council::Members` (r:1 w:0)
	/// Proof: `Council::Members` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Council::ProposalOf` (r:1 w:0)
	/// Proof: `Council::ProposalOf` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `b` is `[2, 1024]`.
	/// The range of component `m` is `[1, 100]`.
	fn propose_execute(b: u32, m: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `103 + m * (32 ±0)`
		//  Estimated: `3569 + m * (32 ±0)`
		// Minimum execution time: 21_587_000 picoseconds.
		Weight::from_parts(20_590_965, 0)
			.saturating_add(Weight::from_parts(0, 3569))
			// Standard Error: 56
			.saturating_add(Weight::from_parts(1_994, 0).saturating_mul(b.into()))
			// Standard Error: 581
			.saturating_add(Weight::from_parts(30_309, 0).saturating_mul(m.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(Weight::from_parts(0, 32).saturating_mul(m.into()))
	}
	/// Storage: `Council::Members` (r:1 w:0)
	/// Proof: `Council::Members` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Council::ProposalOf` (r:1 w:1)
	/// Proof: `Council::ProposalOf` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Council::Proposals` (r:1 w:1)
	/// Proof: `Council::Proposals` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Council::ProposalCount` (r:1 w:1)
	/// Proof: `Council::ProposalCount` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Council::Voting` (r:0 w:1)
	/// Proof: `Council::Voting` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `b` is `[2, 1024]`.
	/// The range of component `m` is `[2, 100]`.
	/// The range of component `p` is `[1, 100]`.
	fn propose_proposed(b: u32, m: u32, p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `368 + m * (32 ±0) + p * (36 ±0)`
		//  Estimated: `3806 + m * (33 ±0) + p * (37 ±0)`
		// Minimum execution time: 29_038_000 picoseconds.
		Weight::from_parts(27_908_197, 0)
			.saturating_add(Weight::from_parts(0, 3806))
			// Standard Error: 98
			.saturating_add(Weight::from_parts(4_475, 0).saturating_mul(b.into()))
			// Standard Error: 1_027
			.saturating_add(Weight::from_parts(17_935, 0).saturating_mul(m.into()))
			// Standard Error: 1_014
			.saturating_add(Weight::from_parts(265_494, 0).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(4))
			.saturating_add(Weight::from_parts(0, 33).saturating_mul(m.into()))
			.saturating_add(Weight::from_parts(0, 37).saturating_mul(p.into()))
	}
	/// Storage: `Council::Members` (r:1 w:0)
	/// Proof: `Council::Members` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Council::Voting` (r:1 w:1)
	/// Proof: `Council::Voting` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `m` is `[5, 100]`.
	fn vote(m: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `969 + m * (64 ±0)`
		//  Estimated: `4433 + m * (64 ±0)`
		// Minimum execution time: 28_630_000 picoseconds.
		Weight::from_parts(29_807_040, 0)
			.saturating_add(Weight::from_parts(0, 4433))
			// Standard Error: 800
			.saturating_add(Weight::from_parts(57_259, 0).saturating_mul(m.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
			.saturating_add(Weight::from_parts(0, 64).saturating_mul(m.into()))
	}
	/// Storage: `Council::Voting` (r:1 w:1)
	/// Proof: `Council::Voting` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Council::Members` (r:1 w:0)
	/// Proof: `Council::Members` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Council::Proposals` (r:1 w:1)
	/// Proof: `Council::Proposals` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Council::ProposalOf` (r:0 w:1)
	/// Proof: `Council::ProposalOf` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `m` is `[4, 100]`.
	/// The range of component `p` is `[1, 100]`.
	fn close_early_disapproved(m: u32, p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `459 + m * (64 ±0) + p * (37 ±0)`
		//  Estimated: `3902 + m * (64 ±0) + p * (37 ±0)`
		// Minimum execution time: 31_909_000 picoseconds.
		Weight::from_parts(31_556_028, 0)
			.saturating_add(Weight::from_parts(0, 3902))
			// Standard Error: 1_642
			.saturating_add(Weight::from_parts(45_100, 0).saturating_mul(m.into()))
			// Standard Error: 1_601
			.saturating_add(Weight::from_parts(239_172, 0).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(3))
			.saturating_add(Weight::from_parts(0, 64).saturating_mul(m.into()))
			.saturating_add(Weight::from_parts(0, 37).saturating_mul(p.into()))
	}
	/// Storage: `Council::Voting` (r:1 w:1)
	/// Proof: `Council::Voting` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Council::Members` (r:1 w:0)
	/// Proof: `Council::Members` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Council::ProposalOf` (r:1 w:1)
	/// Proof: `Council::ProposalOf` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Council::Proposals` (r:1 w:1)
	/// Proof: `Council::Proposals` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// The range of component `b` is `[2, 1024]`.
	/// The range of component `m` is `[4, 100]`.
	/// The range of component `p` is `[1, 100]`.
	fn close_early_approved(b: u32, m: u32, p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `499 + b * (1 ±0) + m * (64 ±0) + p * (42 ±0)`
		//  Estimated: `4059 + b * (1 ±0) + m * (63 ±0) + p * (42 ±0)`
		// Minimum execution time: 46_013_000 picoseconds.
		Weight::from_parts(46_383_251, 0)
			.saturating_add(Weight::from_parts(0, 4059))
			// Standard Error: 199
			.saturating_add(Weight::from_parts(3_410, 0).saturating_mul(b.into()))
			// Standard Error: 2_106
			.saturating_add(Weight::from_parts(43_608, 0).saturating_mul(m.into()))
			// Standard Error: 2_053
			.saturating_add(Weight::from_parts(265_017, 0).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(3))
			.saturating_add(Weight::from_parts(0, 1).saturating_mul(b.into()))
			.saturating_add(Weight::from_parts(0, 63).saturating_mul(m.into()))
			.saturating_add(Weight::from_parts(0, 42).saturating_mul(p.into()))
	}
	/// Storage: `Council::Voting` (r:1 w:1)
	/// Proof: `Council::Voting` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Council::Members` (r:1 w:0)
	/// Proof: `Council::Members` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Council::Prime` (r:1 w:0)
	/// Proof: `Council::Prime` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Council::Proposals` (r:1 w:1)
	/// Proof: `Council::Proposals` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Council::ProposalOf` (r:0 w:1)
	/// Proof: `Council::ProposalOf` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `m` is `[4, 100]`.
	/// The range of component `p` is `[1, 100]`.
	fn close_disapproved(m: u32, p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `479 + m * (64 ±0) + p * (37 ±0)`
		//  Estimated: `3922 + m * (64 ±0) + p * (37 ±0)`
		// Minimum execution time: 35_049_000 picoseconds.
		Weight::from_parts(34_179_615, 0)
			.saturating_add(Weight::from_parts(0, 3922))
			// Standard Error: 1_847
			.saturating_add(Weight::from_parts(49_195, 0).saturating_mul(m.into()))
			// Standard Error: 1_801
			.saturating_add(Weight::from_parts(239_343, 0).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(3))
			.saturating_add(Weight::from_parts(0, 64).saturating_mul(m.into()))
			.saturating_add(Weight::from_parts(0, 37).saturating_mul(p.into()))
	}
	/// Storage: `Council::Voting` (r:1 w:1)
	/// Proof: `Council::Voting` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Council::Members` (r:1 w:0)
	/// Proof: `Council::Members` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Council::Prime` (r:1 w:0)
	/// Proof: `Council::Prime` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Council::ProposalOf` (r:1 w:1)
	/// Proof: `Council::ProposalOf` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Council::Proposals` (r:1 w:1)
	/// Proof: `Council::Proposals` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// The range of component `b` is `[2, 1024]`.
	/// The range of component `m` is `[4, 100]`.
	/// The range of component `p` is `[1, 100]`.
	fn close_approved(b: u32, m: u32, p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `519 + b * (1 ±0) + m * (64 ±0) + p * (42 ±0)`
		//  Estimated: `4079 + b * (1 ±0) + m * (63 ±0) + p * (42 ±0)`
		// Minimum execution time: 48_355_000 picoseconds.
		Weight::from_parts(49_352_988, 0)
			.saturating_add(Weight::from_parts(0, 4079))
			// Standard Error: 186
			.saturating_add(Weight::from_parts(2_610, 0).saturating_mul(b.into()))
			// Standard Error: 1_966
			.saturating_add(Weight::from_parts(47_626, 0).saturating_mul(m.into()))
			// Standard Error: 1_917
			.saturating_add(Weight::from_parts(267_464, 0).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(3))
			.saturating_add(Weight::from_parts(0, 1).saturating_mul(b.into()))
			.saturating_add(Weight::from_parts(0, 63).saturating_mul(m.into()))
			.saturating_add(Weight::from_parts(0, 42).saturating_mul(p.into()))
	}
	/// Storage: `Council::Proposals` (r:1 w:1)
	/// Proof: `Council::Proposals` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Council::Voting` (r:0 w:1)
	/// Proof: `Council::Voting` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Council::ProposalOf` (r:0 w:1)
	/// Proof: `Council::ProposalOf` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `p` is `[1, 100]`.
	fn disapprove_proposal(p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `260 + p * (32 ±0)`
		//  Estimated: `1745 + p * (32 ±0)`
		// Minimum execution time: 17_269_000 picoseconds.
		Weight::from_parts(19_337_700, 0)
			.saturating_add(Weight::from_parts(0, 1745))
			// Standard Error: 1_411
			.saturating_add(Weight::from_parts(220_352, 0).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(3))
			.saturating_add(Weight::from_parts(0, 32).saturating_mul(p.into()))
	}
}