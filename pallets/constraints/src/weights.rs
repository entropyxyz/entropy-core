#![allow(clippy::all)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{
    traits::Get,
    weights::{constants::RocksDbWeight, Weight},
};
use sp_std::marker::PhantomData;

// The weight info trait for `pallet_constraints`.
pub trait WeightInfo {
    fn update_constraints(a: u32, b: u32) -> Weight;
    fn update_v2_constraints() -> Weight;
}

pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    /// Storage: Constraints AllowedToModifyConstraints (r:1 w:0)
    /// Proof Skipped: Constraints AllowedToModifyConstraints (max_values: None, max_size: None,
    /// mode: Measured) Storage: Constraints EvmAcl (r:0 w:1)
    /// Proof Skipped: Constraints EvmAcl (max_values: None, max_size: None, mode: Measured)
    /// Storage: Constraints BtcAcl (r:0 w:1)
    /// Proof Skipped: Constraints BtcAcl (max_values: None, max_size: None, mode: Measured)
    /// Storage: Constraints ActiveArchitectures (r:0 w:2)
    /// Proof Skipped: Constraints ActiveArchitectures (max_values: None, max_size: None, mode:
    /// Measured) The range of component `a` is `[0, 25]`.
    /// The range of component `b` is `[0, 25]`.
    fn update_constraints(a: u32, b: u32) -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `236`
        //  Estimated: `3701`
        // Minimum execution time: 40_000_000 picoseconds.
        Weight::from_parts(40_415_010, 0)
			.saturating_add(Weight::from_parts(0, 3701))
			// Standard Error: 3_735
			.saturating_add(Weight::from_parts(49_613, 0).saturating_mul(a.into()))
			// Standard Error: 3_735
			.saturating_add(Weight::from_parts(73_778, 0).saturating_mul(b.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(4))
    }

    /// Storage: Constraints AllowedToModifyConstraints (r:1 w:0)
    /// Proof Skipped: Constraints AllowedToModifyConstraints (max_values: None, max_size: None,
    /// mode: Measured) Storage: Constraints V2Bytecode (r:1 w:1)
    /// Proof Skipped: Constraints V2Bytecode (max_values: None, max_size: None, mode: Measured)
    fn update_v2_constraints() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `236`
        //  Estimated: `3701`
        // Minimum execution time: 54_000_000 picoseconds.
        Weight::from_parts(55_000_000, 0)
            .saturating_add(Weight::from_parts(0, 3701))
            .saturating_add(T::DbWeight::get().reads(2))
            .saturating_add(T::DbWeight::get().writes(1))
    }
}

// For backwards compatibility and tests
impl WeightInfo for () {
    /// Storage: Constraints AllowedToModifyConstraints (r:1 w:0)
    /// Proof Skipped: Constraints AllowedToModifyConstraints (max_values: None, max_size: None,
    /// mode: Measured) Storage: Constraints EvmAcl (r:0 w:1)
    /// Proof Skipped: Constraints EvmAcl (max_values: None, max_size: None, mode: Measured)
    /// Storage: Constraints BtcAcl (r:0 w:1)
    /// Proof Skipped: Constraints BtcAcl (max_values: None, max_size: None, mode: Measured)
    /// Storage: Constraints ActiveArchitectures (r:0 w:2)
    /// Proof Skipped: Constraints ActiveArchitectures (max_values: None, max_size: None, mode:
    /// Measured) The range of component `a` is `[0, 25]`.
    /// The range of component `b` is `[0, 25]`.
    fn update_constraints(a: u32, b: u32) -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `236`
        //  Estimated: `3701`
        // Minimum execution time: 40_000_000 picoseconds.
        Weight::from_parts(40_415_010, 0)
			.saturating_add(Weight::from_parts(0, 3701))
			// Standard Error: 3_735
			.saturating_add(Weight::from_parts(49_613, 0).saturating_mul(a.into()))
			// Standard Error: 3_735
			.saturating_add(Weight::from_parts(73_778, 0).saturating_mul(b.into()))
			.saturating_add(RocksDbWeight::get().reads(1))
			.saturating_add(RocksDbWeight::get().writes(4))
    }

    /// Storage: Constraints AllowedToModifyConstraints (r:1 w:0)
    /// Proof Skipped: Constraints AllowedToModifyConstraints (max_values: None, max_size: None,
    /// mode: Measured) Storage: Constraints V2Bytecode (r:1 w:1)
    /// Proof Skipped: Constraints V2Bytecode (max_values: None, max_size: None, mode: Measured)
    fn update_v2_constraints() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `236`
        //  Estimated: `3701`
        // Minimum execution time: 54_000_000 picoseconds.
        Weight::from_parts(55_000_000, 0)
            .saturating_add(Weight::from_parts(0, 3701))
            .saturating_add(RocksDbWeight::get().reads(2))
            .saturating_add(RocksDbWeight::get().writes(1))
    }
}
