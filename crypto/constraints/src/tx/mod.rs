// //! This module provides generic transaction types for constraints to use, unsigned transaction
// //! parsing utilities, and architecture information about the differet ways transactions are
// handled //! on each platform (EVM, BTC, Substrate, etc).
pub mod evm;
pub mod utils;

pub enum Arch {
    EVM,
    BTC,
}
