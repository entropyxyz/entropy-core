#[macro_use]
extern crate lazy_static;

mod chain_api;
pub mod constants;
mod node_proc;
pub mod substrate_context;
pub mod test_client;
pub use node_proc::TestNodeProcess;
pub use substrate_context::*;
