#![cfg_attr(not(feature = "std"), no_std)]

pub mod errors {
	#[macro_export]
	macro_rules! unwrap_or_return {
		( $e:expr ) => {
			match $e {
				Ok(x) => x,
				Err(_) => return,
			}
		}
	}

	#[macro_export]
	macro_rules! unwrap_or_return_db_read {
		( $e:expr ) => {
			match $e {
				Some(x) => x,
				None => return T::DbWeight::get().reads(1)
			}
		}
	}

}
