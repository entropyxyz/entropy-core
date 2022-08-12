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
