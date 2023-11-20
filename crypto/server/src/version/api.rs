pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn version() -> String {
    VERSION.to_string()
}
