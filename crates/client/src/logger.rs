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

//! Utilities related to logging
use tokio::sync::OnceCell;
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;

/// The log output format that the application should use.
#[derive(clap::ValueEnum, Clone, Default, Debug)]
pub enum Logger {
    #[default]
    Full,
    Pretty,
    Json,
}

impl std::fmt::Display for Logger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let logger = match self {
            Logger::Full => "full",
            Logger::Pretty => "pretty",
            Logger::Json => "json",
        };
        write!(f, "{logger}")
    }
}

/// Overarching configuration settings around instrumentation and logging.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct Instrumentation {
    /// The log output format that the application should use.
    #[clap(
        long,
        default_value_t = Default::default(),
    )]
    pub logger: Logger,

    /// Whether or not logs should be sent to a Loki server.
    #[clap(long)]
    pub loki: bool,

    /// The endpoint of the Loki server to send logs to.
    #[clap(long, default_value = "http://127.0.0.1:3100")]
    pub loki_endpoint: String,
}

impl Instrumentation {
    /// Configures and initializes the global `tracing` Subscriber.
    pub async fn setup(&self) {
        // We set up the logger to only print out logs of `INFO` or higher by default, otherwise we
        // fall back to the user's `RUST_LOG` settings.
        let stdout = tracing_subscriber::fmt::layer();
        let env_filter = tracing_subscriber::EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();
        let registry = tracing_subscriber::registry().with(env_filter);

        // Depending on our configuration we'll end up with a dynamic number of layers
        let mut layers = Vec::new();

        match self.logger {
            Logger::Full => layers.push(stdout.boxed()),
            Logger::Pretty => layers.push(stdout.pretty().boxed()),
            Logger::Json => {
                let name = format!(
                    "{}@{}-{}",
                    env!("CARGO_PKG_NAME"),
                    env!("CARGO_PKG_VERSION"),
                    env!("VERGEN_GIT_DESCRIBE")
                );
                let bunyan_layer = BunyanFormattingLayer::new(name, std::io::stdout);
                layers.push(JsonStorageLayer.boxed());
                layers.push(bunyan_layer.boxed());
            },
        }

        if self.loki {
            let hostname = hostname::get().unwrap();
            let (loki_layer, task) = tracing_loki::builder()
                .label("appname", env!("CARGO_PKG_NAME"))
                .unwrap()
                .label("version", env!("CARGO_PKG_VERSION"))
                .unwrap()
                .label("hostname", hostname.to_str().unwrap_or_default())
                .unwrap()
                .extra_field("git-info", env!("VERGEN_GIT_DESCRIBE"))
                .unwrap()
                .extra_field("pid", format!("{}", std::process::id()))
                .unwrap()
                .build_url(reqwest::Url::parse(&self.loki_endpoint).unwrap())
                .unwrap();

            // This will spawn a background task which sends our logs to the provided Loki endpoint.
            tokio::spawn(task);
            layers.push(loki_layer.boxed());
        }

        registry.with(layers).init();
    }
}

/// A shared reference to the logger used for tests.
///
/// Since this only needs to be initialized once for the whole test suite we define it as a
/// async-friendly static.
pub static LOGGER: OnceCell<()> = OnceCell::const_new();

/// Initialize the global logger used in tests.
///
/// The logger will only be initialized once, even if this function is called multiple times.
pub async fn initialize_test_logger() {
    let instrumentation = Instrumentation { logger: Logger::Pretty, ..Default::default() };
    *LOGGER.get_or_init(|| instrumentation.setup()).await
}
