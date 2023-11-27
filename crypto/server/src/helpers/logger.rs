use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;

/// The log output format that the application should use.
#[derive(Clone, Default, Debug, clap::ValueEnum)]
pub enum Logger {
    #[default]
    Full,
    Pretty,
    Json,
    Loki,
}

impl Logger {
    /// Configures and initializes the global `tracing` Subscriber.
    pub async fn setup(&self) {
        // We set up the logger to only print out logs of `INFO` or higher by default, otherwise we
        // fall back to the user's `RUST_LOG` settings.
        let stdout = tracing_subscriber::fmt::layer();
        let env_filter = tracing_subscriber::EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();
        let registry = tracing_subscriber::registry().with(env_filter);

        match self {
            Logger::Full => registry.with(stdout).init(),
            Logger::Pretty => registry.with(stdout.pretty()).init(),
            Logger::Json => {
                let name = format!(
                    "{}@{}-{}",
                    env!("CARGO_PKG_NAME"),
                    env!("CARGO_PKG_VERSION"),
                    env!("VERGEN_GIT_DESCRIBE")
                );
                let bunyan_layer = BunyanFormattingLayer::new(name, std::io::stdout);
                registry.with(JsonStorageLayer).with(bunyan_layer).init()
            },
            Logger::Loki => {
                let name = format!(
                    "{}@{}-{}",
                    env!("CARGO_PKG_NAME"),
                    env!("CARGO_PKG_VERSION"),
                    env!("VERGEN_GIT_DESCRIBE")
                );
                let bunyan_layer = BunyanFormattingLayer::new(name, std::io::stdout);

                let (loki_layer, task) = tracing_loki::builder()
                    .label("process", "tss-server")
                    .unwrap()
                    // .extra_field("pid", format!("{}", std::process::id()))
                    // .unwrap()
                    .build_url(reqwest::Url::parse("http://localhost:3100").unwrap())
                    .unwrap();

                tokio::spawn(task);

                registry.with(stdout).with(loki_layer).init();

                tracing::info!("Spawned Loki");
            },
        }
    }
}

impl std::fmt::Display for Logger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let logger = match self {
            Logger::Full => "full",
            Logger::Pretty => "pretty",
            Logger::Json => "json",
            Logger::Loki => "loki",
        };
        write!(f, "{}", logger)
    }
}
