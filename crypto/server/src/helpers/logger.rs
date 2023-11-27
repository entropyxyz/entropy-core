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
        write!(f, "{}", logger)
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
    pub(crate) logger: Logger,

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
            let name = format!(
                "{}@{}-{}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
                env!("VERGEN_GIT_DESCRIBE")
            );

            let (loki_layer, task) = tracing_loki::builder()
                    .label("process", name)
                    .unwrap()
                    // .extra_field("pid", format!("{}", std::process::id()))
                    // .unwrap()
                    .build_url(reqwest::Url::parse(&self.loki_endpoint).unwrap())
                    .unwrap();

            // This will spawn a background task which sends our logs to the provided Loki endpoint.
            tokio::spawn(task);
            layers.push(loki_layer.boxed());
        }

        registry.with(layers).init();
    }
}
