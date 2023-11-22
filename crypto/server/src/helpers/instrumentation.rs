use tracing_subscriber::prelude::*;

#[derive(clap::Args, Debug, Default, Clone)]
pub struct Instrumentation {
    #[clap(
        long,
        default_value_t = Default::default(),
    )]
    pub logger: Logger,
}

impl Instrumentation {
    pub fn setup(&self) {
        // We set up the logger to only print out logs of `ERROR` or higher by default, otherwise we
        // fall back to the user's `RUST_LOG` settings.
        let stdout = tracing_subscriber::fmt::layer();
        let env_filter = tracing_subscriber::EnvFilter::from_default_env();
        let registry = tracing_subscriber::registry().with(stdout).with(env_filter);

        match self.logger {
            Logger::Full => registry.init(),
            Logger::Pretty => registry.with(tracing_subscriber::fmt::layer().pretty()).init(),
            Logger::Json => registry.with(tracing_subscriber::fmt::layer().json()).init(),
        }
    }
}

#[derive(Clone, Default, Debug, clap::ValueEnum)]
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
