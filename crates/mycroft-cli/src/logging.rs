use tracing_subscriber::EnvFilter;

pub fn init(verbose: bool, quiet: bool) {
  let default_level = if quiet {
    "error"
  } else if verbose {
    "debug"
  } else {
    "warn"
  };
  let filter = EnvFilter::try_from_env("MYCROFT_LOG")
    .unwrap_or_else(|_| EnvFilter::new(default_level));

  let _ = tracing_subscriber::fmt()
    .with_env_filter(filter)
    .with_writer(std::io::stderr)
    .compact()
    .try_init();
}
