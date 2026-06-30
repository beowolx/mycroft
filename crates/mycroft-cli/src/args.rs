use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};

const ABOUT: &str = "mycroft - accuracy-focused OSINT username checker.

Find usernames across the web and uncover connections with advanced OSINT tooling.";

#[derive(Debug, Parser)]
#[command(name = "mycroft", version, about = ABOUT)]
pub struct Cli {
  #[command(subcommand)]
  pub command: Commands,
}

#[derive(Debug, Subcommand)]
#[expect(
  clippy::large_enum_variant,
  reason = "clap derive owns subcommand payloads"
)]
pub enum Commands {
  Check(CheckArgs),
  Sites {
    #[command(subcommand)]
    cmd: SitesCmd,
  },
  Manifest {
    #[command(subcommand)]
    cmd: ManifestCmd,
  },
  Completions {
    shell: clap_complete::Shell,
  },
}

#[derive(Debug, Subcommand)]
pub enum SitesCmd {
  List {
    #[arg(long)]
    manifest: Option<String>,
    #[arg(long)]
    include_nsfw: bool,
  },
  Show {
    site: String,
    #[arg(long)]
    manifest: Option<String>,
  },
}

#[derive(Debug, Subcommand)]
pub enum ManifestCmd {
  Validate { path: Option<PathBuf> },
  ImportCatalog { data_json: PathBuf },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FormatArg {
  Human,
  Json,
  Ndjson,
  Csv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PrintArg {
  Found,
  All,
  Uncertain,
  Errors,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ControlModeArg {
  Off,
  Auto,
  Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOnArg {
  None,
  Found,
  Uncertain,
  NotFound,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
  pub usernames: Vec<String>,

  #[command(flatten)]
  pub input: CheckInputArgs,
  #[command(flatten)]
  pub manifest_source: CheckManifestArgs,
  #[command(flatten)]
  pub detection: CheckDetectionArgs,
  #[command(flatten)]
  pub network: CheckNetworkArgs,
  #[command(flatten)]
  pub output: CheckOutputArgs,
  #[command(flatten)]
  pub policy: CheckPolicyArgs,
}

#[derive(Debug, Args)]
pub struct CheckInputArgs {
  #[arg(long)]
  pub usernames_file: Option<PathBuf>,
  #[arg(long)]
  pub variant_placeholder: bool,
  #[arg(long = "site")]
  pub sites: Vec<String>,
  #[arg(long = "exclude-site")]
  pub exclude_sites: Vec<String>,
  #[arg(long = "tag")]
  pub tags: Vec<String>,
  #[arg(long = "exclude-tag")]
  pub exclude_tags: Vec<String>,
  #[arg(long)]
  pub include_nsfw: bool,
}

#[derive(Debug, Args)]
pub struct CheckManifestArgs {
  #[arg(long)]
  pub manifest: Option<String>,
}

#[derive(Debug, Args)]
pub struct CheckDetectionArgs {
  #[arg(long, value_enum)]
  pub control_mode: Option<ControlModeArg>,
  #[arg(long, value_enum)]
  pub print: Option<PrintArg>,
}

#[derive(Debug, Args)]
pub struct CheckNetworkArgs {
  #[arg(long, value_parser = parse_duration)]
  pub timeout: Option<Duration>,
  #[arg(long)]
  pub retries: Option<u8>,
  #[arg(long)]
  pub max_concurrency: Option<usize>,
  #[arg(long)]
  pub per_host_concurrency: Option<usize>,
  #[arg(long)]
  pub per_host_rps: Option<f64>,
  #[arg(long)]
  pub proxy: Option<String>,
  #[arg(long)]
  pub tor: bool,
  #[arg(long)]
  pub proxy_required: bool,
  #[arg(long)]
  pub user_agent: Option<String>,
  #[arg(long)]
  pub allow_private_targets: bool,
}

#[derive(Debug, Args)]
pub struct CheckOutputArgs {
  #[arg(long, value_enum)]
  pub format: Option<FormatArg>,
  #[arg(long = "output")]
  pub output_path: Option<PathBuf>,
  #[arg(long)]
  pub no_progress: bool,
  #[arg(long)]
  pub quiet: bool,
  #[arg(long)]
  pub verbose: bool,
}

#[derive(Debug, Args)]
pub struct CheckPolicyArgs {
  #[arg(long, value_enum)]
  pub fail_on: Option<FailOnArg>,
  #[arg(long)]
  pub fail_on_partial: bool,
}

fn parse_duration(raw: &str) -> Result<Duration, String> {
  let raw = raw.trim();
  let (num, secs_per_unit) = [("ms", 0.001), ("s", 1.0), ("m", 60.0)]
    .into_iter()
    .find_map(|(suffix, mult)| raw.strip_suffix(suffix).map(|n| (n, mult)))
    .unwrap_or((raw, 1.0));
  let value = num
    .parse::<f64>()
    .map_err(|_| format!("invalid duration: '{raw}'"))?;
  Duration::try_from_secs_f64(value * secs_per_unit)
    .map_err(|_| format!("invalid duration: '{raw}'"))
}
