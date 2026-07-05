use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use mycroft_core::config::{
  DEFAULT_USER_AGENT, ProxyConfig, RuntimeConfig, TOR_PROXY_URL,
};
use mycroft_core::result::NetworkRoute;
use mycroft_manifest::ManifestDefaults;
use mycroft_manifest::schema::ControlMode;

use crate::args::{
  CheckArgs, CheckNetworkArgs, CheckOutputArgs, ControlModeArg, FormatArg,
  GithubArgs, PrintArg,
};

#[derive(Debug, Default, Deserialize)]
pub struct FileConfig {
  #[serde(default)]
  pub scan: ScanSection,
  #[serde(default)]
  pub network: NetworkSection,
  #[serde(default)]
  pub manifest: ManifestSection,
  #[serde(default)]
  pub output: OutputSection,
}

#[derive(Debug, Default, Deserialize)]
pub struct ScanSection {
  pub include_nsfw: Option<bool>,
  pub control_mode: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct NetworkSection {
  pub max_concurrency: Option<usize>,
  pub per_host_concurrency: Option<usize>,
  pub per_host_rps: Option<f64>,
  pub retries: Option<u8>,
  pub proxy: Option<String>,
  pub proxy_required: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ManifestSection {
  pub path: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct OutputSection {
  pub format: Option<String>,
  pub print: Option<String>,
  pub progress: Option<bool>,
}

#[must_use]
pub fn config_path() -> Option<PathBuf> {
  directories::ProjectDirs::from("", "", "mycroft")
    .map(|dirs| dirs.config_dir().join("config.toml"))
}

pub fn load() -> Result<FileConfig, String> {
  let Some(path) = config_path() else {
    return Ok(FileConfig::default());
  };
  let contents = match std::fs::read_to_string(&path) {
    Ok(contents) => contents,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      return Ok(FileConfig::default());
    }
    Err(error) => {
      return Err(format!("failed to read {}: {error}", path.display()));
    }
  };
  toml::from_str(&contents)
    .map_err(|error| format!("failed to parse {}: {error}", path.display()))
}

fn env_var(name: &str) -> Option<String> {
  std::env::var(name).ok().filter(|s| !s.is_empty())
}

#[derive(Debug, Clone)]
pub enum ManifestSource {
  Bundled,
  Path(PathBuf),
  Url(String),
}

#[must_use]
pub fn resolve_manifest_source(
  args: &CheckArgs,
  file: &FileConfig,
) -> ManifestSource {
  let raw = args
    .manifest_source
    .manifest
    .clone()
    .or_else(|| env_var("MYCROFT_MANIFEST"))
    .or_else(|| file.manifest.path.clone());
  match raw {
    None => ManifestSource::Bundled,
    Some(s) if s.starts_with("http://") || s.starts_with("https://") => {
      ManifestSource::Url(s)
    }
    Some(s) => ManifestSource::Path(s.into()),
  }
}

pub struct ResolvedSettings {
  pub runtime: RuntimeConfig,
  pub format: FormatArg,
  pub print: PrintArg,
  pub progress: bool,
  pub include_nsfw: bool,
  pub proxy_required: bool,
}

pub struct ResolvedGithubSettings {
  pub runtime: RuntimeConfig,
  pub format: FormatArg,
  pub progress: bool,
  pub proxy_required: bool,
}

#[must_use]
pub fn resolve_settings(
  args: &CheckArgs,
  file: &FileConfig,
  defaults: &ManifestDefaults,
) -> ResolvedSettings {
  let runtime = resolve_runtime(
    &args.network,
    args.detection.control_mode,
    file,
    Some(defaults),
  );
  let format = resolve_format(&args.output, file);
  let progress = resolve_progress(&args.output, format, file);
  ResolvedSettings {
    runtime,
    format,
    print: resolve_print(args, file),
    progress,
    include_nsfw: args.input.include_nsfw
      || file.scan.include_nsfw.unwrap_or(false),
    proxy_required: resolve_proxy_required(&args.network, file),
  }
}

#[must_use]
pub fn resolve_github_settings(
  args: &GithubArgs,
  file: &FileConfig,
) -> ResolvedGithubSettings {
  let runtime = resolve_runtime(&args.network, None, file, None);
  let format = resolve_format(&args.output, file);
  let progress = resolve_progress(&args.output, format, file);
  ResolvedGithubSettings {
    runtime,
    format,
    progress,
    proxy_required: resolve_proxy_required(&args.network, file),
  }
}

fn resolve_progress(
  output: &CheckOutputArgs,
  format: FormatArg,
  file: &FileConfig,
) -> bool {
  !output.no_progress
    && !output.quiet
    && format == FormatArg::Human
    && file.output.progress.unwrap_or(true)
}

#[must_use]
fn resolve_proxy_required(
  network: &CheckNetworkArgs,
  file: &FileConfig,
) -> bool {
  network.proxy_required
    || env_var("MYCROFT_PROXY_REQUIRED")
      .is_some_and(|v| v == "1" || v == "true")
    || file.network.proxy_required.unwrap_or(false)
}

fn resolve_format(output: &CheckOutputArgs, file: &FileConfig) -> FormatArg {
  if let Some(format) = output.format {
    return format;
  }
  if let Some(format) = env_var("MYCROFT_FORMAT")
    .as_deref()
    .and_then(format_from_str)
  {
    return format;
  }
  file
    .output
    .format
    .as_deref()
    .and_then(format_from_str)
    .unwrap_or(FormatArg::Human)
}

fn format_from_str(s: &str) -> Option<FormatArg> {
  match s.to_ascii_lowercase().as_str() {
    "human" => Some(FormatArg::Human),
    "json" => Some(FormatArg::Json),
    "ndjson" => Some(FormatArg::Ndjson),
    "csv" => Some(FormatArg::Csv),
    _ => None,
  }
}

fn resolve_print(args: &CheckArgs, file: &FileConfig) -> PrintArg {
  if let Some(print) = args.detection.print {
    return print;
  }
  match file.output.print.as_deref() {
    Some("all") => PrintArg::All,
    Some("uncertain") => PrintArg::Uncertain,
    Some("errors") => PrintArg::Errors,
    _ => PrintArg::Found,
  }
}

fn resolve_runtime(
  network: &CheckNetworkArgs,
  control_mode: Option<ControlModeArg>,
  file: &FileConfig,
  defaults: Option<&ManifestDefaults>,
) -> RuntimeConfig {
  let mut rc = RuntimeConfig::default();

  if let Some(defaults) = defaults {
    rc.timeouts.request_timeout = Duration::from_millis(defaults.timeout_ms);
    rc.timeouts.connect_timeout =
      Duration::from_millis(defaults.connect_timeout_ms);
    rc.control_mode = defaults.control_mode;
    rc.max_body_bytes_hard_cap =
      rc.max_body_bytes_hard_cap.max(defaults.max_body_bytes);
  }

  if let Some(t) = network.timeout {
    rc.timeouts.request_timeout = t;
  }
  if let Some(r) = network.retries.or(file.network.retries) {
    rc.retries.max_retries = r;
  }

  rc.control_mode = control_mode
    .map(control_mode_from_arg)
    .or_else(|| {
      env_var("MYCROFT_CONTROL_MODE")
        .as_deref()
        .and_then(control_mode_from_str)
    })
    .or_else(|| {
      file
        .scan
        .control_mode
        .as_deref()
        .and_then(control_mode_from_str)
    })
    .unwrap_or(rc.control_mode);

  if let Some(n) = network
    .max_concurrency
    .or_else(|| env_var("MYCROFT_MAX_CONCURRENCY").and_then(|s| s.parse().ok()))
    .or(file.network.max_concurrency)
  {
    rc.limits.global_concurrency = n.max(1);
  }
  if let Some(n) = network
    .per_host_concurrency
    .or(file.network.per_host_concurrency)
  {
    rc.limits.per_host_concurrency = n.max(1);
  }
  if let Some(r) = network
    .per_host_rps
    .or_else(|| env_var("MYCROFT_PER_HOST_RPS").and_then(|s| s.parse().ok()))
    .or(file.network.per_host_rps)
  {
    rc.limits.per_host_rps = r;
  }

  rc.proxy = resolve_proxy(network, file);

  rc.user_agent = network
    .user_agent
    .clone()
    .or_else(|| defaults.and_then(|defaults| defaults.user_agent.clone()))
    .unwrap_or_else(|| DEFAULT_USER_AGENT.to_string());

  rc.allow_private_targets = network.allow_private_targets;

  rc
}

fn resolve_proxy(
  network: &CheckNetworkArgs,
  file: &FileConfig,
) -> Option<ProxyConfig> {
  if network.tor {
    return Some(ProxyConfig {
      url: TOR_PROXY_URL.to_string(),
      route: NetworkRoute::Tor,
    });
  }
  let url = network
    .proxy
    .clone()
    .or_else(|| env_var("MYCROFT_PROXY"))
    .or_else(|| file.network.proxy.clone())?;
  Some(ProxyConfig {
    url,
    route: NetworkRoute::Proxy,
  })
}

const fn control_mode_from_arg(arg: ControlModeArg) -> ControlMode {
  match arg {
    ControlModeArg::Off => ControlMode::Off,
    ControlModeArg::Auto => ControlMode::Auto,
    ControlModeArg::Strict => ControlMode::Strict,
  }
}

fn control_mode_from_str(s: &str) -> Option<ControlMode> {
  match s.to_ascii_lowercase().as_str() {
    "off" => Some(ControlMode::Off),
    "auto" => Some(ControlMode::Auto),
    "strict" => Some(ControlMode::Strict),
    _ => None,
  }
}
