use std::time::Duration;

use mycroft_manifest::ControlMode;

use crate::result::NetworkRoute;

pub const DEFAULT_USER_AGENT: &str =
  "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0";

pub const DEFAULT_MAX_BODY_HARD_CAP: usize = 2 * 1024 * 1024;

pub const TOR_PROXY_URL: &str = "socks5h://127.0.0.1:9050";

#[derive(Clone, Debug)]
pub struct SchedulerLimits {
  pub global_concurrency: usize,
  pub per_host_concurrency: usize,
  pub per_host_rps: f64,
  pub per_host_burst: u32,
}

impl Default for SchedulerLimits {
  fn default() -> Self {
    Self {
      global_concurrency: 40,
      per_host_concurrency: 2,
      per_host_rps: 1.0,
      per_host_burst: 2,
    }
  }
}

#[derive(Clone, Copy, Debug)]
pub struct TimeoutConfig {
  pub connect_timeout: Duration,
  pub request_timeout: Duration,
}

impl Default for TimeoutConfig {
  fn default() -> Self {
    Self {
      connect_timeout: Duration::from_secs(4),
      request_timeout: Duration::from_secs(12),
    }
  }
}

#[derive(Clone, Copy, Debug)]
pub struct RetryConfig {
  pub max_retries: u8,
  pub base_backoff: Duration,
  pub max_backoff: Duration,
}

impl Default for RetryConfig {
  fn default() -> Self {
    Self {
      max_retries: 1,
      base_backoff: Duration::from_millis(500),
      max_backoff: Duration::from_secs(5),
    }
  }
}

#[derive(Clone, Debug)]
pub struct ProxyConfig {
  pub url: String,
  pub route: NetworkRoute,
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
  pub limits: SchedulerLimits,
  pub timeouts: TimeoutConfig,
  pub retries: RetryConfig,
  pub control_mode: ControlMode,
  pub proxy: Option<ProxyConfig>,
  pub user_agent: String,
  pub allow_private_targets: bool,
  pub max_body_bytes_hard_cap: usize,
}

impl Default for RuntimeConfig {
  fn default() -> Self {
    Self {
      limits: SchedulerLimits::default(),
      timeouts: TimeoutConfig::default(),
      retries: RetryConfig::default(),
      control_mode: ControlMode::Auto,
      proxy: None,
      user_agent: DEFAULT_USER_AGENT.to_string(),
      allow_private_targets: false,
      max_body_bytes_hard_cap: DEFAULT_MAX_BODY_HARD_CAP,
    }
  }
}

impl RuntimeConfig {
  #[must_use]
  pub fn network_route(&self) -> NetworkRoute {
    self
      .proxy
      .as_ref()
      .map_or(NetworkRoute::Direct, |p| p.route)
  }
}
