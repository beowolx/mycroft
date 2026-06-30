use serde::Serialize;

use crate::detect::Evidence;

pub const RESULT_SCHEMA_VERSION: &str = "mycroft.result.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScanId(pub String);

impl ScanId {
  #[must_use]
  pub fn random() -> Self {
    use rand::Rng;
    use std::fmt::Write;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    let mut hex = String::with_capacity(32);
    for byte in bytes {
      let _ = write!(hex, "{byte:02x}");
    }
    Self(hex)
  }
}

impl std::fmt::Display for ScanId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.0)
  }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
  Found,
  NotFound,
  Uncertain,
  Blocked,
  RateLimited,
  Captcha,
  LoginRequired,
  InvalidUsername,
  Skipped,
}

impl Verdict {
  #[must_use]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Found => "found",
      Self::NotFound => "not_found",
      Self::Uncertain => "uncertain",
      Self::Blocked => "blocked",
      Self::RateLimited => "rate_limited",
      Self::Captcha => "captcha",
      Self::LoginRequired => "login_required",
      Self::InvalidUsername => "invalid_username",
      Self::Skipped => "skipped",
    }
  }

  #[must_use]
  pub const fn label(self) -> &'static str {
    match self {
      Self::Found => "FOUND",
      Self::NotFound => "NOT_FOUND",
      Self::Uncertain => "UNCERTAIN",
      Self::Blocked => "BLOCKED",
      Self::RateLimited => "RATE_LIMIT",
      Self::Captcha => "CAPTCHA",
      Self::LoginRequired => "LOGIN_REQ",
      Self::InvalidUsername => "INVALID",
      Self::Skipped => "SKIPPED",
    }
  }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkRoute {
  #[default]
  Direct,
  Proxy,
  Tor,
}

#[derive(Clone, Debug, Serialize)]
pub struct RedirectSummary {
  pub status: u16,
  pub url: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProbeSummary {
  pub status: Option<u16>,
  pub final_url: Option<String>,
  pub elapsed_ms: u64,
  pub body_truncated: bool,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub redirects: Vec<RedirectSummary>,
  pub network_route: NetworkRoute,
}

impl ProbeSummary {
  #[must_use]
  pub const fn no_probe(network_route: NetworkRoute) -> Self {
    Self {
      status: None,
      final_url: None,
      elapsed_ms: 0,
      body_truncated: false,
      redirects: Vec::new(),
      network_route,
    }
  }
}

#[derive(Clone, Debug, Serialize)]
pub struct ControlSummary {
  pub status: Option<u16>,
  pub final_url: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub similarity: Option<f32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultErrorKind {
  Dns,
  Connect,
  Tls,
  Timeout,
  HttpProtocol,
  TooManyRedirects,
  BodyDecode,
  ResponseTooLarge,
  RateLimited,
  Blocked,
  Captcha,
  LoginRequired,
  Unsupported,
  InvalidUsernameForSite,
  DetectionRuleError,
  BlockedTarget,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResultErrorInfo {
  pub kind: ResultErrorKind,
  pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SiteResult {
  pub username: String,
  pub site_id: String,
  pub site_name: String,
  pub verdict: Verdict,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub profile_url: Option<String>,
  pub probe: ProbeSummary,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub control: Option<ControlSummary>,
  pub evidence: Vec<Evidence>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub error: Option<ResultErrorInfo>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ScanSummary {
  pub usernames: usize,
  pub sites_selected: usize,
  pub tasks_total: usize,
  pub found: usize,
  pub not_found: usize,
  pub uncertain: usize,
  pub blocked: usize,
  pub rate_limited: usize,
  pub captcha: usize,
  pub login_required: usize,
  pub invalid_username: usize,
  pub skipped: usize,
  pub errors: usize,
  pub elapsed_ms: u64,
  pub control_probes: usize,
  pub retries: usize,
  pub interrupted: bool,
}

impl ScanSummary {
  pub const fn record(&mut self, result: &SiteResult) {
    match result.verdict {
      Verdict::Found => self.found += 1,
      Verdict::NotFound => self.not_found += 1,
      Verdict::Uncertain => self.uncertain += 1,
      Verdict::Blocked => self.blocked += 1,
      Verdict::RateLimited => self.rate_limited += 1,
      Verdict::Captcha => self.captcha += 1,
      Verdict::LoginRequired => self.login_required += 1,
      Verdict::InvalidUsername => self.invalid_username += 1,
      Verdict::Skipped => self.skipped += 1,
    }
    if result.error.is_some() {
      self.errors += 1;
    }
  }
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanReport {
  pub schema_version: String,
  pub scan_id: ScanId,
  pub started_at: String,
  pub finished_at: String,
  pub summary: ScanSummary,
  pub results: Vec<SiteResult>,
}
