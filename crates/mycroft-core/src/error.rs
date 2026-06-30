use crate::result::ResultErrorKind;

#[derive(Debug, thiserror::Error)]
pub enum NetworkConfigError {
  #[error("invalid proxy URL '{0}'")]
  InvalidProxy(String),
  #[error("failed to build HTTP client: {0}")]
  ClientBuild(String),
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
  #[error("DNS resolution failed for '{host}'")]
  Dns { host: String },
  #[error("connection failed: {0}")]
  Connect(String),
  #[error("TLS error: {0}")]
  Tls(String),
  #[error("request timed out")]
  Timeout,
  #[error("too many redirects")]
  TooManyRedirects,
  #[error("target '{0}' is blocked by the SSRF guard")]
  BlockedTarget(String),
  #[error("invalid URL: {0}")]
  InvalidUrl(String),
  #[error("response body error: {0}")]
  Body(String),
  #[error("response body exceeded {limit} bytes")]
  ResponseTooLarge { limit: usize },
  #[error("HTTP protocol error: {0}")]
  Http(String),
}

impl NetworkError {
  #[must_use]
  pub const fn kind(&self) -> ResultErrorKind {
    match self {
      Self::Dns { .. } => ResultErrorKind::Dns,
      Self::Connect(_) => ResultErrorKind::Connect,
      Self::Tls(_) => ResultErrorKind::Tls,
      Self::Timeout => ResultErrorKind::Timeout,
      Self::TooManyRedirects => ResultErrorKind::TooManyRedirects,
      Self::BlockedTarget(_) => ResultErrorKind::BlockedTarget,
      Self::InvalidUrl(_) | Self::Http(_) => ResultErrorKind::HttpProtocol,
      Self::Body(_) => ResultErrorKind::BodyDecode,
      Self::ResponseTooLarge { .. } => ResultErrorKind::ResponseTooLarge,
    }
  }

  #[must_use]
  pub const fn is_retryable(&self) -> bool {
    matches!(self, Self::Connect(_) | Self::Dns { .. })
  }
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
  #[error("no usernames provided")]
  NoUsernames,
  #[error("no sites selected for scanning")]
  NoSites,
  #[error("network configuration error: {0}")]
  NetworkConfig(#[from] NetworkConfigError),
  #[error("scan interrupted")]
  Interrupted,
  #[error("internal error: {0}")]
  Internal(String),
}
