use std::borrow::Cow;
use std::time::Duration;

use async_trait::async_trait;

use mycroft_manifest::{HttpMethod, RedirectPolicy};

use crate::error::NetworkError;

pub mod fetch;
pub mod reqwest_executor;
pub mod ssrf_guard;

pub use fetch::{FetchSettings, fetch_bytes};
pub use reqwest_executor::ReqwestHttpExecutor;
pub use ssrf_guard::SsrfGuard;
pub use url::Url;

#[derive(Clone, Debug)]
pub struct PreparedRequest {
  pub method: HttpMethod,
  pub url: Url,
  pub headers: Vec<(String, String)>,
  pub body: Option<Vec<u8>>,
  pub redirect_policy: RedirectPolicy,
  pub timeout: Duration,
  pub max_body_bytes: usize,
  pub idempotent: bool,
}

#[derive(Clone, Debug)]
pub struct RedirectHop {
  pub status: u16,
  pub from: Url,
  pub to: Url,
}

#[derive(Clone, Debug)]
pub struct ProbeResponse {
  pub request_url: Url,
  pub final_url: Url,
  pub status: u16,
  pub headers: Vec<(String, String)>,
  pub redirect_chain: Vec<RedirectHop>,
  pub body: Vec<u8>,
  pub body_truncated: bool,
  pub elapsed: Duration,
}

impl ProbeResponse {
  #[must_use]
  pub fn header(&self, name: &str) -> Option<&str> {
    self
      .headers
      .iter()
      .find(|(k, _)| k.eq_ignore_ascii_case(name))
      .map(|(_, v)| v.as_str())
  }

  #[must_use]
  pub fn body_text(&self) -> Cow<'_, str> {
    String::from_utf8_lossy(&self.body)
  }
}

#[async_trait]
pub trait HttpExecutor: Send + Sync {
  async fn execute(
    &self,
    request: PreparedRequest,
  ) -> Result<ProbeResponse, NetworkError>;
}

#[must_use]
pub const fn is_redirect_status(status: u16) -> bool {
  matches!(status, 301 | 302 | 303 | 307 | 308)
}
