use std::time::Duration;

use reqwest::header::LOCATION;
use url::Url;

use crate::error::NetworkError;
use crate::net::is_redirect_status;
use crate::net::ssrf_guard::{SsrfGuard, SsrfResolver};

const MAX_FETCH_BYTES: usize = 16 * 1024 * 1024;
const MAX_FETCH_HOPS: usize = 10;
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Default)]
pub struct FetchSettings {
  pub proxy: Option<String>,
  pub allow_private: bool,
}

/// Fetches a remote manifest body with redirects, timeout, and SSRF checks.
///
/// # Errors
///
/// Returns an error when the URL is invalid or blocked, redirects are invalid or
/// exceed the hop limit, the HTTP request fails, or the body exceeds the fetch
/// byte limit.
pub async fn fetch_bytes(
  url: &str,
  settings: &FetchSettings,
) -> Result<Vec<u8>, NetworkError> {
  let client = build_client(settings)?;
  let guard = SsrfGuard::new(settings.allow_private);
  let mut current =
    Url::parse(url).map_err(|e| NetworkError::InvalidUrl(e.to_string()))?;

  for _ in 0..=MAX_FETCH_HOPS {
    guard.check(&current)?;
    let response = client
      .get(current.clone())
      .send()
      .await
      .map_err(|e| NetworkError::Http(e.to_string()))?;
    let status = response.status().as_u16();
    if is_redirect_status(status) {
      let location = response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
          NetworkError::Http("redirect without Location header".to_string())
        })?;
      current = current
        .join(location)
        .map_err(|e| NetworkError::InvalidUrl(e.to_string()))?;
      continue;
    }
    return read_body(response).await;
  }
  Err(NetworkError::TooManyRedirects)
}

fn build_client(
  settings: &FetchSettings,
) -> Result<reqwest::Client, NetworkError> {
  let mut builder = reqwest::Client::builder()
    .timeout(FETCH_TIMEOUT)
    .redirect(reqwest::redirect::Policy::none())
    .dns_resolver(SsrfResolver::new(settings.allow_private))
    .gzip(true);
  if let Some(proxy) = &settings.proxy {
    let p = reqwest::Proxy::all(proxy)
      .map_err(|e| NetworkError::Http(format!("invalid proxy: {e}")))?;
    builder = builder.proxy(p);
  } else {
    builder = builder.no_proxy();
  }
  builder
    .build()
    .map_err(|e| NetworkError::Http(e.to_string()))
}

async fn read_body(
  mut response: reqwest::Response,
) -> Result<Vec<u8>, NetworkError> {
  let mut buffer = Vec::new();
  while let Some(chunk) = response
    .chunk()
    .await
    .map_err(|e| NetworkError::Body(e.to_string()))?
  {
    if buffer.len().saturating_add(chunk.len()) > MAX_FETCH_BYTES {
      return Err(NetworkError::ResponseTooLarge {
        limit: MAX_FETCH_BYTES,
      });
    }
    buffer.extend_from_slice(&chunk);
  }
  Ok(buffer)
}
