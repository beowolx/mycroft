use std::net::SocketAddr;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use url::Url;

use mycroft_manifest::addr::{host_literal_is_disallowed, ip_is_disallowed};

use crate::error::NetworkError;

#[derive(Clone, Copy, Debug)]
pub struct SsrfGuard {
  allow_private: bool,
}

impl SsrfGuard {
  #[must_use]
  pub const fn new(allow_private: bool) -> Self {
    Self { allow_private }
  }

  /// Checks whether a URL is allowed by the direct-connection SSRF policy.
  ///
  /// # Errors
  ///
  /// Returns an error when the URL has an unsupported scheme, no host, or a
  /// blocked literal host.
  pub fn check(&self, url: &Url) -> Result<(), NetworkError> {
    if url.scheme() != "http" && url.scheme() != "https" {
      return Err(NetworkError::BlockedTarget(format!(
        "unsupported scheme '{}'",
        url.scheme()
      )));
    }
    if self.allow_private {
      return Ok(());
    }

    let host = url
      .host_str()
      .ok_or_else(|| NetworkError::InvalidUrl("missing host".to_string()))?;

    if host_literal_is_disallowed(host) {
      return Err(NetworkError::BlockedTarget(host.to_string()));
    }

    Ok(())
  }
}

#[derive(Clone, Copy, Debug)]
pub struct SsrfResolver {
  allow_private: bool,
}

impl SsrfResolver {
  #[must_use]
  pub const fn new(allow_private: bool) -> Self {
    Self { allow_private }
  }
}

impl Resolve for SsrfResolver {
  fn resolve(&self, name: Name) -> Resolving {
    let allow_private = self.allow_private;
    Box::pin(async move {
      let host = name.as_str().to_owned();
      let addrs: Vec<SocketAddr> =
        tokio::net::lookup_host((host.as_str(), 0u16))
          .await?
          .collect();
      if !allow_private {
        if let Some(bad) = addrs.iter().find(|a| ip_is_disallowed(a.ip())) {
          return Err(
            format!("{host} resolves to disallowed address {}", bad.ip())
              .into(),
          );
        }
      }
      Ok(Box::new(addrs.into_iter()) as Addrs)
    })
  }
}

#[cfg(test)]
mod tests {
  use url::Url;

  use reqwest::dns::{Name, Resolve};

  use crate::net::ssrf_guard::{SsrfGuard, SsrfResolver};

  fn check(
    guard: SsrfGuard,
    url: &str,
  ) -> Result<(), crate::error::NetworkError> {
    let url = Url::parse(url).expect("valid url");
    guard.check(&url)
  }

  #[test]
  fn non_http_scheme_is_blocked() {
    let guard = SsrfGuard::new(false);
    assert!(check(guard, "ftp://example.com/").is_err());
  }

  #[test]
  fn literal_metadata_and_loopback_blocked() {
    let guard = SsrfGuard::new(false);
    assert!(check(guard, "http://169.254.169.254/latest/meta-data").is_err());
    assert!(check(guard, "http://127.0.0.1/").is_err());
    assert!(check(guard, "http://localhost/").is_err());
  }

  #[test]
  fn hostname_passes_preflight_and_is_validated_at_resolution() {
    let guard = SsrfGuard::new(false);
    assert!(check(guard, "https://example.com/manifest.json").is_ok());
  }

  #[test]
  fn allow_private_bypasses_everything() {
    let guard = SsrfGuard::new(true);
    assert!(check(guard, "http://127.0.0.1/").is_ok());
  }

  #[tokio::test]
  async fn resolver_rejects_name_resolving_to_loopback() {
    let resolver = SsrfResolver::new(false);
    let name: Name = "localhost".parse().expect("valid name");
    assert!(resolver.resolve(name).await.is_err());
  }

  #[tokio::test]
  async fn resolver_allows_loopback_when_private_allowed() {
    let resolver = SsrfResolver::new(true);
    let name: Name = "localhost".parse().expect("valid name");
    assert!(resolver.resolve(name).await.is_ok());
  }
}
