use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue, LOCATION};
use url::Url;

use mycroft_manifest::HttpMethod;
use mycroft_manifest::schema::RedirectMode;

use crate::config::RuntimeConfig;
use crate::error::{NetworkConfigError, NetworkError};
use crate::net::ssrf_guard::{SsrfGuard, SsrfResolver};
use crate::net::{
  HttpExecutor, PreparedRequest, ProbeResponse, RedirectHop, is_redirect_status,
};

pub struct ReqwestHttpExecutor {
  client: reqwest::Client,
  guard: SsrfGuard,
}

impl ReqwestHttpExecutor {
  /// Builds the default reqwest-backed HTTP executor.
  ///
  /// # Errors
  ///
  /// Returns an error when proxy configuration is invalid or the HTTP client
  /// cannot be built.
  pub fn new(cfg: &RuntimeConfig) -> Result<Self, NetworkConfigError> {
    let mut default_headers = HeaderMap::new();
    default_headers.insert(ACCEPT, HeaderValue::from_static("*/*"));

    let mut builder = reqwest::Client::builder()
      .connect_timeout(cfg.timeouts.connect_timeout)
      .redirect(reqwest::redirect::Policy::none())
      .pool_idle_timeout(Duration::from_secs(30))
      .pool_max_idle_per_host(2)
      .user_agent(cfg.user_agent.clone())
      .default_headers(default_headers)
      .gzip(true)
      .brotli(true)
      .deflate(true)
      .dns_resolver(SsrfResolver::new(cfg.allow_private_targets));

    if let Some(proxy) = &cfg.proxy {
      let p = reqwest::Proxy::all(&proxy.url)
        .map_err(|e| NetworkConfigError::InvalidProxy(e.to_string()))?;
      builder = builder.proxy(p);
    } else {
      builder = builder.no_proxy();
    }

    let client = builder
      .build()
      .map_err(|e| NetworkConfigError::ClientBuild(e.to_string()))?;
    Ok(Self {
      client,
      guard: SsrfGuard::new(cfg.allow_private_targets),
    })
  }

  async fn run(
    &self,
    request: PreparedRequest,
  ) -> Result<ProbeResponse, NetworkError> {
    let started = Instant::now();
    let request_url = request.url.clone();
    let follow = request.redirect_policy.mode == RedirectMode::Follow;
    let max_hops =
      usize::try_from(request.redirect_policy.max_hops).unwrap_or(usize::MAX);

    let mut url = request.url;
    let mut method = request.method;
    let mut body = request.body;
    let mut redirect_chain: Vec<RedirectHop> = Vec::new();

    loop {
      self.guard.check(&url)?;
      let response = self
        .send_once(method, &url, &request.headers, body.as_deref())
        .await?;
      let status = response.status().as_u16();

      if follow && is_redirect_status(status) && redirect_chain.len() < max_hops
      {
        if let Some(location) = response
          .headers()
          .get(LOCATION)
          .and_then(|v| v.to_str().ok())
        {
          let next = url.join(location).map_err(|e| {
            NetworkError::InvalidUrl(format!("bad redirect target: {e}"))
          })?;
          redirect_chain.push(RedirectHop {
            status,
            from: url.clone(),
            to: next.clone(),
          });
          let rebuilt = rebuild_for_redirect(method, body, status);
          method = rebuilt.0;
          body = rebuilt.1;
          url = next;
          continue;
        }
      }

      let headers = collect_headers(&response);
      let (bytes, truncated) =
        read_body_budget(response, request.max_body_bytes).await?;
      return Ok(ProbeResponse {
        request_url,
        final_url: url,
        status,
        headers,
        redirect_chain,
        body: bytes,
        body_truncated: truncated,
        elapsed: started.elapsed(),
      });
    }
  }

  async fn send_once(
    &self,
    method: HttpMethod,
    url: &Url,
    headers: &[(String, String)],
    body: Option<&[u8]>,
  ) -> Result<reqwest::Response, NetworkError> {
    let mut builder =
      self.client.request(to_reqwest_method(method), url.clone());
    for (name, value) in headers {
      builder = builder.header(name, value);
    }
    if let Some(bytes) = body {
      builder = builder.body(bytes.to_vec());
    }
    builder.send().await.map_err(|e| classify_reqwest_error(&e))
  }
}

#[async_trait]
impl HttpExecutor for ReqwestHttpExecutor {
  async fn execute(
    &self,
    request: PreparedRequest,
  ) -> Result<ProbeResponse, NetworkError> {
    let timeout = request.timeout;
    match tokio::time::timeout(timeout, self.run(request)).await {
      Ok(result) => result,
      Err(_elapsed) => Err(NetworkError::Timeout),
    }
  }
}

const fn to_reqwest_method(method: HttpMethod) -> reqwest::Method {
  match method {
    HttpMethod::Get => reqwest::Method::GET,
    HttpMethod::Head => reqwest::Method::HEAD,
    HttpMethod::Post => reqwest::Method::POST,
    HttpMethod::Put => reqwest::Method::PUT,
  }
}

fn rebuild_for_redirect(
  method: HttpMethod,
  body: Option<Vec<u8>>,
  status: u16,
) -> (HttpMethod, Option<Vec<u8>>) {
  match status {
    307 | 308 => (method, body),
    303 => (HttpMethod::Get, None),
    301 | 302 => match method {
      HttpMethod::Post => (HttpMethod::Get, None),
      other => (other, None),
    },
    _ => (method, None),
  }
}

fn collect_headers(response: &reqwest::Response) -> Vec<(String, String)> {
  response
    .headers()
    .iter()
    .map(|(name, value)| {
      (
        name.as_str().to_string(),
        String::from_utf8_lossy(value.as_bytes()).into_owned(),
      )
    })
    .collect()
}

async fn read_body_budget(
  mut response: reqwest::Response,
  max_body_bytes: usize,
) -> Result<(Vec<u8>, bool), NetworkError> {
  let mut buffer = Vec::new();
  let mut truncated = false;
  while let Some(chunk) = response
    .chunk()
    .await
    .map_err(|e| NetworkError::Body(e.to_string()))?
  {
    if buffer.len().saturating_add(chunk.len()) > max_body_bytes {
      let remaining = max_body_bytes.saturating_sub(buffer.len());
      buffer.extend_from_slice(&chunk[..remaining]);
      truncated = true;
      break;
    }
    buffer.extend_from_slice(&chunk);
  }
  Ok((buffer, truncated))
}

fn classify_reqwest_error(error: &reqwest::Error) -> NetworkError {
  if error.is_timeout() {
    NetworkError::Timeout
  } else if error.is_connect() {
    NetworkError::Connect(error.to_string())
  } else if error.is_redirect() {
    NetworkError::TooManyRedirects
  } else if error.is_body() || error.is_decode() {
    NetworkError::Body(error.to_string())
  } else {
    NetworkError::Http(error.to_string())
  }
}
