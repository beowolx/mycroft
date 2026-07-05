use std::time::Duration;

use serde_json::Value;
use url::Url;

use mycroft_manifest::schema::ExtractSource;
use mycroft_manifest::template;
use mycroft_manifest::{Extraction, HttpMethod, RedirectPolicy};

use crate::net::{PreparedRequest, ProbeResponse};

#[derive(Clone, Debug)]
pub struct MainTemplate {
  pub method: HttpMethod,
  pub url: String,
  pub headers: Vec<(String, String)>,
  pub body: Option<Vec<u8>>,
  pub redirect_policy: RedirectPolicy,
  pub timeout: Duration,
  pub max_body_bytes: usize,
  pub idempotent: bool,
}

#[derive(Clone, Debug)]
pub struct TwoStep {
  pub extractions: Vec<Extraction>,
  pub forward_cookies: bool,
  pub main: MainTemplate,
}

/// Extracts prerequest variables from the response according to the manifest.
///
/// # Errors
///
/// Returns an error when any declared extraction cannot be resolved from the
/// response headers, cookies, JSON body, or regex capture.
pub fn extract_vars(
  response: &ProbeResponse,
  extractions: &[Extraction],
) -> Result<Vec<(String, String)>, String> {
  let body = response.body_text();
  let mut vars = Vec::with_capacity(extractions.len());
  for extraction in extractions {
    let value = match &extraction.from {
      ExtractSource::Header { header } => {
        response.header(header).map(str::to_string)
      }
      ExtractSource::Cookie { cookie } => cookie_value(response, cookie),
      ExtractSource::JsonPath { path } => json_value(&body, path),
      ExtractSource::Regex { pattern } => regex_value(&body, pattern),
    };
    match value {
      Some(value) => {
        vars.push((format!("{{var:{}}}", extraction.name), value));
      }
      None => {
        return Err(format!(
          "prerequest did not yield value for '{}'",
          extraction.name
        ));
      }
    }
  }
  Ok(vars)
}

#[must_use]
pub fn collect_cookies(response: &ProbeResponse) -> Option<String> {
  let pairs: Vec<String> = response
    .headers
    .iter()
    .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
    .filter_map(|(_, v)| first_cookie_pair(v))
    .collect();
  if pairs.is_empty() {
    None
  } else {
    Some(pairs.join("; "))
  }
}

/// Applies prerequest variables and cookies to the main request template.
///
/// # Errors
///
/// Returns an error when the rendered main request URL is invalid.
pub fn finalize_main(
  main: &MainTemplate,
  vars: &[(String, String)],
  cookie_header: Option<&str>,
) -> Result<PreparedRequest, String> {
  let url_str = template::interpolate_vars(&main.url, vars);
  let url = Url::parse(&url_str).map_err(|e| format!("invalid URL: {e}"))?;

  let mut headers: Vec<(String, String)> = main
    .headers
    .iter()
    .map(|(k, v)| (k.clone(), template::interpolate_vars(v, vars)))
    .collect();
  if let Some(cookie) = cookie_header {
    if !headers
      .iter()
      .any(|(k, _)| k.eq_ignore_ascii_case("cookie"))
    {
      headers.push(("Cookie".to_string(), cookie.to_string()));
    }
  }

  let body = main.body.as_ref().map(|bytes| {
    template::interpolate_vars(&String::from_utf8_lossy(bytes), vars)
      .into_bytes()
  });

  Ok(PreparedRequest {
    method: main.method,
    url,
    headers,
    body,
    redirect_policy: main.redirect_policy,
    timeout: main.timeout,
    max_body_bytes: main.max_body_bytes,
    idempotent: main.idempotent,
  })
}

fn cookie_value(response: &ProbeResponse, name: &str) -> Option<String> {
  response
    .headers
    .iter()
    .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
    .find_map(|(_, v)| named_cookie(v, name))
}

fn first_cookie_pair(set_cookie: &str) -> Option<String> {
  let pair = set_cookie.split(';').next()?.trim();
  pair.contains('=').then(|| pair.to_string())
}

fn named_cookie(set_cookie: &str, name: &str) -> Option<String> {
  let pair = set_cookie.split(';').next()?.trim();
  let (key, value) = pair.split_once('=')?;
  if key.trim() == name {
    Some(value.trim().to_string())
  } else {
    None
  }
}

fn json_value(body: &str, path: &str) -> Option<String> {
  let parsed: Value = serde_json::from_str(body).ok()?;
  let json_path = serde_json_path::JsonPath::parse(path).ok()?;
  let node = json_path.query(&parsed).all().into_iter().next()?;
  match node {
    Value::String(s) => Some(s.clone()),
    Value::Null => None,
    other => Some(other.to_string()),
  }
}

fn regex_value(body: &str, pattern: &str) -> Option<String> {
  let re = regex::Regex::new(pattern).ok()?;
  let caps = re.captures(body)?;
  caps
    .get(1)
    .or_else(|| caps.get(0))
    .map(|m| m.as_str().to_string())
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use mycroft_manifest::Extraction;
  use mycroft_manifest::schema::ExtractSource;
  use url::Url;

  use crate::net::ProbeResponse;
  use crate::twostep::{collect_cookies, extract_vars};

  fn response(headers: Vec<(String, String)>, body: &str) -> ProbeResponse {
    let url = Url::parse("https://x.test/").unwrap();
    ProbeResponse {
      request_url: url.clone(),
      final_url: url,
      status: 200,
      headers,
      redirect_chain: Vec::new(),
      body: body.as_bytes().to_vec(),
      body_truncated: false,
      elapsed: Duration::ZERO,
    }
  }

  #[test]
  fn extracts_cookie_header_and_html_regex() {
    let resp = response(
      vec![
        (
          "set-cookie".to_string(),
          "csrftoken=abc123; Path=/; Secure".to_string(),
        ),
        ("x-token".to_string(), "hdr-tok".to_string()),
      ],
      r#"<input name="authenticity_token" value="html-tok">"#,
    );
    let extractions = vec![
      Extraction {
        name: "csrf".to_string(),
        from: ExtractSource::Cookie {
          cookie: "csrftoken".to_string(),
        },
      },
      Extraction {
        name: "hdr".to_string(),
        from: ExtractSource::Header {
          header: "x-token".to_string(),
        },
      },
      Extraction {
        name: "html".to_string(),
        from: ExtractSource::Regex {
          pattern: r#"authenticity_token" value="([^"]+)"#.to_string(),
        },
      },
    ];
    let vars = extract_vars(&resp, &extractions).expect("extracts");
    assert_eq!(vars[0], ("{var:csrf}".to_string(), "abc123".to_string()));
    assert_eq!(vars[1], ("{var:hdr}".to_string(), "hdr-tok".to_string()));
    assert_eq!(vars[2], ("{var:html}".to_string(), "html-tok".to_string()));
  }

  #[test]
  fn extracts_json_token() {
    let resp = response(Vec::new(), r#"{"API_TOKEN":"jtok","x":1}"#);
    let extractions = vec![Extraction {
      name: "jt".to_string(),
      from: ExtractSource::JsonPath {
        path: "$.API_TOKEN".to_string(),
      },
    }];
    let vars = extract_vars(&resp, &extractions).expect("extracts");
    assert_eq!(vars[0], ("{var:jt}".to_string(), "jtok".to_string()));
  }

  #[test]
  fn missing_extraction_is_an_error() {
    let resp = response(Vec::new(), "{}");
    let extractions = vec![Extraction {
      name: "csrf".to_string(),
      from: ExtractSource::Cookie {
        cookie: "csrftoken".to_string(),
      },
    }];
    assert!(extract_vars(&resp, &extractions).is_err());
  }

  #[test]
  fn collects_cookie_pairs_for_forwarding() {
    let resp = response(
      vec![
        ("set-cookie".to_string(), "a=1; Path=/".to_string()),
        ("set-cookie".to_string(), "b=2; Secure".to_string()),
      ],
      "",
    );
    assert_eq!(collect_cookies(&resp).as_deref(), Some("a=1; b=2"));
  }
}
