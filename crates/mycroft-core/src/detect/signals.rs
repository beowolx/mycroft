use scraper::{Html, Selector};
use serde_json::Value;

use mycroft_manifest::schema::{
  EchoLocation, MatchOp, SignalKind, SignalKindSpec, SignalSpec,
  SimilarityDirection,
};

use crate::detect::cache::DetectionCache;
use crate::detect::evidence::Evidence;
use crate::detect::fingerprint::{fingerprint, similarity};
use crate::net::ProbeResponse;

pub struct SignalContext<'a> {
  pub response: &'a ProbeResponse,
  pub body_text: &'a str,
  pub username_for_url: &'a str,
  pub username_raw: &'a str,
  pub profile_url: &'a str,
  pub control: Option<&'a ProbeResponse>,
  pub control_body: Option<&'a str>,
  pub cache: &'a DetectionCache,
}

#[must_use]
pub fn evaluate(
  ctx: &SignalContext<'_>,
  signal: &SignalSpec,
) -> Option<Evidence> {
  let matched = match &signal.kind {
    SignalKindSpec::Status { match_spec } => {
      match_spec.matches(ctx.response.status)
    }
    SignalKindSpec::Header {
      header,
      op,
      value,
      pattern,
    } => eval_header(ctx, header, *op, value.as_ref(), pattern.as_deref()),
    SignalKindSpec::Redirect { op, value, pattern } => {
      eval_redirect(ctx, *op, value.as_ref(), pattern.as_deref())
    }
    SignalKindSpec::BodySubstring {
      value,
      case_insensitive,
    } => body_contains(ctx.body_text, value, case_insensitive.unwrap_or(false)),
    SignalKindSpec::BodyRegex { pattern } => ctx
      .cache
      .regex(pattern)
      .is_some_and(|re| re.is_match(ctx.body_text)),
    SignalKindSpec::HtmlTitle { op, value, pattern } => {
      eval_html_title(ctx, *op, value.as_ref(), pattern.as_deref())
    }
    SignalKindSpec::CssSelector {
      selector,
      op,
      attr,
      value,
      pattern,
    } => eval_css(
      ctx,
      selector,
      *op,
      attr.as_deref(),
      value.as_ref(),
      pattern.as_deref(),
    ),
    SignalKindSpec::JsonPath {
      path,
      op,
      value,
      pattern,
    } => eval_json_path(ctx, path, *op, value.as_ref(), pattern.as_deref()),
    SignalKindSpec::CanonicalUrl { selector, pattern } => {
      eval_canonical(ctx, selector.as_deref(), pattern.as_deref())
    }
    SignalKindSpec::UsernameEcho { location } => {
      eval_username_echo(ctx, *location)
    }
    SignalKindSpec::BodySimilarity {
      similarity_threshold,
      direction,
    } => eval_body_similarity(ctx, *similarity_threshold, *direction),
    SignalKindSpec::BodySize { range } => {
      let len = ctx.body_text.len();
      len >= range[0] && len <= range[1]
    }
  };

  matched.then(|| {
    Evidence::matched(
      signal.id.clone(),
      signal.outcome.into(),
      signal.weight,
      describe(signal),
    )
  })
}

#[must_use]
pub const fn is_body_signal(kind: SignalKind) -> bool {
  matches!(
    kind,
    SignalKind::BodySubstring
      | SignalKind::BodyRegex
      | SignalKind::HtmlTitle
      | SignalKind::CssSelector
      | SignalKind::JsonPath
      | SignalKind::CanonicalUrl
      | SignalKind::BodySimilarity
      | SignalKind::BodySize
  )
}

pub fn body_contains(body: &str, needle: &str, case_insensitive: bool) -> bool {
  if case_insensitive {
    body.to_lowercase().contains(&needle.to_lowercase())
  } else {
    body.contains(needle)
  }
}

fn eval_header(
  ctx: &SignalContext<'_>,
  header: &str,
  op: MatchOp,
  value: Option<&Value>,
  pattern: Option<&str>,
) -> bool {
  let actual = ctx.response.header(header);
  match op {
    MatchOp::Exists => actual.is_some(),
    op => actual.is_some_and(|v| apply_str_op(op, v, value, pattern, ctx)),
  }
}

fn eval_redirect(
  ctx: &SignalContext<'_>,
  op: MatchOp,
  value: Option<&Value>,
  pattern: Option<&str>,
) -> bool {
  match op {
    MatchOp::Exists => !ctx.response.redirect_chain.is_empty(),
    op => {
      apply_str_op(op, ctx.response.final_url.as_str(), value, pattern, ctx)
    }
  }
}

fn eval_html_title(
  ctx: &SignalContext<'_>,
  op: MatchOp,
  value: Option<&Value>,
  pattern: Option<&str>,
) -> bool {
  let fp = fingerprint(ctx.body_text, ctx.cache);
  let Some(title) = fp.title else { return false };
  match op {
    MatchOp::Exists => true,
    op => apply_str_op(op, &title, value, pattern, ctx),
  }
}

fn eval_css(
  ctx: &SignalContext<'_>,
  selector: &str,
  op: MatchOp,
  attr: Option<&str>,
  value: Option<&Value>,
  pattern: Option<&str>,
) -> bool {
  let Ok(sel) = Selector::parse(selector) else {
    return false;
  };
  let doc = Html::parse_document(ctx.body_text);
  for element in doc.select(&sel) {
    let actual = attr.map_or_else(
      || element.text().collect::<String>(),
      |a| element.value().attr(a).unwrap_or("").to_string(),
    );
    let actual = actual.trim();
    let matched = match op {
      MatchOp::Exists => true,
      op => apply_str_op(op, actual, value, pattern, ctx),
    };
    if matched {
      return true;
    }
  }
  false
}

fn eval_json_path(
  ctx: &SignalContext<'_>,
  path: &str,
  op: MatchOp,
  value: Option<&Value>,
  pattern: Option<&str>,
) -> bool {
  let Ok(parsed) = serde_json::from_str::<Value>(ctx.body_text) else {
    return false;
  };
  let Ok(json_path) = serde_json_path::JsonPath::parse(path) else {
    return false;
  };
  let nodes = json_path.query(&parsed).all();
  if nodes.is_empty() {
    return false;
  }
  match op {
    MatchOp::Exists => true,
    MatchOp::EqualsUsername => nodes.iter().any(|n| {
      n.as_str()
        .is_some_and(|s| s == ctx.username_for_url || s == ctx.username_raw)
    }),
    MatchOp::Equals => value.is_some_and(|want| nodes.contains(&want)),
    op => nodes
      .iter()
      .filter_map(|n| n.as_str())
      .any(|s| apply_str_op(op, s, value, pattern, ctx)),
  }
}

fn eval_canonical(
  ctx: &SignalContext<'_>,
  selector: Option<&str>,
  pattern: Option<&str>,
) -> bool {
  if let Some(selector) = selector {
    if let Ok(sel) = Selector::parse(selector) {
      let doc = Html::parse_document(ctx.body_text);
      return doc.select(&sel).any(|e| {
        e.value()
          .attr("href")
          .is_some_and(|href| href.contains(ctx.username_for_url))
      });
    }
  }
  pattern
    .and_then(|pattern| ctx.cache.regex(pattern))
    .is_some_and(|re| re.is_match(ctx.body_text))
}

fn eval_username_echo(ctx: &SignalContext<'_>, location: EchoLocation) -> bool {
  let title;
  let haystack: &str = match location {
    EchoLocation::Body => ctx.body_text,
    EchoLocation::Title => {
      title = fingerprint(ctx.body_text, ctx.cache)
        .title
        .unwrap_or_default();
      &title
    }
    EchoLocation::FinalUrl => ctx.response.final_url.as_str(),
    EchoLocation::ProfileUrl => ctx.profile_url,
  };
  haystack.contains(ctx.username_for_url) || haystack.contains(ctx.username_raw)
}

fn eval_body_similarity(
  ctx: &SignalContext<'_>,
  threshold: f32,
  direction: SimilarityDirection,
) -> bool {
  let (Some(_), Some(control_body)) = (ctx.control, ctx.control_body) else {
    return false;
  };
  let sim = similarity(
    &fingerprint(ctx.body_text, ctx.cache),
    &fingerprint(control_body, ctx.cache),
  );
  match direction {
    SimilarityDirection::SimilarToControl => sim >= threshold,
    SimilarityDirection::DifferentFromControl => sim < threshold,
  }
}

fn apply_str_op(
  op: MatchOp,
  actual: &str,
  value: Option<&Value>,
  pattern: Option<&str>,
  ctx: &SignalContext<'_>,
) -> bool {
  match op {
    MatchOp::Exists => true,
    MatchOp::Equals => value.and_then(Value::as_str) == Some(actual),
    MatchOp::NotEquals => value.and_then(Value::as_str) != Some(actual),
    MatchOp::Contains => value
      .and_then(Value::as_str)
      .is_some_and(|v| actual.contains(v)),
    MatchOp::Regex => pattern
      .and_then(|pattern| ctx.cache.regex(pattern))
      .is_some_and(|re| re.is_match(actual)),
    MatchOp::EqualsUsername => {
      actual == ctx.username_for_url || actual == ctx.username_raw
    }
    MatchOp::ContainsUsername => {
      actual.contains(ctx.username_for_url) || actual.contains(ctx.username_raw)
    }
  }
}

fn describe(signal: &SignalSpec) -> String {
  format!("signal '{}' ({:?}) matched", signal.id, signal.kind.kind())
}
