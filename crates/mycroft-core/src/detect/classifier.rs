use mycroft_manifest::schema::{BlockClass, BlockSignal, SignalKind};

use crate::detect::cache::DetectionCache;
use crate::detect::evidence::Evidence;
use crate::detect::signals::body_contains;
use crate::net::ProbeResponse;

#[must_use]
pub fn classify<'a, I>(
  response: &ProbeResponse,
  body_text: &str,
  cache: &DetectionCache,
  signals: I,
) -> Option<(BlockClass, Evidence)>
where
  I: IntoIterator<Item = &'a BlockSignal>,
{
  for signal in signals {
    if block_matches(signal, response, body_text, cache) {
      let evidence = Evidence::matched(
        signal.id.clone(),
        signal.classify_as.into(),
        1.0,
        format!("block signal '{}' matched", signal.id),
      );
      return Some((signal.classify_as, evidence));
    }
  }
  None
}

fn block_matches(
  signal: &BlockSignal,
  response: &ProbeResponse,
  body_text: &str,
  cache: &DetectionCache,
) -> bool {
  match signal.kind {
    SignalKind::Status => signal
      .match_spec
      .as_ref()
      .is_some_and(|m| m.matches(response.status)),
    SignalKind::BodySubstring => {
      signal.value.as_deref().is_some_and(|needle| {
        body_contains(
          body_text,
          needle,
          signal.case_insensitive.unwrap_or(false),
        )
      })
    }
    SignalKind::BodyRegex => signal
      .pattern
      .as_deref()
      .and_then(|pattern| cache.regex(pattern))
      .is_some_and(|re| re.is_match(body_text)),
    SignalKind::Header => signal
      .header
      .as_deref()
      .is_some_and(|h| response.header(h).is_some()),
    _ => false,
  }
}
