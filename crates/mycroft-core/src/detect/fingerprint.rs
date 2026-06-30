use scraper::Html;

use crate::detect::cache::DetectionCache;

#[derive(Clone, Debug)]
pub struct ResponseFingerprint {
  pub title: Option<String>,
  pub simhash: u64,
}

#[must_use]
pub fn fingerprint(
  body_text: &str,
  cache: &DetectionCache,
) -> ResponseFingerprint {
  ResponseFingerprint {
    title: extract_title(body_text, cache),
    simhash: simhash(body_text),
  }
}

#[must_use]
pub fn similarity(a: &ResponseFingerprint, b: &ResponseFingerprint) -> f32 {
  let hamming =
    u8::try_from((a.simhash ^ b.simhash).count_ones()).map_or(64.0, f32::from);
  let body_sim = 1.0 - (hamming / 64.0);
  let title_sim = if a.title == b.title { 1.0 } else { 0.0 };
  0.8f32.mul_add(body_sim, 0.2 * title_sim)
}

fn extract_title(body: &str, cache: &DetectionCache) -> Option<String> {
  let selector = cache.title_selector()?;
  let document = Html::parse_document(body);
  let title = document.select(selector).next()?;
  let mut normalized = String::new();
  for chunk in title.text() {
    for word in chunk.split_whitespace() {
      if !normalized.is_empty() {
        normalized.push(' ');
      }
      normalized.push_str(word);
    }
  }
  (!normalized.is_empty()).then_some(normalized)
}

fn fnv1a(token: &str) -> u64 {
  let mut hash = 0xcbf2_9ce4_8422_2325u64;
  for byte in token.bytes() {
    hash ^= u64::from(byte);
    hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
  }
  hash
}

#[must_use]
pub fn simhash(text: &str) -> u64 {
  let mut counters = [0i32; 64];
  let mut seen = false;
  for token in text.split_whitespace() {
    seen = true;
    let hash = fnv1a(token);
    for (i, counter) in counters.iter_mut().enumerate() {
      if (hash >> i) & 1 == 1 {
        *counter += 1;
      } else {
        *counter -= 1;
      }
    }
  }
  if !seen {
    return 0;
  }
  let mut out = 0u64;
  for (i, counter) in counters.iter().enumerate() {
    if *counter > 0 {
      out |= 1 << i;
    }
  }
  out
}
