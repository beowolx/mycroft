use fancy_regex::Regex;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::Serialize;

use mycroft_manifest::schema::UsernameCase;
use mycroft_manifest::{UsernameEncoding, UsernameRules};

const PATH_SEGMENT: &AsciiSet = &CONTROLS
  .add(b' ')
  .add(b'"')
  .add(b'#')
  .add(b'%')
  .add(b'/')
  .add(b'<')
  .add(b'>')
  .add(b'?')
  .add(b'`')
  .add(b'{')
  .add(b'}');

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
pub struct Username(String);

#[derive(Debug, thiserror::Error)]
pub enum UsernameError {
  #[error("username must not be empty")]
  Empty,
  #[error("username contains control characters")]
  ControlCharacters,
}

impl Username {
  /// Parses and validates a username.
  ///
  /// # Errors
  ///
  /// Returns an error when the username is empty or contains control characters.
  pub fn parse(raw: &str) -> Result<Self, UsernameError> {
    if raw.is_empty() {
      return Err(UsernameError::Empty);
    }
    if raw.chars().any(char::is_control) {
      return Err(UsernameError::ControlCharacters);
    }
    Ok(Self(raw.to_string()))
  }

  #[must_use]
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

impl std::fmt::Display for Username {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.0)
  }
}

/// Expands optional username separator placeholders.
///
/// # Errors
///
/// Returns an error when any expanded username is invalid.
pub fn expand_variants(
  raw: &str,
  enabled: bool,
) -> Result<Vec<Username>, UsernameError> {
  if enabled && raw.contains("{?}") {
    let mut out = Vec::new();
    for sep in ["", "_", ".", "-"] {
      out.push(Username::parse(&raw.replace("{?}", sep))?);
    }
    return Ok(out);
  }
  Ok(vec![Username::parse(raw)?])
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedUsername {
  pub for_url: String,
  pub for_body: String,
}

#[derive(Debug, thiserror::Error)]
pub enum UsernameRuleError {
  #[error("username does not satisfy the site regex")]
  RegexMismatch,
  #[error("site regex is invalid: {0}")]
  InvalidRegex(String),
}

/// Applies a site's username validation and encoding rules.
///
/// # Errors
///
/// Returns an error when the site regex is invalid or the username does not
/// satisfy it.
pub fn apply_site_rules(
  username: &Username,
  rules: &UsernameRules,
) -> Result<EncodedUsername, UsernameRuleError> {
  if let Some(pattern) = &rules.regex {
    let re = Regex::new(pattern)
      .map_err(|e| UsernameRuleError::InvalidRegex(e.to_string()))?;
    let matched = re
      .is_match(username.as_str())
      .map_err(|e| UsernameRuleError::InvalidRegex(e.to_string()))?;
    if !matched {
      return Err(UsernameRuleError::RegexMismatch);
    }
  }

  let cased = apply_case(username.as_str(), rules.case);
  let for_url = encode(&cased, rules.encode);
  Ok(EncodedUsername {
    for_url,
    for_body: cased,
  })
}

fn apply_case(value: &str, case: UsernameCase) -> String {
  match case {
    UsernameCase::Preserve => value.to_string(),
    UsernameCase::Lower => value.to_lowercase(),
    UsernameCase::Upper => value.to_uppercase(),
  }
}

fn encode(value: &str, encoding: UsernameEncoding) -> String {
  match encoding {
    UsernameEncoding::SpaceOnly => value.replace(' ', "%20"),
    UsernameEncoding::PercentPath => {
      utf8_percent_encode(value, PATH_SEGMENT).to_string()
    }
    UsernameEncoding::None => value.to_string(),
  }
}

pub fn generate_absent_username<R: rand::Rng + ?Sized>(
  rules: &UsernameRules,
  target: &str,
  rng: &mut R,
) -> Option<Username> {
  let re = rules.regex.as_deref().and_then(|p| Regex::new(p).ok());
  let matches = |candidate: &str| {
    re.as_ref()
      .is_none_or(|r| r.is_match(candidate).unwrap_or(false))
  };

  if let Some(tmpl) = &rules.absent_template {
    let token = random_base32(rng, 10);
    let candidate =
      tmpl.replace("{random_base32_12}", &token[..12.min(token.len())]);
    if matches(&candidate) {
      return Some(Username(candidate));
    }
  }

  for _ in 0..4 {
    let candidate = structural_mimic(target, rng);
    if !candidate.is_empty() && candidate != target && matches(&candidate) {
      return Some(Username(candidate));
    }
  }

  let prefixed =
    format!("mycroftabsent{}", random_alnum_starting_with_letter(rng, 6));
  if matches(&prefixed) {
    return Some(Username(prefixed));
  }

  for len in [12usize, 10, 8, 6, 15, 5, 20] {
    let candidate = random_alnum_starting_with_letter(rng, len);
    if matches(&candidate) {
      return Some(Username(candidate));
    }
  }
  None
}

fn structural_mimic<R: rand::Rng + ?Sized>(
  target: &str,
  rng: &mut R,
) -> String {
  const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
  const DIGITS: &[u8] = b"0123456789";
  let mut out = String::with_capacity(target.len());
  for ch in target.chars() {
    if ch.is_ascii_digit() {
      out.push(char::from(DIGITS[pick(rng, DIGITS.len())]));
    } else if ch.is_ascii_alphabetic() {
      let letter = LETTERS[pick(rng, LETTERS.len())];
      out.push(char::from(if ch.is_ascii_uppercase() {
        letter.to_ascii_uppercase()
      } else {
        letter
      }));
    } else {
      out.push(ch);
    }
  }
  out
}

fn pick<R: rand::Rng + ?Sized>(rng: &mut R, n: usize) -> usize {
  let mut byte = [0u8; 1];
  rng.fill_bytes(&mut byte);
  usize::from(byte[0]) % n.max(1)
}

pub(crate) fn random_alnum_starting_with_letter<R: rand::Rng + ?Sized>(
  rng: &mut R,
  len: usize,
) -> String {
  const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
  const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
  let mut bytes = vec![0u8; len.max(1)];
  rng.fill_bytes(&mut bytes);
  let mut out = String::with_capacity(len.max(1));
  for (i, b) in bytes.iter().enumerate() {
    let set = if i == 0 { LETTERS } else { ALNUM };
    out.push(char::from(set[usize::from(*b) % set.len()]));
  }
  out
}

fn random_base32<R: rand::Rng + ?Sized>(rng: &mut R, bytes: usize) -> String {
  let mut buf = vec![0u8; bytes];
  rng.fill_bytes(&mut buf);
  base32_lower_no_padding(&buf)
}

fn base32_lower_no_padding(bytes: &[u8]) -> String {
  const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
  let mut out = String::new();
  let mut buffer = 0u32;
  let mut bits = 0u32;
  for &byte in bytes {
    buffer = (buffer << 8) | u32::from(byte);
    bits += 8;
    while bits >= 5 {
      bits -= 5;
      let idx = usize::try_from((buffer >> bits) & 0x1f).unwrap_or(0);
      out.push(char::from(ALPHABET[idx]));
    }
  }
  if bits > 0 {
    let idx = usize::try_from((buffer << (5 - bits)) & 0x1f).unwrap_or(0);
    out.push(char::from(ALPHABET[idx]));
  }
  out
}

#[cfg(test)]
mod tests {
  use mycroft_manifest::{UsernameEncoding, UsernameRules};

  use crate::username::{
    Username, UsernameError, UsernameRuleError, apply_site_rules,
  };

  #[test]
  fn parse_rejects_empty() {
    assert!(matches!(Username::parse(""), Err(UsernameError::Empty)));
  }

  #[test]
  fn space_only_encoding_only_encodes_spaces() {
    let rules = UsernameRules {
      encode: UsernameEncoding::SpaceOnly,
      ..UsernameRules::default()
    };
    let u = Username::parse("a b").unwrap();
    assert_eq!(apply_site_rules(&u, &rules).unwrap().for_url, "a%20b");
  }

  #[test]
  fn regex_mismatch_is_rejected() {
    let rules = UsernameRules {
      regex: Some("^[0-9]+$".to_string()),
      ..UsernameRules::default()
    };
    let u = Username::parse("abc").unwrap();
    assert!(matches!(
      apply_site_rules(&u, &rules),
      Err(UsernameRuleError::RegexMismatch)
    ));
  }
}
