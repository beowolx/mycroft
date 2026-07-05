use md5::Md5;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use sha2::{Digest, Sha256};

use mycroft_manifest::template;

pub use mycroft_manifest::SubjectKind;

use crate::username::EncodedUsername;

const EMAIL_QUERY: &AsciiSet = &CONTROLS
  .add(b' ')
  .add(b'"')
  .add(b'#')
  .add(b'%')
  .add(b'&')
  .add(b'+')
  .add(b'/')
  .add(b'<')
  .add(b'=')
  .add(b'>')
  .add(b'?')
  .add(b'@')
  .add(b'`')
  .add(b'{')
  .add(b'}');

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedSubject {
  pub for_url: Vec<(&'static str, String)>,
  pub for_body: Vec<(&'static str, String)>,
  pub primary_for_url: String,
  pub primary_raw: String,
}

impl EncodedSubject {
  #[must_use]
  pub fn from_username(encoded: EncodedUsername) -> Self {
    use mycroft_manifest::template::USERNAME_PLACEHOLDER;
    Self {
      for_url: vec![(USERNAME_PLACEHOLDER, encoded.for_url.clone())],
      for_body: vec![(USERNAME_PLACEHOLDER, encoded.for_body.clone())],
      primary_for_url: encoded.for_url,
      primary_raw: encoded.for_body,
    }
  }
}

#[derive(Debug, thiserror::Error)]
pub enum EmailError {
  #[error("email must not be empty")]
  Empty,
  #[error("email must contain exactly one '@'")]
  MissingAt,
  #[error("email local part must not be empty")]
  EmptyLocal,
  #[error("email domain must be a valid host with a dot")]
  InvalidDomain,
  #[error("email contains whitespace or control characters")]
  IllegalCharacters,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Email {
  normalized: String,
  local: String,
  domain: String,
}

impl Email {
  /// Parses and normalizes an email subject.
  ///
  /// # Errors
  ///
  /// Returns an error when the input is empty, contains whitespace or control
  /// characters, does not contain exactly one `@`, has an empty local part, or
  /// has a domain that is not usable as a host.
  pub fn parse(raw: &str) -> Result<Self, EmailError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
      return Err(EmailError::Empty);
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
      return Err(EmailError::IllegalCharacters);
    }
    let normalized = trimmed.to_lowercase();
    let mut parts = normalized.split('@');
    let local = parts.next().unwrap_or_default();
    let (Some(domain), None) = (parts.next(), parts.next()) else {
      return Err(EmailError::MissingAt);
    };
    if local.is_empty() {
      return Err(EmailError::EmptyLocal);
    }
    if domain.len() < 3
      || !domain.contains('.')
      || domain.starts_with('.')
      || domain.ends_with('.')
    {
      return Err(EmailError::InvalidDomain);
    }
    Ok(Self {
      local: local.to_string(),
      domain: domain.to_string(),
      normalized,
    })
  }

  #[must_use]
  pub fn as_str(&self) -> &str {
    &self.normalized
  }

  #[must_use]
  pub fn local(&self) -> &str {
    &self.local
  }

  #[must_use]
  pub fn domain(&self) -> &str {
    &self.domain
  }

  #[must_use]
  pub fn md5_hex(&self) -> String {
    crate::util::hex(&Md5::digest(self.normalized.as_bytes()))
  }

  #[must_use]
  pub fn sha256_hex(&self) -> String {
    crate::util::hex(&Sha256::digest(self.normalized.as_bytes()))
  }

  #[must_use]
  pub fn encoded_subject(&self) -> EncodedSubject {
    let email_url = encode(&self.normalized);
    let local_url = encode(&self.local);
    let domain_url = encode(&self.domain);
    let md5 = self.md5_hex();
    let sha256 = self.sha256_hex();

    let for_url = vec![
      (template::EMAIL_PLACEHOLDER, email_url.clone()),
      (template::EMAIL_LOCAL_PLACEHOLDER, local_url),
      (template::EMAIL_DOMAIN_PLACEHOLDER, domain_url),
      (template::EMAIL_MD5_PLACEHOLDER, md5.clone()),
      (template::EMAIL_SHA256_PLACEHOLDER, sha256.clone()),
    ];
    let for_body = vec![
      (template::EMAIL_PLACEHOLDER, self.normalized.clone()),
      (template::EMAIL_LOCAL_PLACEHOLDER, self.local.clone()),
      (template::EMAIL_DOMAIN_PLACEHOLDER, self.domain.clone()),
      (template::EMAIL_MD5_PLACEHOLDER, md5),
      (template::EMAIL_SHA256_PLACEHOLDER, sha256),
    ];
    EncodedSubject {
      for_url,
      for_body,
      primary_for_url: email_url,
      primary_raw: self.normalized.clone(),
    }
  }
}

#[must_use]
pub fn generate_absent_email<R: rand::Rng + ?Sized>(rng: &mut R) -> Email {
  let token = crate::username::random_alnum_starting_with_letter(rng, 16);
  Email {
    local: format!("mycroftabsent{token}"),
    domain: "gmail.com".to_string(),
    normalized: format!("mycroftabsent{token}@gmail.com"),
  }
}

fn encode(value: &str) -> String {
  utf8_percent_encode(value, EMAIL_QUERY).to_string()
}

#[cfg(test)]
mod tests {
  use crate::subject::{Email, EmailError};

  #[test]
  fn parse_normalizes_case_and_trims() {
    let email = Email::parse("  Perneldoreen@Gmail.com ").expect("valid");
    assert_eq!(email.as_str(), "perneldoreen@gmail.com");
    assert_eq!(email.local(), "perneldoreen");
    assert_eq!(email.domain(), "gmail.com");
  }

  #[test]
  fn parse_rejects_bad_shapes() {
    assert!(matches!(Email::parse(""), Err(EmailError::Empty)));
    assert!(matches!(
      Email::parse("nodomain"),
      Err(EmailError::MissingAt)
    ));
    assert!(matches!(
      Email::parse("a@b@c.com"),
      Err(EmailError::MissingAt)
    ));
    assert!(matches!(
      Email::parse("@gmail.com"),
      Err(EmailError::EmptyLocal)
    ));
    assert!(matches!(
      Email::parse("a@localhost"),
      Err(EmailError::InvalidDomain)
    ));
    assert!(matches!(
      Email::parse("a b@gmail.com"),
      Err(EmailError::IllegalCharacters)
    ));
  }

  #[test]
  fn md5_matches_known_gravatar_hash() {
    let email = Email::parse("MyEmailAddress@example.com ").expect("valid");
    assert_eq!(email.md5_hex(), "0bc83cb571cd1c50ba6f3e8a78ef1346");
  }

  #[test]
  fn encoded_subject_percent_encodes_at_for_url_only() {
    let email = Email::parse("perneldoreen@gmail.com").expect("valid");
    let enc = email.encoded_subject();
    assert_eq!(enc.primary_for_url, "perneldoreen%40gmail.com");
    assert_eq!(enc.primary_raw, "perneldoreen@gmail.com");
    let url_email = &enc
      .for_url
      .iter()
      .find(|(k, _)| *k == "{email}")
      .expect("email var")
      .1;
    assert_eq!(url_email, "perneldoreen%40gmail.com");
    let body_email = &enc
      .for_body
      .iter()
      .find(|(k, _)| *k == "{email}")
      .expect("email var")
      .1;
    assert_eq!(body_email, "perneldoreen@gmail.com");
  }
}
