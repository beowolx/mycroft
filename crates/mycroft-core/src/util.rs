//! Small shared helpers used across the crate.

/// Lowercase hex-encodes a byte slice.
pub fn hex(bytes: &[u8]) -> String {
  use std::fmt::Write as _;
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    let _ = write!(out, "{byte:02x}");
  }
  out
}

/// Current UTC time formatted as RFC 3339, or an empty string if formatting
/// fails.
pub fn now_rfc3339() -> String {
  use time::OffsetDateTime;
  use time::format_description::well_known::Rfc3339;
  OffsetDateTime::now_utc()
    .format(&Rfc3339)
    .unwrap_or_default()
}
