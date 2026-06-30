use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOutcome {
  Hit,
  Miss,
  Uncertain,
  Blocked,
  RateLimited,
  Captcha,
  LoginRequired,
  Unsupported,
}

impl From<mycroft_manifest::EvidenceOutcome> for EvidenceOutcome {
  fn from(value: mycroft_manifest::EvidenceOutcome) -> Self {
    match value {
      mycroft_manifest::EvidenceOutcome::Hit => Self::Hit,
      mycroft_manifest::EvidenceOutcome::Miss => Self::Miss,
      mycroft_manifest::EvidenceOutcome::Uncertain => Self::Uncertain,
    }
  }
}

impl From<mycroft_manifest::schema::BlockClass> for EvidenceOutcome {
  fn from(value: mycroft_manifest::schema::BlockClass) -> Self {
    use mycroft_manifest::schema::BlockClass;
    match value {
      BlockClass::Blocked => Self::Blocked,
      BlockClass::RateLimited => Self::RateLimited,
      BlockClass::Captcha => Self::Captcha,
      BlockClass::LoginRequired => Self::LoginRequired,
      BlockClass::Unsupported => Self::Unsupported,
    }
  }
}

#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
  pub signal_id: String,
  pub outcome: EvidenceOutcome,
  pub weight: f32,
  pub matched: bool,
  pub message: String,
}

impl Evidence {
  pub fn matched(
    signal_id: impl Into<String>,
    outcome: EvidenceOutcome,
    weight: f32,
    message: impl Into<String>,
  ) -> Self {
    Self {
      signal_id: signal_id.into(),
      outcome,
      weight,
      matched: true,
      message: message.into(),
    }
  }
}
