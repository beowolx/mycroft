mod cache;
pub(crate) mod classifier;
pub mod evidence;
pub(crate) mod fingerprint;
pub(crate) mod score;
pub(crate) mod signals;

pub use evidence::{Evidence, EvidenceOutcome};

use mycroft_manifest::schema::{BlockClass, BlockSignal, SignalKind};
use mycroft_manifest::{ManifestDefaults, Site};

use crate::detect::cache::DetectionCache;
use crate::detect::signals::{SignalContext, evaluate, is_body_signal};
use crate::net::ProbeResponse;
use crate::result::Verdict;

#[derive(Clone, Copy, Debug)]
pub struct DetectionDefaults {
  pub min_hit_score: f32,
  pub min_miss_score: f32,
  pub decision_margin: f32,
}

#[derive(Clone, Copy)]
pub struct ControlInput<'a> {
  pub response: &'a ProbeResponse,
  pub username_for_url: &'a str,
  pub username_raw: &'a str,
}

pub struct Detector {
  defaults: DetectionDefaults,
  global_block: Vec<BlockSignal>,
  cache: DetectionCache,
}

#[derive(Clone, Debug)]
pub struct DetectionResult {
  pub verdict: Verdict,
  pub evidence: Vec<Evidence>,
  pub control_similarity: Option<f32>,
}

impl Detector {
  #[must_use]
  pub fn new(defaults: &ManifestDefaults) -> Self {
    Self {
      defaults: DetectionDefaults {
        min_hit_score: defaults.min_hit_score,
        min_miss_score: defaults.min_miss_score,
        decision_margin: defaults.decision_margin,
      },
      global_block: defaults.block_signals.clone(),
      cache: DetectionCache::new(),
    }
  }

  #[must_use]
  pub fn evaluate(
    &self,
    site: &Site,
    username_for_url: &str,
    username_raw: &str,
    profile_url: &str,
    primary: &ProbeResponse,
    control: Option<ControlInput<'_>>,
  ) -> DetectionResult {
    let body = primary.body_text();

    let primary_succeeded = matches!(primary.status, 200..=299);
    let global_block = self.global_block.iter().filter(|s| {
      !(primary_succeeded
        && matches!(s.kind, SignalKind::BodySubstring | SignalKind::BodyRegex))
    });
    let block_signals = global_block.chain(site.detection.block_signals.iter());
    if let Some((class, evidence)) =
      classifier::classify(primary, &body, &self.cache, block_signals)
    {
      return DetectionResult {
        verdict: block_verdict(class),
        evidence: vec![evidence],
        control_similarity: None,
      };
    }

    let control_resp = control.as_ref().map(|c| c.response);
    let control_body = control_resp.map(ProbeResponse::body_text);
    let target_ctx = SignalContext {
      response: primary,
      body_text: &body,
      username_for_url,
      username_raw,
      profile_url,
      control: control_resp,
      control_body: control_body.as_deref(),
      cache: &self.cache,
    };
    let mut evidence =
      Self::collect_evidence(site, &target_ctx, primary.status);
    let (min_hit, min_miss, margin) = self.thresholds(site);
    let scores = score::combine(&evidence);
    let mut verdict = score::resolve(scores, min_hit, min_miss, margin);

    let control_similarity = control.as_ref().map(|c| {
      let c_body = c.response.body_text();
      fingerprint::similarity(
        &fingerprint::fingerprint(&body, &self.cache),
        &fingerprint::fingerprint(&c_body, &self.cache),
      )
    });

    if let Some(c) = control.as_ref() {
      if verdict == Verdict::Found
        && self.control_also_found(
          site,
          c,
          profile_url,
          min_hit,
          min_miss,
          margin,
        )
      {
        evidence.push(Evidence::matched(
          "control_indistinguishable",
          EvidenceOutcome::Miss,
          0.9,
          "absent-control username produced the same verdict (soft-404)",
        ));
        verdict = Verdict::NotFound;
      }
    }

    DetectionResult {
      verdict,
      evidence,
      control_similarity,
    }
  }

  fn control_also_found(
    &self,
    site: &Site,
    control: &ControlInput<'_>,
    profile_url: &str,
    min_hit: f32,
    min_miss: f32,
    margin: f32,
  ) -> bool {
    let body = control.response.body_text();
    let ctx = SignalContext {
      response: control.response,
      body_text: &body,
      username_for_url: control.username_for_url,
      username_raw: control.username_raw,
      profile_url,
      control: None,
      control_body: None,
      cache: &self.cache,
    };
    let evidence = Self::collect_evidence(site, &ctx, control.response.status);
    let scores = score::combine(&evidence);
    score::resolve(scores, min_hit, min_miss, margin) == Verdict::Found
  }

  fn collect_evidence(
    site: &Site,
    ctx: &SignalContext<'_>,
    status: u16,
  ) -> Vec<Evidence> {
    let gate = site.detection.status_gate.as_ref();
    let mut evidence = Vec::new();
    for signal in &site.detection.signals {
      if is_body_signal(signal.kind.kind())
        && gate.is_some_and(|g| {
          !g.body_signals_allowed_status.is_empty()
            && !g.body_signals_allowed_status.contains(&status)
        })
      {
        continue;
      }
      if let Some(item) = evaluate(ctx, signal) {
        evidence.push(item);
      }
    }
    evidence
  }

  fn thresholds(&self, site: &Site) -> (f32, f32, f32) {
    (
      site
        .detection
        .min_hit_score
        .unwrap_or(self.defaults.min_hit_score),
      site
        .detection
        .min_miss_score
        .unwrap_or(self.defaults.min_miss_score),
      site
        .detection
        .decision_margin
        .unwrap_or(self.defaults.decision_margin),
    )
  }
}

const fn block_verdict(class: BlockClass) -> Verdict {
  match class {
    BlockClass::Blocked => Verdict::Blocked,
    BlockClass::RateLimited => Verdict::RateLimited,
    BlockClass::Captcha => Verdict::Captcha,
    BlockClass::LoginRequired => Verdict::LoginRequired,
    BlockClass::Unsupported => Verdict::Uncertain,
  }
}
