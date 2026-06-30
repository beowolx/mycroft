use crate::detect::evidence::{Evidence, EvidenceOutcome};
use crate::result::Verdict;

#[derive(Clone, Copy, Debug, Default)]
pub struct Scores {
  pub hit: f32,
  pub miss: f32,
}

#[must_use]
pub fn combine(evidence: &[Evidence]) -> Scores {
  Scores {
    hit: prob_or(
      evidence
        .iter()
        .filter(|e| e.matched && e.outcome == EvidenceOutcome::Hit)
        .map(|e| e.weight),
    ),
    miss: prob_or(
      evidence
        .iter()
        .filter(|e| e.matched && e.outcome == EvidenceOutcome::Miss)
        .map(|e| e.weight),
    ),
  }
}

fn prob_or(weights: impl Iterator<Item = f32>) -> f32 {
  let mut product = 1.0f32;
  for w in weights {
    product *= 1.0 - w.clamp(0.0, 1.0);
  }
  (1.0 - product).clamp(0.0, 1.0)
}

#[must_use]
pub fn resolve(
  scores: Scores,
  min_hit: f32,
  min_miss: f32,
  margin: f32,
) -> Verdict {
  if scores.hit >= min_hit && scores.hit - scores.miss >= margin {
    Verdict::Found
  } else if scores.miss >= min_miss && scores.miss - scores.hit >= margin {
    Verdict::NotFound
  } else {
    Verdict::Uncertain
  }
}

#[cfg(test)]
mod tests {
  use crate::detect::score::{Scores, resolve};
  use crate::result::Verdict;

  #[test]
  fn conflicting_evidence_is_uncertain() {
    let scores = Scores {
      hit: 0.8,
      miss: 0.8,
    };
    assert_eq!(resolve(scores, 0.72, 0.72, 0.18), Verdict::Uncertain);
  }
}
