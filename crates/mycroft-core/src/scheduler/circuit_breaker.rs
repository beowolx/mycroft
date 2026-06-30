use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitState {
  Closed,
  Open,
  HalfOpen,
}

#[derive(Debug)]
pub struct CircuitBreaker {
  state: CircuitState,
  consecutive_failures: u32,
  threshold: u32,
  cooldown: Duration,
  open_until: Option<Instant>,
}

impl CircuitBreaker {
  #[must_use]
  pub const fn new(threshold: u32, cooldown: Duration) -> Self {
    Self {
      state: CircuitState::Closed,
      consecutive_failures: 0,
      threshold,
      cooldown,
      open_until: None,
    }
  }

  pub fn allow(&mut self, now: Instant) -> bool {
    match self.state {
      CircuitState::Open => match self.open_until {
        Some(until) if now < until => false,
        _ => {
          self.state = CircuitState::HalfOpen;
          true
        }
      },
      _ => true,
    }
  }

  #[must_use]
  pub const fn open_until(&self) -> Option<Instant> {
    if matches!(self.state, CircuitState::Open) {
      self.open_until
    } else {
      None
    }
  }

  pub const fn record_success(&mut self) {
    self.consecutive_failures = 0;
    self.state = CircuitState::Closed;
    self.open_until = None;
  }

  pub fn record_failure(&mut self, now: Instant) -> bool {
    self.consecutive_failures += 1;
    if self.consecutive_failures >= self.threshold {
      let was_open = matches!(self.state, CircuitState::Open);
      self.state = CircuitState::Open;
      self.open_until = Some(now + self.cooldown);
      return !was_open;
    }
    false
  }
}

#[cfg(test)]
mod tests {
  use std::time::{Duration, Instant};

  use crate::scheduler::circuit_breaker::CircuitBreaker;

  #[test]
  fn opens_after_threshold_failures() {
    let mut breaker = CircuitBreaker::new(2, Duration::from_secs(30));
    let now = Instant::now();
    assert!(breaker.allow(now));
    assert!(!breaker.record_failure(now));
    assert!(breaker.record_failure(now));
    assert!(!breaker.allow(now));
  }

  #[test]
  fn success_resets_failures() {
    let mut breaker = CircuitBreaker::new(2, Duration::from_secs(30));
    let now = Instant::now();
    breaker.record_failure(now);
    breaker.record_success();
    assert!(!breaker.record_failure(now));
  }
}
