use std::num::NonZeroU32;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use tokio::sync::Semaphore;

use crate::config::SchedulerLimits;
use crate::scheduler::circuit_breaker::CircuitBreaker;

const BREAKER_THRESHOLD: u32 = 5;
const BREAKER_COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
  Success,
  Failure,
}

pub struct HostState {
  semaphore: Semaphore,
  limiter: Option<DefaultDirectRateLimiter>,
  breaker: Mutex<CircuitBreaker>,
}

impl HostState {
  #[must_use]
  pub fn new(limits: &SchedulerLimits) -> Self {
    Self {
      semaphore: Semaphore::new(limits.per_host_concurrency.max(1)),
      limiter: build_limiter(limits.per_host_rps, limits.per_host_burst),
      breaker: Mutex::new(CircuitBreaker::new(
        BREAKER_THRESHOLD,
        BREAKER_COOLDOWN,
      )),
    }
  }

  pub async fn acquire(&self) -> Option<tokio::sync::SemaphorePermit<'_>> {
    self.semaphore.acquire().await.ok()
  }

  pub async fn rate_limit(&self) {
    if let Some(limiter) = &self.limiter {
      limiter.until_ready().await;
    }
  }

  #[must_use]
  pub fn allow(&self, now: Instant) -> bool {
    lock_breaker(&self.breaker).allow(now)
  }

  pub fn record_outcome(
    &self,
    outcome: ProbeOutcome,
    now: Instant,
  ) -> Option<u64> {
    let mut breaker = lock_breaker(&self.breaker);
    match outcome {
      ProbeOutcome::Success => {
        breaker.record_success();
        None
      }
      ProbeOutcome::Failure => {
        if breaker.record_failure(now) {
          breaker.open_until().map(|until| {
            u64::try_from(until.saturating_duration_since(now).as_millis())
              .unwrap_or(u64::MAX)
          })
        } else {
          None
        }
      }
    }
  }
}

fn lock_breaker(
  breaker: &Mutex<CircuitBreaker>,
) -> MutexGuard<'_, CircuitBreaker> {
  match breaker.lock() {
    Ok(guard) => guard,
    Err(poisoned) => poisoned.into_inner(),
  }
}

fn build_limiter(rps: f64, burst: u32) -> Option<DefaultDirectRateLimiter> {
  if rps <= 0.0 || !rps.is_finite() {
    return None;
  }
  let period = Duration::try_from_secs_f64(1.0 / rps).ok()?;
  let quota =
    Quota::with_period(period)?.allow_burst(NonZeroU32::new(burst.max(1))?);
  Some(RateLimiter::direct(quota))
}

#[cfg(test)]
mod tests {
  use std::time::Instant;

  use crate::config::SchedulerLimits;
  use crate::scheduler::host_limiter::{HostState, ProbeOutcome};

  #[test]
  fn breaker_opens_on_the_threshold_failure_and_blocks() {
    let host = HostState::new(&SchedulerLimits::default());
    let now = Instant::now();
    for _ in 0..4 {
      assert!(host.record_outcome(ProbeOutcome::Failure, now).is_none());
      assert!(host.allow(now));
    }
    assert!(host.record_outcome(ProbeOutcome::Failure, now).is_some());
    assert!(!host.allow(now));
  }

  #[test]
  fn a_success_resets_the_failure_run() {
    let host = HostState::new(&SchedulerLimits::default());
    let now = Instant::now();
    for _ in 0..4 {
      host.record_outcome(ProbeOutcome::Failure, now);
    }
    assert!(host.record_outcome(ProbeOutcome::Success, now).is_none());
    assert!(host.record_outcome(ProbeOutcome::Failure, now).is_none());
    assert!(host.allow(now));
  }
}
