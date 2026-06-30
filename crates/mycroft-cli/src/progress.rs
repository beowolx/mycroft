use std::io::IsTerminal;
use std::sync::atomic::{AtomicU64, Ordering};

use indicatif::{ProgressBar, ProgressStyle};

use mycroft_core::Verdict;
use mycroft_core::event::ScanEvent;

pub struct Progress {
  bar: Option<ProgressBar>,
  found: AtomicU64,
}

impl Progress {
  #[must_use]
  pub fn new(enabled: bool) -> Self {
    let bar = (enabled && std::io::stderr().is_terminal()).then(|| {
      let bar = ProgressBar::new(0);
      if let Ok(style) = ProgressStyle::with_template(
        "  {spinner:.cyan} {wide_bar:.cyan/blue} {pos:>4}/{len} {msg}",
      ) {
        bar.set_style(style.progress_chars("█▉▊▋▌▍▎▏ "));
      }
      bar.enable_steady_tick(std::time::Duration::from_millis(120));
      bar
    });
    Self {
      bar,
      found: AtomicU64::new(0),
    }
  }

  #[must_use]
  pub fn bar(&self) -> Option<ProgressBar> {
    self.bar.clone()
  }

  pub fn on_event(&self, event: &ScanEvent) {
    let Some(bar) = &self.bar else {
      return;
    };
    match event {
      ScanEvent::ScanStarted { task_count, .. } => {
        bar.set_length(u64::try_from(*task_count).unwrap_or(u64::MAX));
      }
      ScanEvent::Result { result } => {
        bar.inc(1);
        if result.verdict == Verdict::Found {
          let found = self.found.fetch_add(1, Ordering::Relaxed) + 1;
          bar.set_message(
            console::style(format!("{found} found")).green().to_string(),
          );
        }
      }
      ScanEvent::ScanFinished { .. } => bar.finish_and_clear(),
      _ => {}
    }
  }
}
