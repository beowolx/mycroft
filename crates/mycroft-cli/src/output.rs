use std::borrow::Cow;
use std::io::{self, Write};

use console::Style;
use indicatif::ProgressBar;

use mycroft_core::event::ScanEvent;
use mycroft_core::result::{ScanReport, SiteResult, Verdict};

use crate::args::{FormatArg, PrintArg};

pub type Sink = Box<dyn Write + Send>;

pub trait OutputWriter: Send {
  fn on_event(&mut self, event: &ScanEvent) -> io::Result<()>;
  fn finish(&mut self, report: &ScanReport) -> io::Result<()>;
}

pub struct HumanOptions {
  pub print: PrintArg,
  pub verbose: bool,
  pub quiet: bool,
  pub color: bool,
  pub bar: Option<ProgressBar>,
}

#[must_use]
pub fn make_writer(
  format: FormatArg,
  sink: Sink,
  human: HumanOptions,
) -> Box<dyn OutputWriter> {
  match format {
    FormatArg::Human => Box::new(HumanWriter {
      sink,
      print: human.print,
      verbose: human.verbose,
      quiet: human.quiet,
      color: human.color,
      bar: human.bar,
    }),
    FormatArg::Json => Box::new(JsonWriter { sink }),
    FormatArg::Ndjson => Box::new(NdjsonWriter { sink }),
    FormatArg::Csv => Box::new(CsvWriter {
      sink,
      scan_id: String::new(),
    }),
  }
}

struct HumanWriter {
  sink: Sink,
  print: PrintArg,
  verbose: bool,
  quiet: bool,
  color: bool,
  bar: Option<ProgressBar>,
}

impl OutputWriter for HumanWriter {
  fn on_event(&mut self, event: &ScanEvent) -> io::Result<()> {
    match event {
      ScanEvent::ScanStarted {
        scan_id,
        task_count,
      } if !self.quiet => {
        let line = self.header(&scan_id.to_string(), *task_count);
        self.emit(&line)
      }
      ScanEvent::Result { result } if should_print(result, self.print) => {
        let block = self.render_row(result);
        self.emit(&block)
      }
      _ => Ok(()),
    }
  }

  fn finish(&mut self, report: &ScanReport) -> io::Result<()> {
    if self.quiet {
      return Ok(());
    }
    writeln!(self.sink, "\n{}", self.summary(&report.summary))
  }
}

impl HumanWriter {
  fn paint(&self, style: Style, text: &str) -> String {
    style.force_styling(self.color).apply_to(text).to_string()
  }

  fn header(&self, scan_id: &str, task_count: usize) -> String {
    let id = scan_id.get(..12).unwrap_or(scan_id);
    format!(
      "  {} {}\n",
      self.paint(
        Style::new().bold(),
        &format!("mycroft v{}", env!("CARGO_PKG_VERSION"))
      ),
      self.paint(Style::new().dim(), &format!("· {task_count} checks · {id}")),
    )
  }

  fn render_row(&self, result: &SiteResult) -> String {
    let glyph =
      self.paint(verdict_style(result.verdict), verdict_glyph(result.verdict));
    let name_style = if result.verdict == Verdict::Found {
      Style::new().bold()
    } else {
      Style::new()
    };
    let name = self.paint(
      name_style,
      &format!("{:<22}", truncate(&result.site_name, 22)),
    );
    let detail = self.detail(result);

    let mut block = format!("  {glyph}  {name} {detail}");
    if self.verbose {
      for evidence in &result.evidence {
        block.push('\n');
        block.push_str(&self.paint(
          Style::new().dim(),
          &format!(
            "        {} [{}] {}",
            evidence.signal_id, evidence.weight, evidence.message
          ),
        ));
      }
    }
    block
  }

  fn detail(&self, result: &SiteResult) -> String {
    if let Some(url) = &result.profile_url {
      return url.clone();
    }
    if let Some(error) = &result.error {
      return self.paint(Style::new().red(), &error.message);
    }
    String::new()
  }

  fn summary(&self, s: &mycroft_core::result::ScanSummary) -> String {
    let mut parts = vec![
      self.paint(Style::new().green().bold(), &format!("{} found", s.found)),
      format!("{} not found", s.not_found),
      format!("{} uncertain", s.uncertain),
      format!("{} blocked", s.blocked),
      format!("{} rate-limited", s.rate_limited),
      format!("{} invalid", s.invalid_username),
    ];
    let errors = format!("{} errors", s.errors);
    parts.push(if s.errors > 0 {
      self.paint(Style::new().red(), &errors)
    } else {
      errors
    });
    parts.push(self.paint(Style::new().dim(), &format_elapsed(s.elapsed_ms)));
    format!(
      "  {}",
      parts.join(self.paint(Style::new().dim(), "  ·  ").as_str())
    )
  }

  fn emit(&mut self, line: &str) -> io::Result<()> {
    match self.bar.clone() {
      Some(bar) => bar.suspend(|| writeln!(self.sink, "{line}")),
      None => writeln!(self.sink, "{line}"),
    }
  }
}

const fn verdict_glyph(verdict: Verdict) -> &'static str {
  match verdict {
    Verdict::Found => "✓",
    Verdict::NotFound => "✗",
    Verdict::Uncertain => "?",
    Verdict::Blocked => "■",
    Verdict::RateLimited => "~",
    Verdict::Captcha => "▦",
    Verdict::LoginRequired => "⚿",
    Verdict::InvalidUsername => "!",
    Verdict::Skipped => "·",
  }
}

const fn verdict_style(verdict: Verdict) -> Style {
  let base = Style::new();
  match verdict {
    Verdict::Found => base.green().bold(),
    Verdict::Uncertain | Verdict::RateLimited => base.yellow(),
    Verdict::Blocked
    | Verdict::Captcha
    | Verdict::LoginRequired
    | Verdict::InvalidUsername => base.red(),
    Verdict::NotFound | Verdict::Skipped => base.dim(),
  }
}

fn format_elapsed(ms: u64) -> String {
  if ms < 1000 {
    format!("{ms}ms")
  } else if ms < 60_000 {
    format!("{}.{}s", ms / 1000, (ms % 1000) / 100)
  } else {
    let secs = ms / 1000;
    format!("{}m{:02}s", secs / 60, secs % 60)
  }
}

struct JsonWriter {
  sink: Sink,
}

impl OutputWriter for JsonWriter {
  fn on_event(&mut self, _event: &ScanEvent) -> io::Result<()> {
    Ok(())
  }

  fn finish(&mut self, report: &ScanReport) -> io::Result<()> {
    let json = serde_json::to_string_pretty(report)
      .map_err(|e| io::Error::other(e.to_string()))?;
    writeln!(self.sink, "{json}")
  }
}

struct NdjsonWriter {
  sink: Sink,
}

impl OutputWriter for NdjsonWriter {
  fn on_event(&mut self, event: &ScanEvent) -> io::Result<()> {
    let line = serde_json::to_string(event)
      .map_err(|e| io::Error::other(e.to_string()))?;
    writeln!(self.sink, "{line}")
  }

  fn finish(&mut self, _report: &ScanReport) -> io::Result<()> {
    self.sink.flush()
  }
}

struct CsvWriter {
  sink: Sink,
  scan_id: String,
}

impl OutputWriter for CsvWriter {
  fn on_event(&mut self, event: &ScanEvent) -> io::Result<()> {
    match event {
      ScanEvent::ScanStarted { scan_id, .. } => {
        self.scan_id = scan_id.to_string();
        writeln!(
          self.sink,
          "scan_id,username,site_id,site_name,verdict,\
           profile_url,status,final_url,elapsed_ms,error_kind"
        )
      }
      ScanEvent::Result { result } => self.write_row(result),
      _ => Ok(()),
    }
  }

  fn finish(&mut self, _report: &ScanReport) -> io::Result<()> {
    self.sink.flush()
  }
}

impl CsvWriter {
  fn write_row(&mut self, r: &SiteResult) -> io::Result<()> {
    let status = r.probe.status.map_or_else(String::new, |s| s.to_string());
    let final_url = r.probe.final_url.clone().unwrap_or_default();
    let error_kind = r
      .error
      .as_ref()
      .map_or_else(String::new, |e| format!("{:?}", e.kind));
    let fields = [
      self.scan_id.clone(),
      r.username.clone(),
      r.site_id.clone(),
      r.site_name.clone(),
      r.verdict.as_str().to_string(),
      r.profile_url.clone().unwrap_or_default(),
      status,
      final_url,
      r.probe.elapsed_ms.to_string(),
      error_kind,
    ];
    writeln!(
      self.sink,
      "{}",
      fields
        .iter()
        .map(|f| csv_escape(f))
        .collect::<Vec<_>>()
        .join(",")
    )
  }
}

fn csv_escape(field: &str) -> Cow<'_, str> {
  if field.contains([',', '"', '\n', '\r']) {
    Cow::Owned(format!("\"{}\"", field.replace('"', "\"\"")))
  } else {
    Cow::Borrowed(field)
  }
}

fn should_print(result: &SiteResult, print: PrintArg) -> bool {
  match print {
    PrintArg::Found => result.verdict == Verdict::Found,
    PrintArg::All => true,
    PrintArg::Uncertain => {
      matches!(result.verdict, Verdict::Found | Verdict::Uncertain)
    }
    PrintArg::Errors => {
      result.verdict == Verdict::Found || result.error.is_some()
    }
  }
}

fn truncate(value: &str, max: usize) -> String {
  if value.chars().count() <= max {
    value.to_string()
  } else {
    let mut s: String = value.chars().take(max.saturating_sub(1)).collect();
    s.push('…');
    s
  }
}
