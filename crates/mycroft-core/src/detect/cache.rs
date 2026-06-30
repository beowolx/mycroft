use std::collections::HashMap;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use regex::Regex;
use scraper::Selector;

type RegexCache = HashMap<String, Option<Arc<Regex>>>;

pub struct DetectionCache {
  regexes: RwLock<RegexCache>,
  title_selector: Option<Selector>,
}

impl DetectionCache {
  pub fn new() -> Self {
    Self {
      regexes: RwLock::new(HashMap::new()),
      title_selector: Selector::parse("title").ok(),
    }
  }

  pub fn regex(&self, pattern: &str) -> Option<Arc<Regex>> {
    if let Some(cached) = read_lock(&self.regexes).get(pattern) {
      return cached.clone();
    }
    let compiled = Regex::new(pattern).ok().map(Arc::new);
    write_lock(&self.regexes).insert(pattern.to_owned(), compiled.clone());
    compiled
  }

  pub const fn title_selector(&self) -> Option<&Selector> {
    self.title_selector.as_ref()
  }
}

fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
  match lock.read() {
    Ok(guard) => guard,
    Err(poisoned) => poisoned.into_inner(),
  }
}

fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
  match lock.write() {
    Ok(guard) => guard,
    Err(poisoned) => poisoned.into_inner(),
  }
}
