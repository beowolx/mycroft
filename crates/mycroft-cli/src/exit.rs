use std::process::ExitCode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
  Ok,
  Internal,
  Usage,
  Io,
  Interrupted,
  NetworkSetup,
  Partial,
  Policy,
}

impl Exit {
  #[must_use]
  pub const fn code(self) -> u8 {
    match self {
      Self::Ok => 0,
      Self::Internal => 1,
      Self::Usage => 2,
      Self::Io => 3,
      Self::Interrupted => 4,
      Self::NetworkSetup => 5,
      Self::Partial => 6,
      Self::Policy => 7,
    }
  }
}

impl From<Exit> for ExitCode {
  fn from(exit: Exit) -> Self {
    Self::from(exit.code())
  }
}
