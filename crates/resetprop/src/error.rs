use std::fmt;

#[derive(Debug)]
pub enum Error {
    NotFound,
    AreaCorrupt(String),
    PermissionDenied(std::io::Error),
    AreaFull,
    Io(std::io::Error),
    ValueTooLong { len: usize },
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "property not found"),
            Self::AreaCorrupt(msg) => write!(f, "corrupt property area: {msg}"),
            Self::PermissionDenied(e) => write!(f, "permission denied: {e}"),
            Self::AreaFull => write!(f, "property area full"),
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::ValueTooLong { len } => write!(f, "value too long: {len} bytes"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PermissionDenied(e) | Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        match e.raw_os_error() {
            Some(libc::EACCES | libc::EPERM) => Self::PermissionDenied(e),
            _ => Self::Io(e),
        }
    }
}
