use std::fmt;
use std::path::PathBuf;

/// Errors returned by property operations.
#[derive(Debug)]
pub enum Error {
    NotFound,
    AreaCorrupt(String),
    PermissionDenied(std::io::Error),
    AreaFull,
    Io(std::io::Error),
    ValueTooLong { len: usize },
    InvalidKey,
    PersistCorrupt(String),
    PtraceAttach(std::io::Error),
    PtraceOp(std::io::Error),
    PtraceUnexpectedStatus(i32),
    PtraceScope,
    PtraceTracerBusy { tracer_pid: libc::pid_t },
    ArenaAlreadySealed(PathBuf),
    ArenaNotMapped(PathBuf),
    ElfParse(String),
    SymbolNotFound(String),
    HookInstallFailed(String),
    Unsupported(String),
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
            Self::InvalidKey => write!(f, "invalid property key"),
            Self::PersistCorrupt(msg) => write!(f, "corrupt persist file: {msg}"),
            Self::PtraceAttach(e) => write!(f, "ptrace attach failed: {e}"),
            Self::PtraceOp(e) => write!(f, "ptrace operation failed: {e}"),
            Self::PtraceUnexpectedStatus(status) => write!(
                f,
                "ptrace received unexpected wait status: 0x{status:x}"
            ),
            Self::PtraceScope => write!(
                f,
                "ptrace blocked by /proc/sys/kernel/yama/ptrace_scope; root required or echo 0 into the file"
            ),
            Self::PtraceTracerBusy { tracer_pid } => write!(
                f,
                "ptrace target already traced by pid {tracer_pid}; pause that module and retry"
            ),
            Self::ArenaAlreadySealed(p) => write!(f, "arena already sealed: {}", p.display()),
            Self::ArenaNotMapped(p) => write!(f, "arena not mapped in target process: {}", p.display()),
            Self::ElfParse(msg) => write!(f, "ELF parse error: {msg}"),
            Self::SymbolNotFound(sym) => write!(f, "symbol not found: {sym}"),
            Self::HookInstallFailed(msg) => write!(f, "hook install failed: {msg}"),
            Self::Unsupported(msg) => write!(f, "unsupported: {msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PermissionDenied(e) | Self::Io(e) => Some(e),
            Self::PtraceAttach(e) | Self::PtraceOp(e) => Some(e),
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
