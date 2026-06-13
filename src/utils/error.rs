use std::fmt;

#[derive(Debug, PartialEq)]
pub enum AppError {
    ProcessNotFound(String),
    PermissionDenied(u32),
    PlatformUnsupported,
    MissingArg(String),
    InvalidArg(String),
    UnknownCommand(String),
    Other(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::ProcessNotFound(name) => write!(f, "process '{}' not found", name),
            AppError::PermissionDenied(pid) => {
                write!(f, "permission denied accessing process {}", pid)
            }
            AppError::PlatformUnsupported => {
                write!(f, "operation not supported on this platform")
            }
            AppError::MissingArg(name) => write!(f, "missing argument: {}", name),
            AppError::InvalidArg(msg) => write!(f, "{}", msg),
            AppError::UnknownCommand(cmd) => {
                write!(f, "unknown command '{}' — run 'mvis --help'", cmd)
            }
            AppError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for AppError {}
