//! Typed errors.
//!
//! `CcpError` carries a §10.4 rejection code for operations that fail outside
//! a `Decision` (grant lifecycle, grant construction). `IdentityError` carries
//! an §25.8 identity-layer code and must never surface as a signal outcome.
//! `HostProfileError` is an invalid §26.4 host contract.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcpError {
    pub code: String,
    pub message: String,
}

impl CcpError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for CcpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            write!(formatter, "{}", self.code)
        } else {
            write!(formatter, "{}: {}", self.code, self.message)
        }
    }
}

impl std::error::Error for CcpError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityError {
    pub code: String,
    pub message: String,
}

impl IdentityError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            write!(formatter, "{}", self.code)
        } else {
            write!(formatter, "{}: {}", self.code, self.message)
        }
    }
}

impl std::error::Error for IdentityError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProfileError {
    pub code: &'static str,
    pub message: String,
}

impl HostProfileError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            code: "invalid_request",
            message: message.into(),
        }
    }
}

impl fmt::Display for HostProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for HostProfileError {}

impl From<HostProfileError> for CcpError {
    fn from(error: HostProfileError) -> Self {
        CcpError::new(error.code, error.message)
    }
}
