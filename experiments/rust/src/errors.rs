//! Error types for SMCP Security

use thiserror::Error;

/// Main error type for SMCP Security operations
#[derive(Error, Debug)]
pub enum SecurityError {
    /// Input validation failed
    #[error("Validation error: {message}")]
    Validation {
        /// Error message
        message: String,
        /// Validation errors
        errors: Vec<String>,
    },

    /// Authentication failed
    #[error("Authentication error: {message}")]
    Authentication {
        /// Error message
        message: String,
    },

    /// Authorization failed
    #[error("Authorization error: {message}")]
    Authorization {
        /// Error message
        message: String,
        /// Required permission
        required_permission: Option<String>,
    },

    /// Rate limit exceeded
    #[error("Rate limit exceeded: {message}")]
    RateLimit {
        /// Error message
        message: String,
        /// Retry after seconds
        retry_after: u64,
    },

    /// Cryptographic operation failed
    #[error("Cryptographic error: {message}")]
    Cryptographic {
        /// Error message
        message: String,
    },

    /// AI immune system detected a threat
    #[error("Threat detected: {message}")]
    ThreatDetected {
        /// Error message
        message: String,
        /// Threat score
        threat_score: f64,
    },

    /// Configuration error
    #[error("Configuration error: {message}")]
    Configuration {
        /// Error message
        message: String,
    },

    /// Internal error
    #[error("Internal error: {message}")]
    Internal {
        /// Error message
        message: String,
        /// Source error
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// JWT error
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// Regex error
    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    /// Base64 decode error
    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// UUID parse error
    #[error("UUID parse error: {0}")]
    UuidParse(#[from] uuid::Error),

    /// Argon2 error
    #[error("Argon2 error: {0}")]
    Argon2(#[from] argon2::Error),

    /// TOTP error
    #[error("TOTP error: {0}")]
    Totp(#[from] totp_rs::TotpUrlError),

    /// QR code error
    #[error("QR code error: {0}")]
    QrCode(#[from] qrcode::types::QrError),
}

/// Result type for SMCP Security operations
pub type SecurityResult<T> = Result<T, SecurityError>;

/// Validation-specific error
#[derive(Error, Debug)]
#[error("Validation failed: {message}")]
pub struct ValidationError {
    /// Error message
    pub message: String,
    /// List of validation errors
    pub errors: Vec<String>,
}

/// Authentication-specific error
#[derive(Error, Debug)]
#[error("Authentication failed: {message}")]
pub struct AuthenticationError {
    /// Error message
    pub message: String,
}

/// Authorization-specific error
#[derive(Error, Debug)]
#[error("Authorization failed: {message}")]
pub struct AuthorizationError {
    /// Error message
    pub message: String,
    /// Required permission that was missing
    pub required_permission: Option<String>,
}

/// Rate limiting error
#[derive(Error, Debug)]
#[error("Rate limit exceeded: {message}")]
pub struct RateLimitError {
    /// Error message
    pub message: String,
    /// Seconds to wait before retrying
    pub retry_after: u64,
}

/// Cryptographic error
#[derive(Error, Debug)]
#[error("Cryptographic operation failed: {message}")]
pub struct CryptographicError {
    /// Error message
    pub message: String,
}

/// AI immune system error
#[derive(Error, Debug)]
#[error("AI immune system error: {message}")]
pub struct AIImmuneError {
    /// Error message
    pub message: String,
    /// Threat score that triggered the error
    pub threat_score: f64,
}

impl SecurityError {
    /// Create a new validation error
    pub fn validation(message: impl Into<String>, errors: Vec<String>) -> Self {
        Self::Validation {
            message: message.into(),
            errors,
        }
    }

    /// Create a new authentication error
    pub fn authentication(message: impl Into<String>) -> Self {
        Self::Authentication {
            message: message.into(),
        }
    }

    /// Create a new authorization error
    pub fn authorization(message: impl Into<String>, required_permission: Option<String>) -> Self {
        Self::Authorization {
            message: message.into(),
            required_permission,
        }
    }

    /// Create a new rate limit error
    pub fn rate_limit(message: impl Into<String>, retry_after: u64) -> Self {
        Self::RateLimit {
            message: message.into(),
            retry_after,
        }
    }

    /// Create a new cryptographic error
    pub fn cryptographic(message: impl Into<String>) -> Self {
        Self::Cryptographic {
            message: message.into(),
        }
    }

    /// Create a new threat detection error
    pub fn threat_detected(message: impl Into<String>, threat_score: f64) -> Self {
        Self::ThreatDetected {
            message: message.into(),
            threat_score,
        }
    }

    /// Create a new configuration error
    pub fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }

    /// Create a new internal error
    pub fn internal(
        message: impl Into<String>,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Internal {
            message: message.into(),
            source,
        }
    }

    /// Get the error code for HTTP responses
    pub fn status_code(&self) -> u16 {
        match self {
            SecurityError::Validation { .. } => 400,
            SecurityError::Authentication { .. } => 401,
            SecurityError::Authorization { .. } => 403,
            SecurityError::ThreatDetected { .. } => 403,
            SecurityError::RateLimit { .. } => 429,
            SecurityError::Configuration { .. } => 500,
            SecurityError::Internal { .. } => 500,
            SecurityError::Cryptographic { .. } => 500,
            SecurityError::Json(_) => 400,
            SecurityError::Jwt(_) => 401,
            SecurityError::Regex(_) => 500,
            SecurityError::Base64Decode(_) => 400,
            SecurityError::UuidParse(_) => 400,
            SecurityError::Argon2(_) => 500,
            SecurityError::Totp(_) => 400,
            SecurityError::QrCode(_) => 500,
        }
    }

    /// Check if this is a client error (4xx)
    pub fn is_client_error(&self) -> bool {
        let code = self.status_code();
        code >= 400 && code < 500
    }

    /// Check if this is a server error (5xx)
    pub fn is_server_error(&self) -> bool {
        let code = self.status_code();
        code >= 500 && code < 600
    }
}
