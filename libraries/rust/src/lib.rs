//! # SMCP Security - Rust Library
//!
//! Secure Model Context Protocol (SMCP) v1 - A production-ready security framework
//! for Model Context Protocol implementations in Rust.
//!
//! ## Features
//!
//! - Multi-layered security with input validation, authentication, authorization, and encryption
//! - AI-immune system with machine learning-based threat detection
//! - High performance with zero-cost abstractions
//! - Comprehensive auditing and monitoring
//! - Adaptive rate limiting with DoS protection
//! - Easy integration with popular Rust web frameworks
//! - Memory safety guarantees from Rust
//! - Async-first design
//!
//! ## Quick Start
//!
//! ```rust
//! use smcp_security::{SecurityFramework, SecurityConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize security framework
//!     let security = SecurityFramework::new(SecurityConfig::default()).await?;
//!     
//!     // Use the framework...
//!     Ok(())
//! }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]
#![deny(unsafe_code)]

pub mod core;
pub mod validation;
pub mod auth;
pub mod crypto;
pub mod ratelimit;
pub mod audit;
pub mod ai;
pub mod types;
pub mod errors;

// Framework integrations
#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
pub mod axum;

#[cfg(feature = "warp")]
#[cfg_attr(docsrs, doc(cfg(feature = "warp")))]
pub mod warp;

#[cfg(feature = "actix")]
#[cfg_attr(docsrs, doc(cfg(feature = "actix")))]
pub mod actix;

// Re-exports for convenience
pub use crate::core::{SecurityFramework, SecurityConfig};
pub use crate::types::*;
pub use crate::errors::*;
pub use crate::validation::{InputValidator, ValidationStrictness};
pub use crate::auth::{JWTAuthenticator, MFAManager, RBACManager};
pub use crate::crypto::{SMCPCrypto, CryptoConfig};
pub use crate::ratelimit::{AdaptiveRateLimiter, RateLimitConfig};
pub use crate::audit::{AuditLogger, LogLevel};
pub use crate::ai::{AIImmuneSystem, AIImmuneConfig};

/// Current version of the SMCP Security library
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default security configuration for development environments
pub fn development_config() -> SecurityConfig {
    SecurityConfig {
        enable_mfa: false,
        validation_strictness: ValidationStrictness::Minimal,
        enable_ai_immune: false,
        anomaly_threshold: 0.9,
        default_rate_limit: 1000,
        learning_mode: true,
        log_level: LogLevel::Debug,
        ..Default::default()
    }
}

/// Default security configuration for production environments
pub fn production_config() -> SecurityConfig {
    SecurityConfig {
        enable_mfa: true,
        validation_strictness: ValidationStrictness::Maximum,
        enable_ai_immune: true,
        anomaly_threshold: 0.7,
        default_rate_limit: 100,
        learning_mode: false,
        log_level: LogLevel::Info,
        ..Default::default()
    }
}

/// Default security configuration for testing environments
pub fn testing_config() -> SecurityConfig {
    SecurityConfig {
        enable_mfa: false,
        validation_strictness: ValidationStrictness::Standard,
        enable_ai_immune: false,
        enable_rate_limiting: false,
        enable_audit_logging: false,
        log_level: LogLevel::Error,
        ..Default::default()
    }
}
