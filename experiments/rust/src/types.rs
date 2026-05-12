//! Type definitions for SMCP Security

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Represents a Model Context Protocol request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MCPRequest {
    /// JSON-RPC version (should be "2.0")
    pub jsonrpc: String,
    /// Unique request identifier
    pub id: String,
    /// Method name to call
    pub method: String,
    /// Optional parameters for the method
    pub params: Option<serde_json::Value>,
}

/// Represents a Model Context Protocol response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MCPResponse {
    /// JSON-RPC version (should be "2.0")
    pub jsonrpc: String,
    /// Request identifier this response corresponds to
    pub id: String,
    /// Result data (present on success)
    pub result: Option<serde_json::Value>,
    /// Error information (present on failure)
    pub error: Option<MCPError>,
}

/// Represents an MCP error
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MCPError {
    /// Error code
    pub code: i32,
    /// Human-readable error message
    pub message: String,
    /// Additional error data
    pub data: Option<serde_json::Value>,
}

/// User authentication credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCredentials {
    /// Username
    pub username: String,
    /// Password
    pub password: String,
    /// Optional MFA code
    pub mfa_code: Option<String>,
}

/// Authenticated user context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserContext {
    /// Unique user identifier
    pub user_id: String,
    /// Username
    pub username: String,
    /// User role
    pub role: String,
    /// User permissions
    pub permissions: Vec<String>,
    /// Session identifier
    pub session_id: String,
    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,
}

/// Security metrics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityMetrics {
    /// Total number of requests processed
    pub total_requests: u64,
    /// Number of requests blocked
    pub blocked_requests: u64,
    /// Number of threats detected
    pub threats_detected: u64,
    /// Average response time in milliseconds
    pub average_response_time: f64,
    /// Number of active users
    pub active_users: u64,
    /// Number of rate limit hits
    pub rate_limit_hits: u64,
    /// Number of authentication failures
    pub authentication_failures: u64,
    /// Timestamp of last threat detected
    pub last_threat_detected: Option<DateTime<Utc>>,
}

/// Threat analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAnalysis {
    /// Risk score (0.0 to 1.0)
    pub risk_score: f64,
    /// Type of threat detected
    pub threat_type: String,
    /// Confidence in the analysis (0.0 to 1.0)
    pub confidence: f64,
    /// Threat indicators
    pub indicators: Vec<String>,
    /// Recommended action
    pub recommended_action: RecommendedAction,
}

/// Recommended action for threat response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RecommendedAction {
    /// Allow the request
    Allow,
    /// Block the request
    Block,
    /// Monitor the request
    Monitor,
}

/// Validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the validation passed
    pub is_valid: bool,
    /// Validation errors
    pub errors: Vec<String>,
    /// Sanitized data (if applicable)
    pub sanitized_data: Option<serde_json::Value>,
    /// Risk score (0.0 to 1.0)
    pub risk_score: f64,
}

/// Audit event for logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier
    pub id: Uuid,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// User ID (if applicable)
    pub user_id: Option<String>,
    /// Action performed
    pub action: String,
    /// Resource accessed
    pub resource: String,
    /// Result of the action
    pub result: AuditResult,
    /// Risk score
    pub risk_score: f64,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Result of an audited action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditResult {
    /// Action succeeded
    Success,
    /// Action failed
    Failure,
    /// Action was blocked
    Blocked,
}

/// MFA secret information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MFASecret {
    /// Base32-encoded secret
    pub secret: String,
    /// QR code as base64-encoded PNG
    pub qr_code: String,
    /// Backup codes
    pub backup_codes: Vec<String>,
}

/// Role definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Role name
    pub name: String,
    /// Permissions granted by this role
    pub permissions: Vec<String>,
    /// Role description
    pub description: Option<String>,
}

/// Permission definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    /// Permission name
    pub name: String,
    /// Resource this permission applies to
    pub resource: String,
    /// Action this permission allows
    pub action: String,
    /// Permission description
    pub description: Option<String>,
}

/// AI model information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIModel {
    /// Model name
    pub name: String,
    /// Model version
    pub version: String,
    /// Model accuracy
    pub accuracy: f64,
    /// Last training timestamp
    pub last_trained: DateTime<Utc>,
}

/// Learning data for AI training
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningData {
    /// Feature vector
    pub features: Vec<f64>,
    /// Label (benign or malicious)
    pub label: ThreatLabel,
    /// Confidence in the label
    pub confidence: f64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Threat label for training data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatLabel {
    /// Benign request
    Benign,
    /// Malicious request
    Malicious,
}

/// Options for processing a secure request
#[derive(Debug, Clone)]
pub struct SecureRequestOptions {
    /// The MCP request to process
    pub request: MCPRequest,
    /// User ID
    pub user_id: String,
    /// Session token
    pub session_token: String,
    /// Client IP address
    pub client_ip: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
}

/// JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Username
    pub username: String,
    /// User role
    pub role: String,
    /// User permissions
    pub permissions: Vec<String>,
    /// Session ID
    pub session_id: String,
    /// Issued at timestamp
    pub iat: i64,
    /// Expiration timestamp
    pub exp: i64,
}

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// Current request count
    pub current_count: u32,
    /// Rate limit
    pub limit: u32,
    /// Time window in seconds
    pub window_seconds: u64,
    /// Time until reset
    pub reset_time: DateTime<Utc>,
    /// Whether the limit is exceeded
    pub exceeded: bool,
}
