//! Core security framework implementation

use crate::{
    ai::{AIImmuneConfig, AIImmuneSystem},
    audit::{AuditLogger, LogLevel},
    auth::{JWTAuthenticator, MFAManager, RBACManager},
    crypto::{CryptoConfig, SMCPCrypto},
    errors::{SecurityError, SecurityResult},
    ratelimit::{AdaptiveRateLimiter, RateLimitConfig},
    types::*,
    validation::{InputValidator, ValidationStrictness},
};
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

/// Main security framework that orchestrates all security components
#[derive(Clone)]
pub struct SecurityFramework {
    config: SecurityConfig,
    input_validator: Option<Arc<InputValidator>>,
    jwt_auth: Arc<JWTAuthenticator>,
    mfa_manager: Option<Arc<MFAManager>>,
    rbac_manager: Option<Arc<RwLock<RBACManager>>>,
    rate_limiter: Option<Arc<AdaptiveRateLimiter>>,
    crypto: Option<Arc<SMCPCrypto>>,
    audit_logger: Option<Arc<AuditLogger>>,
    ai_immune: Option<Arc<AIImmuneSystem>>,
    metrics: Arc<RwLock<SecurityMetrics>>,
}

/// Security configuration
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    // Input validation settings
    pub enable_input_validation: bool,
    pub validation_strictness: ValidationStrictness,

    // Authentication settings
    pub enable_mfa: bool,
    pub jwt_expiry_seconds: u64,
    pub session_timeout_seconds: u64,

    // Authorization settings
    pub enable_rbac: bool,
    pub default_permissions: Vec<String>,

    // Rate limiting settings
    pub enable_rate_limiting: bool,
    pub default_rate_limit: u32,
    pub adaptive_limits: bool,

    // Cryptographic settings
    pub enable_encryption: bool,
    pub key_rotation_interval: u64,

    // AI immune system settings
    pub enable_ai_immune: bool,
    pub anomaly_threshold: f64,
    pub learning_mode: bool,

    // Audit settings
    pub enable_audit_logging: bool,
    pub log_level: LogLevel,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_input_validation: true,
            validation_strictness: ValidationStrictness::Standard,
            enable_mfa: true,
            jwt_expiry_seconds: 3600,
            session_timeout_seconds: 7200,
            enable_rbac: true,
            default_permissions: vec!["read".to_string()],
            enable_rate_limiting: true,
            default_rate_limit: 100,
            adaptive_limits: true,
            enable_encryption: true,
            key_rotation_interval: 86400,
            enable_ai_immune: true,
            anomaly_threshold: 0.7,
            learning_mode: false,
            enable_audit_logging: true,
            log_level: LogLevel::Info,
        }
    }
}

impl SecurityFramework {
    /// Create a new security framework instance
    pub async fn new(config: SecurityConfig) -> SecurityResult<Self> {
        Self::validate_config(&config)?;

        let mut framework = Self {
            config: config.clone(),
            input_validator: None,
            jwt_auth: Arc::new(JWTAuthenticator::new(
                std::env::var("JWT_SECRET").unwrap_or_else(|_| "default-secret".to_string()),
                config.jwt_expiry_seconds,
            )?),
            mfa_manager: None,
            rbac_manager: None,
            rate_limiter: None,
            crypto: None,
            audit_logger: None,
            ai_immune: None,
            metrics: Arc::new(RwLock::new(SecurityMetrics::default())),
        };

        framework.initialize_components().await?;
        
        info!("SMCP Security Framework initialized with config: {:?}", config);
        Ok(framework)
    }

    /// Validate an MCP request
    pub async fn validate_request(&self, request: &MCPRequest) -> SecurityResult<MCPRequest> {
        let start_time = std::time::Instant::now();
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_requests += 1;
        }

        let mut validated_request = request.clone();

        // Input validation
        if self.config.enable_input_validation {
            if let Some(validator) = &self.input_validator {
                let validation_result = validator.validate(request).await?;
                
                if !validation_result.is_valid {
                    let mut metrics = self.metrics.write().await;
                    metrics.blocked_requests += 1;
                    
                    return Err(SecurityError::validation(
                        "Request validation failed",
                        validation_result.errors,
                    ));
                }

                // Use sanitized data if available
                if let Some(sanitized) = validation_result.sanitized_data {
                    if let Ok(sanitized_request) = serde_json::from_value::<MCPRequest>(sanitized) {
                        validated_request = sanitized_request;
                    }
                }
            }
        }

        // AI immune system check
        if self.config.enable_ai_immune {
            if let Some(ai_immune) = &self.ai_immune {
                let threat_analysis = ai_immune.analyze_request(&validated_request).await?;
                
                if threat_analysis.risk_score > self.config.anomaly_threshold {
                    let mut metrics = self.metrics.write().await;
                    metrics.threats_detected += 1;
                    metrics.blocked_requests += 1;
                    metrics.last_threat_detected = Some(Utc::now());

                    // Log threat
                    if let Some(audit_logger) = &self.audit_logger {
                        audit_logger.log_threat(&threat_analysis, &validated_request).await?;
                    }

                    return Err(SecurityError::threat_detected(
                        format!("High-risk request detected: {}", threat_analysis.threat_type),
                        threat_analysis.risk_score,
                    ));
                }
            }
        }

        // Update response time metrics
        let processing_time = start_time.elapsed();
        self.update_average_response_time(processing_time.as_millis() as f64).await;

        Ok(validated_request)
    }

    /// Authenticate user credentials
    pub async fn authenticate_user(&self, credentials: &AuthCredentials) -> SecurityResult<String> {
        // Basic validation
        if credentials.username.is_empty() || credentials.password.is_empty() {
            let mut metrics = self.metrics.write().await;
            metrics.authentication_failures += 1;
            
            return Err(SecurityError::authentication("Username and password required"));
        }

        // Verify credentials (in real implementation, check against database)
        let is_valid = self.verify_credentials(credentials).await?;
        
        if !is_valid {
            let mut metrics = self.metrics.write().await;
            metrics.authentication_failures += 1;
            
            return Err(SecurityError::authentication("Invalid credentials"));
        }

        // MFA verification if enabled
        if self.config.enable_mfa {
            if let Some(mfa_manager) = &self.mfa_manager {
                if let Some(mfa_code) = &credentials.mfa_code {
                    let mfa_valid = mfa_manager.verify_token(&credentials.username, mfa_code).await?;
                    
                    if !mfa_valid {
                        let mut metrics = self.metrics.write().await;
                        metrics.authentication_failures += 1;
                        
                        return Err(SecurityError::authentication("Invalid MFA code"));
                    }
                } else {
                    return Err(SecurityError::authentication("MFA code required"));
                }
            }
        }

        // Generate JWT token
        let user_context = self.get_user_context(&credentials.username).await?;
        let token = self.jwt_auth.generate_token(&user_context).await?;

        // Log successful authentication
        if let Some(audit_logger) = &self.audit_logger {
            audit_logger.log_authentication(&credentials.username, true, credentials.mfa_code.is_some()).await?;
        }

        Ok(token)
    }

    /// Check if user is authorized for an action
    pub async fn authorize_action(&self, user_id: &str, action: &str) -> SecurityResult<bool> {
        if !self.config.enable_rbac {
            return Ok(true); // Authorization disabled
        }

        if let Some(rbac_manager) = &self.rbac_manager {
            let rbac = rbac_manager.read().await;
            let has_permission = rbac.has_permission(user_id, action).await?;
            
            // Log authorization attempt
            if let Some(audit_logger) = &self.audit_logger {
                audit_logger.log_authorization(user_id, action, has_permission).await?;
            }

            Ok(has_permission)
        } else {
            Ok(true)
        }
    }

    /// Process a secure request with full security checks
    pub async fn process_secure_request(
        &self,
        request: &MCPRequest,
        user_id: &str,
        session_token: &str,
    ) -> SecurityResult<serde_json::Value> {
        let start_time = std::time::Instant::now();

        // Validate JWT token
        let user_context = self.jwt_auth.verify_token(session_token).await?;
        
        if user_context.user_id != user_id {
            return Err(SecurityError::authentication("Token user mismatch"));
        }

        // Rate limiting check
        if self.config.enable_rate_limiting {
            if let Some(rate_limiter) = &self.rate_limiter {
                let allowed = rate_limiter.is_allowed(user_id).await?;
                
                if !allowed {
                    let mut metrics = self.metrics.write().await;
                    metrics.rate_limit_hits += 1;
                    
                    return Err(SecurityError::rate_limit("Rate limit exceeded", 60));
                }
            }
        }

        // Validate the request
        let validated_request = self.validate_request(request).await?;

        // Authorization check
        let action = &request.method;
        let is_authorized = self.authorize_action(user_id, action).await?;
        
        if !is_authorized {
            return Err(SecurityError::authorization(
                format!("Access denied for action: {}", action),
                Some(action.clone()),
            ));
        }

        // Process the request (placeholder implementation)
        let result = self.process_request(&validated_request, &user_context).await?;

        // Log successful request
        if let Some(audit_logger) = &self.audit_logger {
            let processing_time = start_time.elapsed();
            audit_logger.log_request(user_id, &validated_request, &result, processing_time).await?;
        }

        Ok(result)
    }

    /// Get current security metrics
    pub async fn get_security_metrics(&self) -> SecurityMetrics {
        self.metrics.read().await.clone()
    }

    // Private helper methods

    async fn initialize_components(&mut self) -> SecurityResult<()> {
        // Initialize input validator
        if self.config.enable_input_validation {
            self.input_validator = Some(Arc::new(InputValidator::new(self.config.validation_strictness)?));
        }

        // Initialize MFA manager
        if self.config.enable_mfa {
            self.mfa_manager = Some(Arc::new(MFAManager::new()?));
        }

        // Initialize RBAC manager
        if self.config.enable_rbac {
            let mut rbac = RBACManager::new();
            self.setup_default_roles(&mut rbac).await?;
            self.rbac_manager = Some(Arc::new(RwLock::new(rbac)));
        }

        // Initialize rate limiter
        if self.config.enable_rate_limiting {
            self.rate_limiter = Some(Arc::new(AdaptiveRateLimiter::new(RateLimitConfig {
                base_limit: self.config.default_rate_limit,
                burst_limit: Some(self.config.default_rate_limit * 2),
                window: std::time::Duration::from_secs(60),
                adaptive: self.config.adaptive_limits,
            }).await?));
        }

        // Initialize crypto
        if self.config.enable_encryption {
            self.crypto = Some(Arc::new(SMCPCrypto::new(CryptoConfig::default()).await?));
        }

        // Initialize audit logger
        if self.config.enable_audit_logging {
            self.audit_logger = Some(Arc::new(AuditLogger::new(self.config.log_level)?));
        }

        // Initialize AI immune system
        if self.config.enable_ai_immune {
            self.ai_immune = Some(Arc::new(AIImmuneSystem::new(AIImmuneConfig {
                anomaly_threshold: self.config.anomaly_threshold,
                learning_mode: self.config.learning_mode,
            }).await?));
        }

        Ok(())
    }

    async fn setup_default_roles(&self, rbac: &mut RBACManager) -> SecurityResult<()> {
        // Setup default roles
        rbac.add_role("admin", vec![
            "read".to_string(),
            "write".to_string(),
            "delete".to_string(),
            "admin".to_string(),
            "tools:*".to_string(),
            "resources:*".to_string(),
            "prompts:*".to_string(),
        ]).await?;

        rbac.add_role("user", vec![
            "read".to_string(),
            "tools:list".to_string(),
            "tools:call".to_string(),
            "resources:list".to_string(),
            "resources:read".to_string(),
            "prompts:list".to_string(),
            "prompts:get".to_string(),
        ]).await?;

        rbac.add_role("readonly", vec![
            "read".to_string(),
            "tools:list".to_string(),
            "resources:list".to_string(),
            "prompts:list".to_string(),
        ]).await?;

        Ok(())
    }

    fn validate_config(config: &SecurityConfig) -> SecurityResult<()> {
        if config.default_rate_limit == 0 {
            return Err(SecurityError::configuration("Rate limit must be positive"));
        }

        if !(0.0..=1.0).contains(&config.anomaly_threshold) {
            return Err(SecurityError::configuration(
                "Anomaly threshold must be between 0.0 and 1.0",
            ));
        }

        if config.jwt_expiry_seconds == 0 {
            return Err(SecurityError::configuration("JWT expiry must be positive"));
        }

        if config.session_timeout_seconds == 0 {
            return Err(SecurityError::configuration("Session timeout must be positive"));
        }

        Ok(())
    }

    async fn verify_credentials(&self, credentials: &AuthCredentials) -> SecurityResult<bool> {
        // In a real implementation, this would check against a database
        // For demo purposes, accept any non-empty credentials
        Ok(!credentials.username.is_empty() && !credentials.password.is_empty())
    }

    async fn get_user_context(&self, user_id: &str) -> SecurityResult<UserContext> {
        // In a real implementation, this would fetch from database
        Ok(UserContext {
            user_id: user_id.to_string(),
            username: user_id.to_string(),
            role: "user".to_string(),
            permissions: self.config.default_permissions.clone(),
            session_id: Uuid::new_v4().to_string(),
            last_activity: Utc::now(),
        })
    }

    async fn process_request(
        &self,
        request: &MCPRequest,
        user_context: &UserContext,
    ) -> SecurityResult<serde_json::Value> {
        // This is a placeholder - in a real implementation, this would
        // delegate to the actual MCP server implementation
        Ok(serde_json::json!({
            "jsonrpc": "2.0",
            "id": request.id,
            "result": {
                "message": "Request processed successfully",
                "method": request.method,
                "user": user_context.user_id
            }
        }))
    }

    async fn update_average_response_time(&self, new_time_ms: f64) {
        let mut metrics = self.metrics.write().await;
        let total_requests = metrics.total_requests as f64;
        let current_average = metrics.average_response_time;

        metrics.average_response_time = 
            ((current_average * (total_requests - 1.0)) + new_time_ms) / total_requests;
    }
}
