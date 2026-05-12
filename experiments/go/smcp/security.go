// Package smcp provides a comprehensive security framework for Model Context Protocol implementations.
package smcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// SecurityFramework is the main security framework that orchestrates all security components.
type SecurityFramework struct {
	config         *SecurityConfig
	inputValidator *InputValidator
	jwtAuth        *JWTAuthenticator
	mfaManager     *MFAManager
	rbacManager    *RBACManager
	rateLimiter    *AdaptiveRateLimiter
	crypto         *Crypto
	auditLogger    *AuditLogger
	aiImmune       *AIImmuneSystem
	metrics        *SecurityMetrics
	logger         *logrus.Logger
}

// SecurityConfig holds the configuration for the security framework.
type SecurityConfig struct {
	// Input validation settings
	EnableInputValidation bool
	ValidationStrictness  ValidationStrictness

	// Authentication settings
	EnableMFA             bool
	JWTExpirySeconds      int
	SessionTimeoutSeconds int

	// Authorization settings
	EnableRBAC         bool
	DefaultPermissions []string

	// Rate limiting settings
	EnableRateLimiting bool
	DefaultRateLimit   int
	AdaptiveLimits     bool

	// Cryptographic settings
	EnableEncryption    bool
	KeyRotationInterval int

	// AI immune system settings
	EnableAIImmune   bool
	AnomalyThreshold float64
	LearningMode     bool

	// Audit settings
	EnableAuditLogging bool
	LogLevel           LogLevel
}

// ValidationStrictness defines the level of input validation.
type ValidationStrictness int

const (
	ValidationMinimal ValidationStrictness = iota
	ValidationStandard
	ValidationMaximum
)

// LogLevel defines the logging level.
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarning
	LogLevelError
	LogLevelCritical
)

// MCPRequest represents a Model Context Protocol request.
type MCPRequest struct {
	JSONRPC string                 `json:"jsonrpc"`
	ID      string                 `json:"id"`
	Method  string                 `json:"method"`
	Params  map[string]interface{} `json:"params,omitempty"`
}

// MCPResponse represents a Model Context Protocol response.
type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      string      `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

// MCPError represents an MCP error.
type MCPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// AuthCredentials represents user authentication credentials.
type AuthCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	MFACode  string `json:"mfa_code,omitempty"`
}

// UserContext represents authenticated user information.
type UserContext struct {
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	Permissions  []string  `json:"permissions"`
	SessionID    string    `json:"session_id"`
	LastActivity time.Time `json:"last_activity"`
}

// SecurityMetrics holds security-related metrics.
type SecurityMetrics struct {
	TotalRequests          int64     `json:"total_requests"`
	BlockedRequests        int64     `json:"blocked_requests"`
	ThreatsDetected        int64     `json:"threats_detected"`
	AverageResponseTime    float64   `json:"average_response_time"`
	ActiveUsers            int64     `json:"active_users"`
	RateLimitHits          int64     `json:"rate_limit_hits"`
	AuthenticationFailures int64     `json:"authentication_failures"`
	LastThreatDetected     time.Time `json:"last_threat_detected,omitempty"`
}

// SecureRequestOptions holds options for processing a secure request.
type SecureRequestOptions struct {
	Request      *MCPRequest `json:"request"`
	UserID       string      `json:"user_id"`
	SessionToken string      `json:"session_token"`
	ClientIP     string      `json:"client_ip,omitempty"`
	UserAgent    string      `json:"user_agent,omitempty"`
}

// NewSecurityFramework creates a new security framework instance.
func NewSecurityFramework(config *SecurityConfig) (*SecurityFramework, error) {
	if config == nil {
		config = DefaultSecurityConfig()
	}

	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	sf := &SecurityFramework{
		config:  config,
		metrics: &SecurityMetrics{},
		logger:  logrus.New(),
	}

	if err := sf.initializeComponents(); err != nil {
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}

	return sf, nil
}

// DefaultSecurityConfig returns a default security configuration.
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		EnableInputValidation: true,
		ValidationStrictness:  ValidationStandard,
		EnableMFA:             true,
		JWTExpirySeconds:      3600,
		SessionTimeoutSeconds: 7200,
		EnableRBAC:            true,
		DefaultPermissions:    []string{"read"},
		EnableRateLimiting:    true,
		DefaultRateLimit:      100,
		AdaptiveLimits:        true,
		EnableEncryption:      true,
		KeyRotationInterval:   86400,
		EnableAIImmune:        true,
		AnomalyThreshold:      0.7,
		LearningMode:          false,
		EnableAuditLogging:    true,
		LogLevel:              LogLevelInfo,
	}
}

// ValidateRequest validates an MCP request.
func (sf *SecurityFramework) ValidateRequest(ctx context.Context, request *MCPRequest) (*MCPRequest, error) {
	startTime := time.Now()
	sf.metrics.TotalRequests++

	// Input validation
	if sf.config.EnableInputValidation && sf.inputValidator != nil {
		validationResult, err := sf.inputValidator.Validate(ctx, request)
		if err != nil {
			sf.metrics.BlockedRequests++
			return nil, fmt.Errorf("validation failed: %w", err)
		}

		if !validationResult.IsValid {
			sf.metrics.BlockedRequests++
			return nil, &ValidationError{
				Message: "Request validation failed",
				Errors:  validationResult.Errors,
			}
		}

		// Use sanitized data if available
		if validationResult.SanitizedData != nil {
			request = validationResult.SanitizedData.(*MCPRequest)
		}
	}

	// AI immune system check
	if sf.config.EnableAIImmune && sf.aiImmune != nil {
		threatAnalysis, err := sf.aiImmune.AnalyzeRequest(ctx, request)
		if err != nil {
			sf.logger.WithError(err).Warn("AI immune system analysis failed")
		} else if threatAnalysis.RiskScore > sf.config.AnomalyThreshold {
			sf.metrics.ThreatsDetected++
			sf.metrics.BlockedRequests++
			sf.metrics.LastThreatDetected = time.Now()

			if sf.auditLogger != nil {
				sf.auditLogger.LogThreat(ctx, &ThreatEvent{
					Request:        request,
					ThreatAnalysis: threatAnalysis,
					Action:         "blocked",
					Timestamp:      time.Now(),
				})
			}

			return nil, &SecurityError{
				Message: fmt.Sprintf("High-risk request detected: %s", threatAnalysis.ThreatType),
				Code:    "THREAT_DETECTED",
			}
		}
	}

	// Update metrics
	processingTime := time.Since(startTime)
	sf.updateAverageResponseTime(processingTime)

	return request, nil
}

// AuthenticateUser authenticates user credentials and returns a JWT token.
func (sf *SecurityFramework) AuthenticateUser(ctx context.Context, credentials *AuthCredentials) (string, error) {
	// Basic credential validation
	if credentials.Username == "" || credentials.Password == "" {
		sf.metrics.AuthenticationFailures++
		return "", &AuthenticationError{Message: "Username and password required"}
	}

	// Verify credentials (in a real implementation, this would check against a database)
	isValid, err := sf.verifyCredentials(ctx, credentials)
	if err != nil {
		return "", fmt.Errorf("credential verification failed: %w", err)
	}

	if !isValid {
		sf.metrics.AuthenticationFailures++
		return "", &AuthenticationError{Message: "Invalid credentials"}
	}

	// MFA verification if enabled
	if sf.config.EnableMFA && sf.mfaManager != nil {
		if credentials.MFACode == "" {
			return "", &AuthenticationError{Message: "MFA code required"}
		}

		mfaValid := sf.mfaManager.VerifyToken(credentials.Username, credentials.MFACode)
		if !mfaValid {
			sf.metrics.AuthenticationFailures++
			return "", &AuthenticationError{Message: "Invalid MFA code"}
		}
	}

	// Generate JWT token
	userContext, err := sf.getUserContext(ctx, credentials.Username)
	if err != nil {
		return "", fmt.Errorf("failed to get user context: %w", err)
	}

	token, err := sf.jwtAuth.GenerateToken(userContext)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	// Log successful authentication
	if sf.auditLogger != nil {
		sf.auditLogger.LogAuthentication(ctx, &AuthEvent{
			UserID:    credentials.Username,
			Success:   true,
			MFAUsed:   credentials.MFACode != "",
			Timestamp: time.Now(),
		})
	}

	return token, nil
}

// AuthorizeAction checks if a user is authorized to perform an action.
func (sf *SecurityFramework) AuthorizeAction(ctx context.Context, userID, action string) (bool, error) {
	if !sf.config.EnableRBAC || sf.rbacManager == nil {
		return true, nil // Authorization disabled
	}

	hasPermission := sf.rbacManager.HasPermission(userID, action)

	// Log authorization attempt
	if sf.auditLogger != nil {
		sf.auditLogger.LogAuthorization(ctx, &AuthzEvent{
			UserID:    userID,
			Action:    action,
			Granted:   hasPermission,
			Timestamp: time.Now(),
		})
	}

	return hasPermission, nil
}

// ProcessSecureRequest processes a request with full security checks.
func (sf *SecurityFramework) ProcessSecureRequest(ctx context.Context, options *SecureRequestOptions) (interface{}, error) {
	startTime := time.Now()

	// Validate JWT token
	userContext, err := sf.jwtAuth.VerifyToken(options.SessionToken)
	if err != nil {
		return nil, &AuthenticationError{Message: "Invalid or expired token"}
	}

	if userContext.UserID != options.UserID {
		return nil, &AuthenticationError{Message: "Token user mismatch"}
	}

	// Rate limiting check
	if sf.config.EnableRateLimiting && sf.rateLimiter != nil {
		allowed, err := sf.rateLimiter.IsAllowed(ctx, options.UserID)
		if err != nil {
			return nil, fmt.Errorf("rate limit check failed: %w", err)
		}

		if !allowed {
			sf.metrics.RateLimitHits++
			return nil, &RateLimitError{Message: "Rate limit exceeded"}
		}
	}

	// Validate the request
	validatedRequest, err := sf.ValidateRequest(ctx, options.Request)
	if err != nil {
		return nil, err
	}

	// Authorization check
	action := options.Request.Method
	isAuthorized, err := sf.AuthorizeAction(ctx, options.UserID, action)
	if err != nil {
		return nil, fmt.Errorf("authorization check failed: %w", err)
	}

	if !isAuthorized {
		return nil, &AuthorizationError{
			Message:            fmt.Sprintf("Access denied for action: %s", action),
			RequiredPermission: action,
		}
	}

	// Process the request (this would be implemented by the MCP server)
	result := sf.processRequest(ctx, validatedRequest, userContext)

	// Log successful request
	if sf.auditLogger != nil {
		sf.auditLogger.LogRequest(ctx, &RequestEvent{
			UserID:         options.UserID,
			Request:        validatedRequest,
			Result:         result,
			ProcessingTime: time.Since(startTime),
			ClientIP:       options.ClientIP,
			UserAgent:      options.UserAgent,
			Timestamp:      time.Now(),
		})
	}

	return result, nil
}

// GetSecurityMetrics returns current security metrics.
func (sf *SecurityFramework) GetSecurityMetrics() *SecurityMetrics {
	return &SecurityMetrics{
		TotalRequests:          sf.metrics.TotalRequests,
		BlockedRequests:        sf.metrics.BlockedRequests,
		ThreatsDetected:        sf.metrics.ThreatsDetected,
		AverageResponseTime:    sf.metrics.AverageResponseTime,
		ActiveUsers:            sf.metrics.ActiveUsers,
		RateLimitHits:          sf.metrics.RateLimitHits,
		AuthenticationFailures: sf.metrics.AuthenticationFailures,
		LastThreatDetected:     sf.metrics.LastThreatDetected,
	}
}

// Helper methods

func (sf *SecurityFramework) initializeComponents() error {
	// Initialize input validator
	if sf.config.EnableInputValidation {
		sf.inputValidator = NewInputValidator(&InputValidatorConfig{
			Strictness: sf.config.ValidationStrictness,
		})
	}

	// Initialize JWT authenticator
	sf.jwtAuth = NewJWTAuthenticator(&JWTConfig{
		Secret:    getJWTSecret(),
		ExpiresIn: sf.config.JWTExpirySeconds,
	})

	// Initialize MFA manager
	if sf.config.EnableMFA {
		sf.mfaManager = NewMFAManager()
	}

	// Initialize RBAC manager
	if sf.config.EnableRBAC {
		sf.rbacManager = NewRBACManager()
		sf.setupDefaultRoles()
	}

	// Initialize rate limiter
	if sf.config.EnableRateLimiting {
		sf.rateLimiter = NewAdaptiveRateLimiter(&RateLimitConfig{
			BaseLimit:  sf.config.DefaultRateLimit,
			WindowMs:   60000, // 1 minute
			Adaptive:   sf.config.AdaptiveLimits,
		})
	}

	// Initialize crypto
	if sf.config.EnableEncryption {
		sf.crypto = NewCrypto(&CryptoConfig{
			Algorithm: "AES-256-GCM",
			KeySize:   32,
		})
	}

	// Initialize audit logger
	if sf.config.EnableAuditLogging {
		sf.auditLogger = NewAuditLogger(&AuditConfig{
			LogLevel: sf.config.LogLevel,
		})
	}

	// Initialize AI immune system
	if sf.config.EnableAIImmune {
		sf.aiImmune = NewAIImmuneSystem(&AIImmuneConfig{
			AnomalyThreshold: sf.config.AnomalyThreshold,
			LearningMode:     sf.config.LearningMode,
		})
	}

	return nil
}

func (sf *SecurityFramework) setupDefaultRoles() {
	if sf.rbacManager == nil {
		return
	}

	// Setup default roles
	sf.rbacManager.AddRole("admin", []string{
		"read", "write", "delete", "admin",
		"tools:*", "resources:*", "prompts:*",
	})

	sf.rbacManager.AddRole("user", []string{
		"read", "tools:list", "tools:call",
		"resources:list", "resources:read",
		"prompts:list", "prompts:get",
	})

	sf.rbacManager.AddRole("readonly", []string{
		"read", "tools:list", "resources:list", "prompts:list",
	})
}

func (sf *SecurityFramework) verifyCredentials(ctx context.Context, credentials *AuthCredentials) (bool, error) {
	// In a real implementation, this would check against a database
	// For demo purposes, accept any non-empty credentials
	return len(credentials.Username) > 0 && len(credentials.Password) > 0, nil
}

func (sf *SecurityFramework) getUserContext(ctx context.Context, userID string) (*UserContext, error) {
	// In a real implementation, this would fetch from database
	return &UserContext{
		UserID:       userID,
		Username:     userID,
		Role:         "user",
		Permissions:  sf.config.DefaultPermissions,
		SessionID:    generateSessionID(),
		LastActivity: time.Now(),
	}, nil
}

func (sf *SecurityFramework) processRequest(ctx context.Context, request *MCPRequest, userContext *UserContext) interface{} {
	// This is a placeholder - in a real implementation, this would
	// delegate to the actual MCP server implementation
	return &MCPResponse{
		JSONRPC: "2.0",
		ID:      request.ID,
		Result: map[string]interface{}{
			"message": "Request processed successfully",
			"method":  request.Method,
			"user":    userContext.UserID,
		},
	}
}

func (sf *SecurityFramework) updateAverageResponseTime(newTime time.Duration) {
	totalRequests := sf.metrics.TotalRequests
	currentAverage := sf.metrics.AverageResponseTime
	newTimeMs := float64(newTime.Nanoseconds()) / 1e6

	sf.metrics.AverageResponseTime = ((currentAverage * float64(totalRequests-1)) + newTimeMs) / float64(totalRequests)
}

func validateConfig(config *SecurityConfig) error {
	if config.DefaultRateLimit <= 0 {
		return fmt.Errorf("rate limit must be positive")
	}

	if config.AnomalyThreshold < 0.0 || config.AnomalyThreshold > 1.0 {
		return fmt.Errorf("anomaly threshold must be between 0.0 and 1.0")
	}

	if config.JWTExpirySeconds <= 0 {
		return fmt.Errorf("JWT expiry must be positive")
	}

	if config.SessionTimeoutSeconds <= 0 {
		return fmt.Errorf("session timeout must be positive")
	}

	return nil
}

func getJWTSecret() string {
	// In production, this should come from environment variables or secure storage
	return "your-secret-key"
}

func generateSessionID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
