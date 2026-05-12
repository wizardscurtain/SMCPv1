package com.smcp.security;

import com.smcp.security.auth.JWTAuthenticator;
import com.smcp.security.auth.MFAManager;
import com.smcp.security.auth.RBACManager;
import com.smcp.security.audit.AuditLogger;
import com.smcp.security.crypto.SMCPCrypto;
import com.smcp.security.exception.*;
import com.smcp.security.model.*;
import com.smcp.security.ratelimit.AdaptiveRateLimiter;
import com.smcp.security.validation.InputValidator;
import com.smcp.security.ai.AIImmuneSystem;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Main SMCP Security Framework that orchestrates all security components.
 * 
 * This class provides a comprehensive security framework for Model Context Protocol
 * implementations, including input validation, authentication, authorization,
 * rate limiting, encryption, AI-based threat detection, and audit logging.
 * 
 * @author SMCP Security Team
 * @version 1.0.0
 * @since 1.0.0
 */
public class SMCPSecurityFramework {
    
    private static final Logger logger = LoggerFactory.getLogger(SMCPSecurityFramework.class);
    
    private final SecurityConfig config;
    private final InputValidator inputValidator;
    private final JWTAuthenticator jwtAuthenticator;
    private final MFAManager mfaManager;
    private final RBACManager rbacManager;
    private final AdaptiveRateLimiter rateLimiter;
    private final SMCPCrypto crypto;
    private final AuditLogger auditLogger;
    private final AIImmuneSystem aiImmune;
    private final SecurityMetrics metrics;
    
    // Metrics tracking
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong blockedRequests = new AtomicLong(0);
    private final AtomicLong threatsDetected = new AtomicLong(0);
    private final AtomicLong authenticationFailures = new AtomicLong(0);
    private final AtomicLong rateLimitHits = new AtomicLong(0);
    private volatile double averageResponseTime = 0.0;
    private volatile Instant lastThreatDetected;
    
    /**
     * Creates a new SMCP Security Framework with default configuration.
     */
    public SMCPSecurityFramework() {
        this(SecurityConfig.defaultConfig());
    }
    
    /**
     * Creates a new SMCP Security Framework with the specified configuration.
     * 
     * @param config the security configuration
     * @throws SecurityConfigurationException if the configuration is invalid
     */
    public SMCPSecurityFramework(SecurityConfig config) {
        this.config = validateConfig(config);
        this.metrics = new SecurityMetrics();
        
        // Initialize components based on configuration
        this.inputValidator = config.isEnableInputValidation() ? 
            new InputValidator(config.getValidationStrictness()) : null;
            
        this.jwtAuthenticator = new JWTAuthenticator(
            config.getJwtSecret(),
            config.getJwtExpirySeconds()
        );
        
        this.mfaManager = config.isEnableMFA() ? new MFAManager() : null;
        
        this.rbacManager = config.isEnableRBAC() ? new RBACManager() : null;
        if (this.rbacManager != null) {
            setupDefaultRoles();
        }
        
        this.rateLimiter = config.isEnableRateLimiting() ? 
            new AdaptiveRateLimiter(config.getDefaultRateLimit(), config.isAdaptiveLimits()) : null;
            
        this.crypto = config.isEnableEncryption() ? new SMCPCrypto() : null;
        
        this.auditLogger = config.isEnableAuditLogging() ? 
            new AuditLogger(config.getLogLevel()) : null;
            
        this.aiImmune = config.isEnableAIImmune() ? 
            new AIImmuneSystem(config.getAnomalyThreshold(), config.isLearningMode()) : null;
        
        logger.info("SMCP Security Framework initialized with configuration: {}", config);
    }
    
    /**
     * Validates an MCP request against all configured security policies.
     * 
     * @param request the MCP request to validate
     * @return the validated (and potentially sanitized) request
     * @throws ValidationException if the request fails validation
     * @throws SecurityException if a security threat is detected
     */
    public MCPRequest validateRequest(MCPRequest request) throws SecurityException {
        long startTime = System.currentTimeMillis();
        totalRequests.incrementAndGet();
        
        try {
            logger.debug("Validating MCP request: {}", request.getId());
            
            // Input validation
            MCPRequest validatedRequest = request;
            if (inputValidator != null) {
                ValidationResult result = inputValidator.validate(request);
                
                if (!result.isValid()) {
                    blockedRequests.incrementAndGet();
                    
                    if (auditLogger != null) {
                        auditLogger.logValidationFailure(request, result.getErrors());
                    }
                    
                    throw new ValidationException("Request validation failed", result.getErrors());
                }
                
                validatedRequest = result.getSanitizedRequest();
            }
            
            // AI immune system check
            if (aiImmune != null) {
                ThreatAnalysis analysis = aiImmune.analyzeRequest(validatedRequest);
                
                if (analysis.getRiskScore() > config.getAnomalyThreshold()) {
                    threatsDetected.incrementAndGet();
                    blockedRequests.incrementAndGet();
                    lastThreatDetected = Instant.now();
                    
                    if (auditLogger != null) {
                        auditLogger.logThreatDetection(validatedRequest, analysis);
                    }
                    
                    throw new ThreatDetectedException(
                        "High-risk request detected: " + analysis.getThreatType(),
                        analysis.getRiskScore()
                    );
                }
            }
            
            // Update metrics
            updateAverageResponseTime(System.currentTimeMillis() - startTime);
            
            logger.debug("Request validation completed successfully: {}", request.getId());
            return validatedRequest;
            
        } catch (SecurityException e) {
            if (auditLogger != null) {
                auditLogger.logSecurityEvent(request, e);
            }
            throw e;
        }
    }
    
    /**
     * Authenticates user credentials and returns a JWT token.
     * 
     * @param credentials the user credentials
     * @return JWT token for authenticated user
     * @throws AuthenticationException if authentication fails
     */
    public String authenticateUser(AuthCredentials credentials) throws AuthenticationException {
        try {
            logger.debug("Authenticating user: {}", credentials.getUsername());
            
            // Basic credential validation
            if (credentials.getUsername() == null || credentials.getUsername().trim().isEmpty() ||
                credentials.getPassword() == null || credentials.getPassword().trim().isEmpty()) {
                authenticationFailures.incrementAndGet();
                throw new AuthenticationException("Username and password are required");
            }
            
            // Verify credentials (in real implementation, check against database)
            if (!verifyCredentials(credentials)) {
                authenticationFailures.incrementAndGet();
                
                if (auditLogger != null) {
                    auditLogger.logAuthenticationFailure(credentials.getUsername(), "Invalid credentials");
                }
                
                throw new AuthenticationException("Invalid credentials");
            }
            
            // MFA verification if enabled
            if (mfaManager != null && credentials.getMfaCode() != null) {
                boolean mfaValid = mfaManager.verifyToken(credentials.getUsername(), credentials.getMfaCode());
                
                if (!mfaValid) {
                    authenticationFailures.incrementAndGet();
                    
                    if (auditLogger != null) {
                        auditLogger.logAuthenticationFailure(credentials.getUsername(), "Invalid MFA code");
                    }
                    
                    throw new AuthenticationException("Invalid MFA code");
                }
            } else if (mfaManager != null) {
                throw new AuthenticationException("MFA code required");
            }
            
            // Generate JWT token
            UserContext userContext = getUserContext(credentials.getUsername());
            String token = jwtAuthenticator.generateToken(userContext);
            
            if (auditLogger != null) {
                auditLogger.logAuthenticationSuccess(credentials.getUsername(), credentials.getMfaCode() != null);
            }
            
            logger.debug("User authenticated successfully: {}", credentials.getUsername());
            return token;
            
        } catch (AuthenticationException e) {
            logger.warn("Authentication failed for user: {}", credentials.getUsername());
            throw e;
        }
    }
    
    /**
     * Checks if a user is authorized to perform a specific action.
     * 
     * @param userId the user ID
     * @param action the action to authorize
     * @return true if authorized, false otherwise
     * @throws AuthorizationException if authorization check fails
     */
    public boolean authorizeAction(String userId, String action) throws AuthorizationException {
        if (rbacManager == null) {
            return true; // Authorization disabled
        }
        
        try {
            boolean hasPermission = rbacManager.hasPermission(userId, action);
            
            if (auditLogger != null) {
                auditLogger.logAuthorizationAttempt(userId, action, hasPermission);
            }
            
            return hasPermission;
            
        } catch (Exception e) {
            logger.error("Authorization check failed for user {} and action {}", userId, action, e);
            throw new AuthorizationException("Authorization check failed", action);
        }
    }
    
    /**
     * Processes a secure request with full security checks.
     * 
     * @param request the MCP request
     * @param userId the user ID
     * @param sessionToken the JWT session token
     * @return the processed result
     * @throws SecurityException if any security check fails
     */
    public Object processSecureRequest(MCPRequest request, String userId, String sessionToken) 
            throws SecurityException {
        long startTime = System.currentTimeMillis();
        
        try {
            logger.debug("Processing secure request: {} for user: {}", request.getId(), userId);
            
            // Validate JWT token
            UserContext userContext = jwtAuthenticator.verifyToken(sessionToken);
            
            if (!userContext.getUserId().equals(userId)) {
                throw new AuthenticationException("Token user mismatch");
            }
            
            // Rate limiting check
            if (rateLimiter != null) {
                if (!rateLimiter.isAllowed(userId)) {
                    rateLimitHits.incrementAndGet();
                    
                    if (auditLogger != null) {
                        auditLogger.logRateLimitExceeded(userId, request);
                    }
                    
                    throw new RateLimitException("Rate limit exceeded for user: " + userId);
                }
            }
            
            // Validate the request
            MCPRequest validatedRequest = validateRequest(request);
            
            // Authorization check
            String action = request.getMethod();
            if (!authorizeAction(userId, action)) {
                throw new AuthorizationException("Access denied for action: " + action, action);
            }
            
            // Process the request (placeholder implementation)
            Object result = processRequest(validatedRequest, userContext);
            
            // Log successful request
            if (auditLogger != null) {
                auditLogger.logRequestSuccess(userId, validatedRequest, result, 
                    System.currentTimeMillis() - startTime);
            }
            
            logger.debug("Secure request processed successfully: {}", request.getId());
            return result;
            
        } catch (SecurityException e) {
            if (auditLogger != null) {
                auditLogger.logRequestFailure(userId, request, e, 
                    System.currentTimeMillis() - startTime);
            }
            throw e;
        }
    }
    
    /**
     * Gets current security metrics.
     * 
     * @return security metrics
     */
    public SecurityMetrics getSecurityMetrics() {
        return SecurityMetrics.builder()
            .totalRequests(totalRequests.get())
            .blockedRequests(blockedRequests.get())
            .threatsDetected(threatsDetected.get())
            .averageResponseTime(averageResponseTime)
            .activeUsers(0L) // Would be calculated from active sessions
            .rateLimitHits(rateLimitHits.get())
            .authenticationFailures(authenticationFailures.get())
            .lastThreatDetected(lastThreatDetected)
            .build();
    }
    
    // Private helper methods
    
    private SecurityConfig validateConfig(SecurityConfig config) {
        if (config == null) {
            throw new SecurityConfigurationException("Security configuration cannot be null");
        }
        
        if (config.getDefaultRateLimit() <= 0) {
            throw new SecurityConfigurationException("Rate limit must be positive");
        }
        
        if (config.getAnomalyThreshold() < 0.0 || config.getAnomalyThreshold() > 1.0) {
            throw new SecurityConfigurationException("Anomaly threshold must be between 0.0 and 1.0");
        }
        
        if (config.getJwtExpirySeconds() <= 0) {
            throw new SecurityConfigurationException("JWT expiry must be positive");
        }
        
        return config;
    }
    
    private void setupDefaultRoles() {
        if (rbacManager != null) {
            rbacManager.addRole("admin", java.util.List.of(
                "read", "write", "delete", "admin",
                "tools:*", "resources:*", "prompts:*"
            ));
            
            rbacManager.addRole("user", java.util.List.of(
                "read", "tools:list", "tools:call",
                "resources:list", "resources:read",
                "prompts:list", "prompts:get"
            ));
            
            rbacManager.addRole("readonly", java.util.List.of(
                "read", "tools:list", "resources:list", "prompts:list"
            ));
        }
    }
    
    private boolean verifyCredentials(AuthCredentials credentials) {
        // In a real implementation, this would check against a database
        // For demo purposes, accept any non-empty credentials
        return credentials.getUsername() != null && !credentials.getUsername().trim().isEmpty() &&
               credentials.getPassword() != null && !credentials.getPassword().trim().isEmpty();
    }
    
    private UserContext getUserContext(String username) {
        // In a real implementation, this would fetch from database
        return UserContext.builder()
            .userId(username)
            .username(username)
            .role("user")
            .permissions(config.getDefaultPermissions())
            .sessionId(java.util.UUID.randomUUID().toString())
            .lastActivity(Instant.now())
            .build();
    }
    
    private Object processRequest(MCPRequest request, UserContext userContext) {
        // This is a placeholder - in a real implementation, this would
        // delegate to the actual MCP server implementation
        return MCPResponse.builder()
            .jsonrpc("2.0")
            .id(request.getId())
            .result(java.util.Map.of(
                "message", "Request processed successfully",
                "method", request.getMethod(),
                "user", userContext.getUserId()
            ))
            .build();
    }
    
    private void updateAverageResponseTime(long newTime) {
        long totalReqs = totalRequests.get();
        if (totalReqs > 0) {
            averageResponseTime = ((averageResponseTime * (totalReqs - 1)) + newTime) / totalReqs;
        }
    }
}
