using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SMCP.Security.Authentication;
using SMCP.Security.Authorization;
using SMCP.Security.Cryptography;
using SMCP.Security.Exceptions;
using SMCP.Security.Models;
using SMCP.Security.RateLimit;
using SMCP.Security.Validation;
using SMCP.Security.Audit;
using SMCP.Security.AI;
using System.Collections.Concurrent;

namespace SMCP.Security;

/// <summary>
/// Main SMCP Security Framework that orchestrates all security components.
/// Provides comprehensive security for Model Context Protocol implementations
/// including input validation, authentication, authorization, rate limiting,
/// encryption, AI-based threat detection, and audit logging.
/// </summary>
public class SMCPSecurityFramework : ISMCPSecurityFramework
{
    private readonly SMCPSecurityOptions _options;
    private readonly ILogger<SMCPSecurityFramework> _logger;
    private readonly IInputValidator? _inputValidator;
    private readonly IJWTAuthenticator _jwtAuthenticator;
    private readonly IMFAManager? _mfaManager;
    private readonly IRBACManager? _rbacManager;
    private readonly IAdaptiveRateLimiter? _rateLimiter;
    private readonly ISMCPCrypto? _crypto;
    private readonly IAuditLogger? _auditLogger;
    private readonly IAIImmuneSystem? _aiImmune;
    
    // Metrics tracking
    private long _totalRequests = 0;
    private long _blockedRequests = 0;
    private long _threatsDetected = 0;
    private long _authenticationFailures = 0;
    private long _rateLimitHits = 0;
    private double _averageResponseTime = 0.0;
    private DateTime? _lastThreatDetected;
    private readonly object _metricsLock = new();
    
    /// <summary>
    /// Initializes a new instance of the SMCPSecurityFramework.
    /// </summary>
    /// <param name="options">Security configuration options</param>
    /// <param name="logger">Logger instance</param>
    /// <param name="inputValidator">Input validator (optional)</param>
    /// <param name="jwtAuthenticator">JWT authenticator</param>
    /// <param name="mfaManager">MFA manager (optional)</param>
    /// <param name="rbacManager">RBAC manager (optional)</param>
    /// <param name="rateLimiter">Rate limiter (optional)</param>
    /// <param name="crypto">Cryptography service (optional)</param>
    /// <param name="auditLogger">Audit logger (optional)</param>
    /// <param name="aiImmune">AI immune system (optional)</param>
    public SMCPSecurityFramework(
        IOptions<SMCPSecurityOptions> options,
        ILogger<SMCPSecurityFramework> logger,
        IInputValidator? inputValidator = null,
        IJWTAuthenticator? jwtAuthenticator = null,
        IMFAManager? mfaManager = null,
        IRBACManager? rbacManager = null,
        IAdaptiveRateLimiter? rateLimiter = null,
        ISMCPCrypto? crypto = null,
        IAuditLogger? auditLogger = null,
        IAIImmuneSystem? aiImmune = null)
    {
        _options = options.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        
        ValidateConfiguration(_options);
        
        // Initialize components based on configuration
        _inputValidator = _options.EnableInputValidation ? inputValidator : null;
        _jwtAuthenticator = jwtAuthenticator ?? throw new ArgumentNullException(nameof(jwtAuthenticator));
        _mfaManager = _options.EnableMFA ? mfaManager : null;
        _rbacManager = _options.EnableRBAC ? rbacManager : null;
        _rateLimiter = _options.EnableRateLimiting ? rateLimiter : null;
        _crypto = _options.EnableEncryption ? crypto : null;
        _auditLogger = _options.EnableAuditLogging ? auditLogger : null;
        _aiImmune = _options.EnableAIImmune ? aiImmune : null;
        
        // Setup default roles if RBAC is enabled
        if (_rbacManager != null)
        {
            SetupDefaultRoles();
        }
        
        _logger.LogInformation("SMCP Security Framework initialized with configuration: {@Options}", _options);
    }
    
    /// <summary>
    /// Parameterless constructor for basic usage.
    /// </summary>
    public SMCPSecurityFramework() : this(
        Options.Create(new SMCPSecurityOptions()),
        new LoggerFactory().CreateLogger<SMCPSecurityFramework>())
    {
    }
    
    /// <summary>
    /// Validates an MCP request against all configured security policies.
    /// </summary>
    /// <param name="request">The MCP request to validate</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The validated (and potentially sanitized) request</returns>
    /// <exception cref="ValidationException">Thrown when request validation fails</exception>
    /// <exception cref="ThreatDetectedException">Thrown when a security threat is detected</exception>
    public async Task<MCPRequest> ValidateRequestAsync(MCPRequest request, CancellationToken cancellationToken = default)
    {
        var startTime = DateTime.UtcNow;
        Interlocked.Increment(ref _totalRequests);
        
        try
        {
            _logger.LogDebug("Validating MCP request: {RequestId}", request.Id);
            
            // Input validation
            var validatedRequest = request;
            if (_inputValidator != null)
            {
                var validationResult = await _inputValidator.ValidateAsync(request, cancellationToken);
                
                if (!validationResult.IsValid)
                {
                    Interlocked.Increment(ref _blockedRequests);
                    
                    if (_auditLogger != null)
                    {
                        await _auditLogger.LogValidationFailureAsync(request, validationResult.Errors, cancellationToken);
                    }
                    
                    throw new ValidationException("Request validation failed", validationResult.Errors);
                }
                
                validatedRequest = validationResult.SanitizedRequest ?? request;
            }
            
            // AI immune system check
            if (_aiImmune != null)
            {
                var analysis = await _aiImmune.AnalyzeRequestAsync(validatedRequest, cancellationToken);
                
                if (analysis.RiskScore > _options.AnomalyThreshold)
                {
                    Interlocked.Increment(ref _threatsDetected);
                    Interlocked.Increment(ref _blockedRequests);
                    _lastThreatDetected = DateTime.UtcNow;
                    
                    if (_auditLogger != null)
                    {
                        await _auditLogger.LogThreatDetectionAsync(validatedRequest, analysis, cancellationToken);
                    }
                    
                    throw new ThreatDetectedException(
                        $"High-risk request detected: {analysis.ThreatType}",
                        analysis.RiskScore
                    );
                }
            }
            
            // Update metrics
            var processingTime = (DateTime.UtcNow - startTime).TotalMilliseconds;
            UpdateAverageResponseTime(processingTime);
            
            _logger.LogDebug("Request validation completed successfully: {RequestId}", request.Id);
            return validatedRequest;
        }
        catch (SecurityException ex)
        {
            if (_auditLogger != null)
            {
                await _auditLogger.LogSecurityEventAsync(request, ex, cancellationToken);
            }
            throw;
        }
    }
    
    /// <summary>
    /// Authenticates user credentials and returns a JWT token.
    /// </summary>
    /// <param name="credentials">User credentials</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>JWT token for authenticated user</returns>
    /// <exception cref="AuthenticationException">Thrown when authentication fails</exception>
    public async Task<string> AuthenticateUserAsync(AuthCredentials credentials, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogDebug("Authenticating user: {Username}", credentials.Username);
            
            // Basic credential validation
            if (string.IsNullOrWhiteSpace(credentials.Username) || string.IsNullOrWhiteSpace(credentials.Password))
            {
                Interlocked.Increment(ref _authenticationFailures);
                throw new AuthenticationException("Username and password are required");
            }
            
            // Verify credentials (in real implementation, check against database)
            if (!await VerifyCredentialsAsync(credentials, cancellationToken))
            {
                Interlocked.Increment(ref _authenticationFailures);
                
                if (_auditLogger != null)
                {
                    await _auditLogger.LogAuthenticationFailureAsync(credentials.Username, "Invalid credentials", cancellationToken);
                }
                
                throw new AuthenticationException("Invalid credentials");
            }
            
            // MFA verification if enabled
            if (_mfaManager != null && !string.IsNullOrEmpty(credentials.MfaCode))
            {
                var mfaValid = await _mfaManager.VerifyTokenAsync(credentials.Username, credentials.MfaCode, cancellationToken);
                
                if (!mfaValid)
                {
                    Interlocked.Increment(ref _authenticationFailures);
                    
                    if (_auditLogger != null)
                    {
                        await _auditLogger.LogAuthenticationFailureAsync(credentials.Username, "Invalid MFA code", cancellationToken);
                    }
                    
                    throw new AuthenticationException("Invalid MFA code");
                }
            }
            else if (_mfaManager != null)
            {
                throw new AuthenticationException("MFA code required");
            }
            
            // Generate JWT token
            var userContext = await GetUserContextAsync(credentials.Username, cancellationToken);
            var token = await _jwtAuthenticator.GenerateTokenAsync(userContext, cancellationToken);
            
            if (_auditLogger != null)
            {
                await _auditLogger.LogAuthenticationSuccessAsync(credentials.Username, !string.IsNullOrEmpty(credentials.MfaCode), cancellationToken);
            }
            
            _logger.LogDebug("User authenticated successfully: {Username}", credentials.Username);
            return token;
        }
        catch (AuthenticationException)
        {
            _logger.LogWarning("Authentication failed for user: {Username}", credentials.Username);
            throw;
        }
    }
    
    /// <summary>
    /// Checks if a user is authorized to perform a specific action.
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="action">Action to authorize</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if authorized, false otherwise</returns>
    /// <exception cref="AuthorizationException">Thrown when authorization check fails</exception>
    public async Task<bool> AuthorizeActionAsync(string userId, string action, CancellationToken cancellationToken = default)
    {
        if (_rbacManager == null)
        {
            return true; // Authorization disabled
        }
        
        try
        {
            var hasPermission = await _rbacManager.HasPermissionAsync(userId, action, cancellationToken);
            
            if (_auditLogger != null)
            {
                await _auditLogger.LogAuthorizationAttemptAsync(userId, action, hasPermission, cancellationToken);
            }
            
            return hasPermission;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Authorization check failed for user {UserId} and action {Action}", userId, action);
            throw new AuthorizationException("Authorization check failed", action);
        }
    }
    
    /// <summary>
    /// Processes a secure request with full security checks.
    /// </summary>
    /// <param name="request">MCP request</param>
    /// <param name="userId">User ID</param>
    /// <param name="sessionToken">JWT session token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Processed result</returns>
    /// <exception cref="SecurityException">Thrown when any security check fails</exception>
    public async Task<object> ProcessSecureRequestAsync(MCPRequest request, string userId, string sessionToken, CancellationToken cancellationToken = default)
    {
        var startTime = DateTime.UtcNow;
        
        try
        {
            _logger.LogDebug("Processing secure request: {RequestId} for user: {UserId}", request.Id, userId);
            
            // Validate JWT token
            var userContext = await _jwtAuthenticator.VerifyTokenAsync(sessionToken, cancellationToken);
            
            if (userContext.UserId != userId)
            {
                throw new AuthenticationException("Token user mismatch");
            }
            
            // Rate limiting check
            if (_rateLimiter != null)
            {
                if (!await _rateLimiter.IsAllowedAsync(userId, cancellationToken))
                {
                    Interlocked.Increment(ref _rateLimitHits);
                    
                    if (_auditLogger != null)
                    {
                        await _auditLogger.LogRateLimitExceededAsync(userId, request, cancellationToken);
                    }
                    
                    throw new RateLimitException($"Rate limit exceeded for user: {userId}");
                }
            }
            
            // Validate the request
            var validatedRequest = await ValidateRequestAsync(request, cancellationToken);
            
            // Authorization check
            var action = request.Method;
            if (!await AuthorizeActionAsync(userId, action, cancellationToken))
            {
                throw new AuthorizationException($"Access denied for action: {action}", action);
            }
            
            // Process the request (placeholder implementation)
            var result = await ProcessRequestAsync(validatedRequest, userContext, cancellationToken);
            
            // Log successful request
            if (_auditLogger != null)
            {
                var processingTime = (DateTime.UtcNow - startTime).TotalMilliseconds;
                await _auditLogger.LogRequestSuccessAsync(userId, validatedRequest, result, processingTime, cancellationToken);
            }
            
            _logger.LogDebug("Secure request processed successfully: {RequestId}", request.Id);
            return result;
        }
        catch (SecurityException ex)
        {
            if (_auditLogger != null)
            {
                var processingTime = (DateTime.UtcNow - startTime).TotalMilliseconds;
                await _auditLogger.LogRequestFailureAsync(userId, request, ex, processingTime, cancellationToken);
            }
            throw;
        }
    }
    
    /// <summary>
    /// Gets current security metrics.
    /// </summary>
    /// <returns>Security metrics</returns>
    public SecurityMetrics GetSecurityMetrics()
    {
        lock (_metricsLock)
        {
            return new SecurityMetrics
            {
                TotalRequests = _totalRequests,
                BlockedRequests = _blockedRequests,
                ThreatsDetected = _threatsDetected,
                AverageResponseTime = _averageResponseTime,
                ActiveUsers = 0, // Would be calculated from active sessions
                RateLimitHits = _rateLimitHits,
                AuthenticationFailures = _authenticationFailures,
                LastThreatDetected = _lastThreatDetected
            };
        }
    }
    
    // Private helper methods
    
    private static void ValidateConfiguration(SMCPSecurityOptions options)
    {
        if (options.DefaultRateLimit <= 0)
        {
            throw new SecurityConfigurationException("Rate limit must be positive");
        }
        
        if (options.AnomalyThreshold < 0.0 || options.AnomalyThreshold > 1.0)
        {
            throw new SecurityConfigurationException("Anomaly threshold must be between 0.0 and 1.0");
        }
        
        if (options.JwtExpirySeconds <= 0)
        {
            throw new SecurityConfigurationException("JWT expiry must be positive");
        }
    }
    
    private void SetupDefaultRoles()
    {
        if (_rbacManager == null) return;
        
        _rbacManager.AddRole("admin", new[]
        {
            "read", "write", "delete", "admin",
            "tools:*", "resources:*", "prompts:*"
        });
        
        _rbacManager.AddRole("user", new[]
        {
            "read", "tools:list", "tools:call",
            "resources:list", "resources:read",
            "prompts:list", "prompts:get"
        });
        
        _rbacManager.AddRole("readonly", new[]
        {
            "read", "tools:list", "resources:list", "prompts:list"
        });
    }
    
    private async Task<bool> VerifyCredentialsAsync(AuthCredentials credentials, CancellationToken cancellationToken)
    {
        // In a real implementation, this would check against a database
        // For demo purposes, accept any non-empty credentials
        await Task.Delay(10, cancellationToken); // Simulate async database call
        return !string.IsNullOrWhiteSpace(credentials.Username) && !string.IsNullOrWhiteSpace(credentials.Password);
    }
    
    private async Task<UserContext> GetUserContextAsync(string username, CancellationToken cancellationToken)
    {
        // In a real implementation, this would fetch from database
        await Task.Delay(10, cancellationToken); // Simulate async database call
        
        return new UserContext
        {
            UserId = username,
            Username = username,
            Role = "user",
            Permissions = _options.DefaultPermissions.ToList(),
            SessionId = Guid.NewGuid().ToString(),
            LastActivity = DateTime.UtcNow
        };
    }
    
    private async Task<object> ProcessRequestAsync(MCPRequest request, UserContext userContext, CancellationToken cancellationToken)
    {
        // This is a placeholder - in a real implementation, this would
        // delegate to the actual MCP server implementation
        await Task.Delay(10, cancellationToken); // Simulate processing
        
        return new MCPResponse
        {
            JsonRpc = "2.0",
            Id = request.Id,
            Result = new Dictionary<string, object>
            {
                ["message"] = "Request processed successfully",
                ["method"] = request.Method,
                ["user"] = userContext.UserId
            }
        };
    }
    
    private void UpdateAverageResponseTime(double newTime)
    {
        lock (_metricsLock)
        {
            var totalReqs = _totalRequests;
            if (totalReqs > 0)
            {
                _averageResponseTime = ((_averageResponseTime * (totalReqs - 1)) + newTime) / totalReqs;
            }
        }
    }
}
