# SMCP Security - .NET Library

[![NuGet Version](https://img.shields.io/nuget/v/SMCP.Security.svg)](https://www.nuget.org/packages/SMCP.Security/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/SMCP.Security.svg)](https://www.nuget.org/packages/SMCP.Security/)
[![.NET Version](https://img.shields.io/badge/.NET-6.0%2B-blue.svg)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/wizardscurtain/SMCPv1/workflows/.NET%20CI/badge.svg)](https://github.com/wizardscurtain/SMCPv1/actions)

Secure Model Context Protocol (SMCP) v1 - A production-ready security framework for Model Context Protocol implementations in .NET.

## Features

- 🔐 **Multi-layered Security**: Input validation, authentication, authorization, and encryption
- 🛡️ **AI-Immune System**: Machine learning-based threat detection and prevention
- 🚀 **High Performance**: Optimized for production workloads with minimal overhead
- 📊 **Comprehensive Auditing**: Detailed security event logging and monitoring
- 🔄 **Rate Limiting**: Adaptive rate limiting with DoS protection
- 🎯 **Easy Integration**: Dependency injection and middleware for ASP.NET Core
- 📝 **Type Safety**: Full C# type safety with nullable reference types
- ⚡ **Async/Await**: Built with async/await from the ground up

## Quick Start

### Installation

#### Package Manager Console

```powershell
Install-Package SMCP.Security
```

#### .NET CLI

```bash
dotnet add package SMCP.Security
```

#### PackageReference

```xml
<PackageReference Include="SMCP.Security" Version="1.0.0" />
```

### Basic Usage

```csharp
using SMCP.Security;
using SMCP.Security.Models;

class Program
{
    static async Task Main(string[] args)
    {
        // Initialize with default configuration
        var security = new SMCPSecurityFramework();
        
        // Example MCP request
        var request = new MCPRequest
        {
            JsonRpc = "2.0",
            Id = "req-123",
            Method = "tools/list",
            Params = null
        };
        
        try
        {
            // Validate the request
            var validatedRequest = await security.ValidateRequestAsync(request);
            
            // Process with security checks
            var result = await security.ProcessSecureRequestAsync(
                validatedRequest,
                "user-123",
                "jwt-token-here"
            );
            
            Console.WriteLine($"Request processed securely: {result}");
        }
        catch (SecurityException ex)
        {
            Console.WriteLine($"Security violation: {ex.Message}");
        }
    }
}
```

### ASP.NET Core Integration

```csharp
using SMCP.Security;
using SMCP.Security.Extensions;
using SMCP.Security.Middleware;

var builder = WebApplication.CreateBuilder(args);

// Add SMCP Security services
builder.Services.AddSMCPSecurity(options =>
{
    options.EnableMFA = true;
    options.ValidationStrictness = ValidationStrictness.Maximum;
    options.EnableAIImmune = true;
    options.AnomalyThreshold = 0.8;
    options.DefaultRateLimit = 100;
    options.EnableAuditLogging = true;
});

// Add controllers
builder.Services.AddControllers();

var app = builder.Build();

// Use SMCP Security middleware
app.UseSMCPSecurity();

app.MapControllers();

app.Run();
```

```csharp
[ApiController]
[Route("mcp")]
public class MCPController : ControllerBase
{
    private readonly ISMCPSecurityFramework _security;
    
    public MCPController(ISMCPSecurityFramework security)
    {
        _security = security;
    }
    
    [HttpPost("request")]
    [SMCPSecured]
    public async Task<IActionResult> HandleMCPRequest(
        [FromBody] MCPRequest request,
        [FromServices] IUserContextAccessor userContextAccessor)
    {
        // Request is automatically validated and secured
        var userContext = userContextAccessor.UserContext;
        var result = await ProcessMCPRequestAsync(request, userContext);
        return Ok(result);
    }
    
    [HttpPost("auth/login")]
    public async Task<IActionResult> Login([FromBody] AuthCredentials credentials)
    {
        try
        {
            var token = await _security.AuthenticateUserAsync(credentials);
            return Ok(new
            {
                access_token = token,
                token_type = "bearer"
            });
        }
        catch (AuthenticationException ex)
        {
            return Unauthorized(new { error = ex.Message });
        }
    }
}
```

### Configuration

#### appsettings.json

```json
{
  "SMCPSecurity": {
    "EnableInputValidation": true,
    "ValidationStrictness": "Maximum",
    "EnableMFA": true,
    "JwtExpirySeconds": 3600,
    "SessionTimeoutSeconds": 7200,
    "EnableRBAC": true,
    "DefaultPermissions": ["read"],
    "EnableRateLimiting": true,
    "DefaultRateLimit": 100,
    "AdaptiveLimits": true,
    "EnableEncryption": true,
    "KeyRotationInterval": 86400,
    "EnableAIImmune": true,
    "AnomalyThreshold": 0.8,
    "LearningMode": false,
    "EnableAuditLogging": true,
    "LogLevel": "Information"
  },
  "JWT": {
    "Secret": "your-secret-key",
    "Issuer": "your-app",
    "Audience": "your-audience",
    "Algorithm": "HS256"
  },
  "RateLimit": {
    "WindowMs": 60000,
    "BurstMultiplier": 2
  },
  "Audit": {
    "LogFile": "logs/smcp-audit.log",
    "MaxFileSize": "10MB",
    "MaxFiles": 5
  }
}
```

#### Programmatic Configuration

```csharp
builder.Services.Configure<SMCPSecurityOptions>(options =>
{
    options.EnableInputValidation = true;
    options.ValidationStrictness = ValidationStrictness.Maximum;
    options.EnableMFA = true;
    options.JwtExpirySeconds = 3600;
    options.SessionTimeoutSeconds = 7200;
    options.EnableRBAC = true;
    options.DefaultPermissions = new[] { "read" };
    options.EnableRateLimiting = true;
    options.DefaultRateLimit = 50;
    options.AdaptiveLimits = true;
    options.EnableEncryption = true;
    options.KeyRotationInterval = 86400;
    options.EnableAIImmune = true;
    options.AnomalyThreshold = 0.8;
    options.LearningMode = false;
    options.EnableAuditLogging = true;
    options.LogLevel = LogLevel.Information;
});
```

## Advanced Features

### AI-Immune System

```csharp
public class ThreatDetectionService
{
    private readonly IAIImmuneSystem _aiImmune;
    
    public ThreatDetectionService(IAIImmuneSystem aiImmune)
    {
        _aiImmune = aiImmune;
    }
    
    public async Task<bool> AnalyzeRequestAsync(MCPRequest request)
    {
        var analysis = await _aiImmune.AnalyzeRequestAsync(request);
        
        if (analysis.RiskScore > 0.7)
        {
            Console.WriteLine($"High-risk request detected: {analysis.ThreatType}");
            return false;
        }
        
        return true;
    }
    
    public async Task LearnFromAttackAsync(AttackData attackData)
    {
        await _aiImmune.LearnFromAttackAsync(attackData);
    }
}
```

### Rate Limiting

```csharp
public class RateLimitingService
{
    private readonly IAdaptiveRateLimiter _rateLimiter;
    
    public RateLimitingService(IAdaptiveRateLimiter rateLimiter)
    {
        _rateLimiter = rateLimiter;
    }
    
    public async Task<bool> CheckRateLimitAsync(string userId)
    {
        try
        {
            return await _rateLimiter.IsAllowedAsync(userId);
        }
        catch (RateLimitException)
        {
            return false;
        }
    }
    
    [RateLimit(Limit = 50, Window = "1m")]
    public async Task ProcessRequestAsync(string userId)
    {
        // Method is automatically rate limited
        await Task.Delay(100);
    }
}
```

### Cryptographic Operations

```csharp
public class CryptographyService
{
    private readonly ISMCPCrypto _crypto;
    
    public CryptographyService(ISMCPCrypto crypto)
    {
        _crypto = crypto;
    }
    
    public async Task<string> EncryptSensitiveDataAsync(string data)
    {
        try
        {
            return await _crypto.EncryptAsync(data);
        }
        catch (CryptographicException ex)
        {
            throw new SecurityException("Failed to encrypt data", ex);
        }
    }
    
    public async Task<string> DecryptSensitiveDataAsync(string encryptedData)
    {
        try
        {
            return await _crypto.DecryptAsync(encryptedData);
        }
        catch (CryptographicException ex)
        {
            throw new SecurityException("Failed to decrypt data", ex);
        }
    }
    
    public string GenerateSecureToken(int length = 32)
    {
        return _crypto.GenerateSecureToken(length);
    }
}
```

### Authentication & Authorization

```csharp
public class AuthenticationService
{
    private readonly IJWTAuthenticator _jwtAuth;
    private readonly IMFAManager _mfaManager;
    private readonly IRBACManager _rbacManager;
    
    public AuthenticationService(
        IJWTAuthenticator jwtAuth,
        IMFAManager mfaManager,
        IRBACManager rbacManager)
    {
        _jwtAuth = jwtAuth;
        _mfaManager = mfaManager;
        _rbacManager = rbacManager;
    }
    
    public async Task<string> AuthenticateUserAsync(AuthCredentials credentials)
    {
        // Verify credentials
        if (!await VerifyCredentialsAsync(credentials))
        {
            throw new AuthenticationException("Invalid credentials");
        }
        
        // MFA verification
        if (!string.IsNullOrEmpty(credentials.MfaCode))
        {
            var mfaValid = await _mfaManager.VerifyTokenAsync(
                credentials.Username,
                credentials.MfaCode
            );
            
            if (!mfaValid)
            {
                throw new AuthenticationException("Invalid MFA code");
            }
        }
        
        // Generate JWT token
        var userContext = await GetUserContextAsync(credentials.Username);
        return await _jwtAuth.GenerateTokenAsync(userContext);
    }
    
    [Authorize(Policy = "AdminOnly")]
    public async Task AdminOnlyMethodAsync()
    {
        // Method requires admin permission
        await Task.CompletedTask;
    }
}
```

### Custom Validation

```csharp
public class CustomMCPValidator : AbstractValidator<MCPRequest>
{
    public CustomMCPValidator()
    {
        RuleFor(x => x.Method)
            .NotEmpty()
            .Must(NotContainPathTraversal)
            .WithMessage("Path traversal attempt detected");
            
        RuleFor(x => x.Params)
            .Must(NotContainXSS)
            .WithMessage("XSS attempt detected")
            .When(x => x.Params != null);
    }
    
    private bool NotContainPathTraversal(string method)
    {
        return !method.Contains("../");
    }
    
    private bool NotContainXSS(object? parameters)
    {
        if (parameters == null) return true;
        
        var json = JsonSerializer.Serialize(parameters);
        return !json.Contains("<script>", StringComparison.OrdinalIgnoreCase);
    }
}
```

## API Reference

### Core Interfaces

#### ISMCPSecurityFramework

```csharp
public interface ISMCPSecurityFramework
{
    Task<MCPRequest> ValidateRequestAsync(MCPRequest request, CancellationToken cancellationToken = default);
    Task<string> AuthenticateUserAsync(AuthCredentials credentials, CancellationToken cancellationToken = default);
    Task<bool> AuthorizeActionAsync(string userId, string action, CancellationToken cancellationToken = default);
    Task<object> ProcessSecureRequestAsync(MCPRequest request, string userId, string sessionToken, CancellationToken cancellationToken = default);
    SecurityMetrics GetSecurityMetrics();
}
```

#### SMCPSecurityOptions

```csharp
public class SMCPSecurityOptions
{
    public bool EnableInputValidation { get; set; } = true;
    public ValidationStrictness ValidationStrictness { get; set; } = ValidationStrictness.Standard;
    public bool EnableMFA { get; set; } = true;
    public int JwtExpirySeconds { get; set; } = 3600;
    public int SessionTimeoutSeconds { get; set; } = 7200;
    public bool EnableRBAC { get; set; } = true;
    public string[] DefaultPermissions { get; set; } = { "read" };
    public bool EnableRateLimiting { get; set; } = true;
    public int DefaultRateLimit { get; set; } = 100;
    public bool AdaptiveLimits { get; set; } = true;
    public bool EnableEncryption { get; set; } = true;
    public int KeyRotationInterval { get; set; } = 86400;
    public bool EnableAIImmune { get; set; } = true;
    public double AnomalyThreshold { get; set; } = 0.7;
    public bool LearningMode { get; set; } = false;
    public bool EnableAuditLogging { get; set; } = true;
    public LogLevel LogLevel { get; set; } = LogLevel.Information;
}
```

### Attributes

#### SMCPSecuredAttribute

```csharp
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public class SMCPSecuredAttribute : Attribute
{
    public string[] Permissions { get; set; } = Array.Empty<string>();
    public bool RequireMFA { get; set; } = false;
    public int RateLimit { get; set; } = -1;
}
```

#### RateLimitAttribute

```csharp
[AttributeUsage(AttributeTargets.Method)]
public class RateLimitAttribute : Attribute
{
    public int Limit { get; set; }
    public string Window { get; set; } = "1m";
    public string Key { get; set; } = "";
}
```

### Extension Methods

```csharp
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSMCPSecurity(this IServiceCollection services);
    public static IServiceCollection AddSMCPSecurity(this IServiceCollection services, Action<SMCPSecurityOptions> configure);
    public static IServiceCollection AddSMCPSecurity(this IServiceCollection services, IConfiguration configuration);
}

public static class ApplicationBuilderExtensions
{
    public static IApplicationBuilder UseSMCPSecurity(this IApplicationBuilder app);
    public static IApplicationBuilder UseSMCPSecurity(this IApplicationBuilder app, SMCPSecurityOptions options);
}
```

## Examples

See the [examples](https://github.com/wizardscurtain/SMCPv1/tree/main/examples/csharp) directory for complete implementation examples:

- [Basic Usage](examples/BasicUsage/Program.cs)
- [ASP.NET Core Web API](examples/WebApi/Program.cs)
- [Minimal APIs](examples/MinimalApi/Program.cs)
- [Blazor Server](examples/BlazorServer/Program.cs)
- [Custom Security Policies](examples/CustomPolicies/Program.cs)
- [AI Immune System](examples/AIImmune/Program.cs)
- [Microservices Architecture](examples/Microservices/)

## Testing

```bash
# Run tests
dotnet test

# Run with coverage
dotnet test --collect:"XPlat Code Coverage"

# Run specific test
dotnet test --filter "FullyQualifiedName~SMCPSecurityFrameworkTests"

# Run performance tests
dotnet test --filter "Category=Performance"
```

## Performance

- **Minimal Overhead**: < 2ms latency impact
- **High Throughput**: Handles 30,000+ requests/second
- **Memory Efficient**: < 15MB memory footprint
- **Async/Await**: Full async support for non-blocking operations
- **Scalable**: Horizontal scaling support with distributed caching

## Security Features

### Input Validation
- Command injection prevention
- SQL injection protection
- XSS prevention
- Path traversal protection
- Schema validation with FluentValidation
- Content sanitization

### Authentication & Authorization
- JWT token management
- Multi-factor authentication (MFA)
- Role-based access control (RBAC)
- Session management
- Token refresh and rotation
- ASP.NET Core Identity integration

### Threat Detection
- Real-time anomaly detection
- Machine learning-based threat classification
- Behavioral analysis
- Attack pattern recognition
- Adaptive defense mechanisms

### Audit & Monitoring
- Comprehensive security event logging
- Real-time monitoring with Application Insights
- Compliance reporting
- Performance metrics
- Security analytics
- Integration with .NET logging providers

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## Security

For security issues, please email security@smcp.dev instead of using the issue tracker.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📖 [Documentation](https://github.com/wizardscurtain/SMCPv1/tree/main/libraries/csharp)
- 💬 [Discussions](https://github.com/wizardscurtain/SMCPv1/discussions)
- 🐛 [Issues](https://github.com/wizardscurtain/SMCPv1/issues)
- 📧 [Email Support](mailto:support@smcp.dev)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.
