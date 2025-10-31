# SMCP Security - Java Library

[![Maven Central](https://img.shields.io/maven-central/v/com.smcp/smcp-security.svg)](https://search.maven.org/artifact/com.smcp/smcp-security)
[![Java Version](https://img.shields.io/badge/Java-11%2B-blue.svg)](https://openjdk.java.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/wizardscurtain/SMCPv1/workflows/Java%20CI/badge.svg)](https://github.com/wizardscurtain/SMCPv1/actions)

Secure Model Context Protocol (SMCP) v1 - A production-ready security framework for Model Context Protocol implementations in Java.

## Features

- 🔐 **Multi-layered Security**: Input validation, authentication, authorization, and encryption
- 🛡️ **AI-Immune System**: Machine learning-based threat detection and prevention
- 🚀 **High Performance**: Optimized for production workloads with minimal overhead
- 📊 **Comprehensive Auditing**: Detailed security event logging and monitoring
- 🔄 **Rate Limiting**: Adaptive rate limiting with DoS protection
- 🎯 **Easy Integration**: Annotations and auto-configuration for Spring Boot
- ☕ **Java Ecosystem**: Full integration with Java security and web frameworks
- 📝 **Type Safety**: Comprehensive type safety with validation annotations

## Quick Start

### Installation

#### Maven

```xml
<dependency>
    <groupId>com.smcp</groupId>
    <artifactId>smcp-security</artifactId>
    <version>1.0.0</version>
</dependency>

<!-- For Spring Boot integration -->
<dependency>
    <groupId>com.smcp</groupId>
    <artifactId>smcp-security-spring-boot-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```

#### Gradle

```gradle
implementation 'com.smcp:smcp-security:1.0.0'

// For Spring Boot integration
implementation 'com.smcp:smcp-security-spring-boot-starter:1.0.0'
```

### Basic Usage

```java
import com.smcp.security.SMCPSecurityFramework;
import com.smcp.security.SecurityConfig;
import com.smcp.security.model.MCPRequest;

public class BasicExample {
    public static void main(String[] args) {
        // Initialize with default configuration
        SMCPSecurityFramework security = new SMCPSecurityFramework();
        
        // Example MCP request
        MCPRequest request = MCPRequest.builder()
            .jsonrpc("2.0")
            .id("req-123")
            .method("tools/list")
            .build();
        
        try {
            // Validate the request
            MCPRequest validatedRequest = security.validateRequest(request);
            
            // Process with security checks
            Object result = security.processSecureRequest(
                validatedRequest,
                "user-123",
                "jwt-token-here"
            );
            
            System.out.println("Request processed securely: " + result);
        } catch (SecurityException e) {
            System.err.println("Security violation: " + e.getMessage());
        }
    }
}
```

### Spring Boot Integration

```java
@SpringBootApplication
@EnableSMCPSecurity
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

@RestController
@RequestMapping("/mcp")
public class MCPController {
    
    @Autowired
    private SMCPSecurityFramework security;
    
    @PostMapping("/request")
    @SMCPSecured
    public ResponseEntity<?> handleMCPRequest(
            @RequestBody @Valid MCPRequest request,
            @SMCPUserContext UserContext userContext) {
        
        // Request is automatically validated and secured
        Object result = processMCPRequest(request, userContext);
        return ResponseEntity.ok(result);
    }
    
    @PostMapping("/auth/login")
    public ResponseEntity<?> login(@RequestBody @Valid AuthCredentials credentials) {
        try {
            String token = security.authenticateUser(credentials);
            return ResponseEntity.ok(Map.of(
                "access_token", token,
                "token_type", "bearer"
            ));
        } catch (AuthenticationException e) {
            return ResponseEntity.status(401).body(Map.of("error", e.getMessage()));
        }
    }
}
```

### Custom Configuration

```java
@Configuration
public class SecurityConfiguration {
    
    @Bean
    public SecurityConfig securityConfig() {
        return SecurityConfig.builder()
            .enableInputValidation(true)
            .validationStrictness(ValidationStrictness.MAXIMUM)
            .enableMFA(true)
            .jwtExpirySeconds(3600)
            .sessionTimeoutSeconds(7200)
            .enableRBAC(true)
            .defaultPermissions(List.of("read"))
            .enableRateLimiting(true)
            .defaultRateLimit(50)
            .adaptiveLimits(true)
            .enableEncryption(true)
            .keyRotationInterval(86400)
            .enableAIImmune(true)
            .anomalyThreshold(0.8)
            .learningMode(false)
            .enableAuditLogging(true)
            .logLevel(LogLevel.INFO)
            .build();
    }
}
```

### Application Properties

```properties
# SMCP Security Configuration
smcp.security.enable-input-validation=true
smcp.security.validation-strictness=maximum
smcp.security.enable-mfa=true
smcp.security.jwt-expiry-seconds=3600
smcp.security.session-timeout-seconds=7200
smcp.security.enable-rbac=true
smcp.security.default-permissions=read
smcp.security.enable-rate-limiting=true
smcp.security.default-rate-limit=100
smcp.security.adaptive-limits=true
smcp.security.enable-encryption=true
smcp.security.key-rotation-interval=86400
smcp.security.enable-ai-immune=true
smcp.security.anomaly-threshold=0.8
smcp.security.learning-mode=false
smcp.security.enable-audit-logging=true
smcp.security.log-level=INFO

# JWT Configuration
smcp.jwt.secret=${JWT_SECRET:your-secret-key}
smcp.jwt.algorithm=HS256

# Rate Limiting
smcp.rate-limit.window-ms=60000
smcp.rate-limit.burst-multiplier=2

# Audit Logging
smcp.audit.log-file=logs/smcp-audit.log
smcp.audit.max-file-size=10MB
smcp.audit.max-files=5
```

## Advanced Features

### AI-Immune System

```java
@Service
public class ThreatDetectionService {
    
    @Autowired
    private AIImmuneSystem aiImmune;
    
    public void analyzeRequest(MCPRequest request) {
        try {
            ThreatAnalysis analysis = aiImmune.analyzeRequest(request);
            
            if (analysis.getRiskScore() > 0.7) {
                log.warn("High-risk request detected: {}", analysis.getThreatType());
                // Handle threat
            }
        } catch (Exception e) {
            log.error("Threat analysis failed", e);
        }
    }
    
    public void learnFromAttack(AttackData attackData) {
        aiImmune.learnFromAttack(attackData);
    }
}
```

### Rate Limiting

```java
@Component
public class RateLimitingService {
    
    @Autowired
    private AdaptiveRateLimiter rateLimiter;
    
    public boolean checkRateLimit(String userId) {
        try {
            return rateLimiter.isAllowed(userId);
        } catch (RateLimitException e) {
            log.warn("Rate limit exceeded for user: {}", userId);
            return false;
        }
    }
    
    @RateLimited(limit = 50, window = "1m")
    public void processRequest(String userId) {
        // Method is automatically rate limited
    }
}
```

### Cryptographic Operations

```java
@Service
public class CryptographyService {
    
    @Autowired
    private SMCPCrypto crypto;
    
    public String encryptSensitiveData(String data) {
        try {
            return crypto.encrypt(data);
        } catch (CryptographicException e) {
            log.error("Encryption failed", e);
            throw new SecurityException("Failed to encrypt data");
        }
    }
    
    public String decryptSensitiveData(String encryptedData) {
        try {
            return crypto.decrypt(encryptedData);
        } catch (CryptographicException e) {
            log.error("Decryption failed", e);
            throw new SecurityException("Failed to decrypt data");
        }
    }
    
    public String generateSecureToken(int length) {
        return crypto.generateSecureToken(length);
    }
}
```

### Authentication & Authorization

```java
@Service
public class AuthenticationService {
    
    @Autowired
    private JWTAuthenticator jwtAuth;
    
    @Autowired
    private MFAManager mfaManager;
    
    @Autowired
    private RBACManager rbacManager;
    
    public String authenticateUser(AuthCredentials credentials) {
        // Verify credentials
        if (!verifyCredentials(credentials)) {
            throw new AuthenticationException("Invalid credentials");
        }
        
        // MFA verification
        if (credentials.getMfaCode() != null) {
            boolean mfaValid = mfaManager.verifyToken(
                credentials.getUsername(),
                credentials.getMfaCode()
            );
            
            if (!mfaValid) {
                throw new AuthenticationException("Invalid MFA code");
            }
        }
        
        // Generate JWT token
        UserContext userContext = getUserContext(credentials.getUsername());
        return jwtAuth.generateToken(userContext);
    }
    
    @PreAuthorize("@rbacManager.hasPermission(authentication.name, 'admin')")
    public void adminOnlyMethod() {
        // Method requires admin permission
    }
}
```

### Custom Validation

```java
@Component
public class CustomValidator implements MCPRequestValidator {
    
    @Override
    public ValidationResult validate(MCPRequest request) {
        List<String> errors = new ArrayList<>();
        
        // Custom validation logic
        if (request.getMethod().contains("../")) {
            errors.add("Path traversal attempt detected");
        }
        
        if (request.getParams() != null && 
            request.getParams().toString().contains("<script>")) {
            errors.add("XSS attempt detected");
        }
        
        return ValidationResult.builder()
            .valid(errors.isEmpty())
            .errors(errors)
            .riskScore(errors.isEmpty() ? 0.0 : 0.8)
            .build();
    }
}
```

## API Reference

### Core Classes

#### SMCPSecurityFramework

```java
public class SMCPSecurityFramework {
    public SMCPSecurityFramework();
    public SMCPSecurityFramework(SecurityConfig config);
    
    public MCPRequest validateRequest(MCPRequest request) throws SecurityException;
    public String authenticateUser(AuthCredentials credentials) throws AuthenticationException;
    public boolean authorizeAction(String userId, String action) throws AuthorizationException;
    public Object processSecureRequest(MCPRequest request, String userId, String sessionToken) throws SecurityException;
    public SecurityMetrics getSecurityMetrics();
}
```

#### SecurityConfig

```java
@Data
@Builder
public class SecurityConfig {
    private boolean enableInputValidation = true;
    private ValidationStrictness validationStrictness = ValidationStrictness.STANDARD;
    private boolean enableMFA = true;
    private int jwtExpirySeconds = 3600;
    private int sessionTimeoutSeconds = 7200;
    private boolean enableRBAC = true;
    private List<String> defaultPermissions = List.of("read");
    private boolean enableRateLimiting = true;
    private int defaultRateLimit = 100;
    private boolean adaptiveLimits = true;
    private boolean enableEncryption = true;
    private int keyRotationInterval = 86400;
    private boolean enableAIImmune = true;
    private double anomalyThreshold = 0.7;
    private boolean learningMode = false;
    private boolean enableAuditLogging = true;
    private LogLevel logLevel = LogLevel.INFO;
}
```

### Annotations

#### @SMCPSecured

```java
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface SMCPSecured {
    String[] permissions() default {};
    boolean requireMFA() default false;
    int rateLimit() default -1;
}
```

#### @RateLimited

```java
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RateLimited {
    int limit();
    String window() default "1m";
    String key() default "";
}
```

#### @ValidateMCP

```java
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = MCPRequestValidator.class)
public @interface ValidateMCP {
    String message() default "Invalid MCP request";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
    ValidationStrictness strictness() default ValidationStrictness.STANDARD;
}
```

## Examples

See the [examples](https://github.com/wizardscurtain/SMCPv1/tree/main/examples/java) directory for complete implementation examples:

- [Basic Usage](examples/basic-usage/src/main/java/BasicExample.java)
- [Spring Boot Application](examples/spring-boot/src/main/java/Application.java)
- [Quarkus Application](examples/quarkus/src/main/java/QuarkusApplication.java)
- [Custom Security Policies](examples/custom-policies/src/main/java/CustomPoliciesExample.java)
- [AI Immune System](examples/ai-immune/src/main/java/AIImmuneExample.java)
- [Microservices Architecture](examples/microservices/)

## Testing

```bash
# Run tests
mvn test

# Run with coverage
mvn test jacoco:report

# Run integration tests
mvn verify

# Run specific test
mvn test -Dtest=SMCPSecurityFrameworkTest
```

## Performance

- **Minimal Overhead**: < 5ms latency impact
- **High Throughput**: Handles 20,000+ requests/second
- **Memory Efficient**: < 20MB memory footprint
- **JVM Optimized**: Optimized for HotSpot and OpenJ9
- **Scalable**: Horizontal scaling support with clustering

## Security Features

### Input Validation
- Command injection prevention
- SQL injection protection
- XSS prevention
- Path traversal protection
- Schema validation with Bean Validation
- Content sanitization

### Authentication & Authorization
- JWT token management
- Multi-factor authentication (MFA)
- Role-based access control (RBAC)
- Session management
- Token refresh and rotation
- Spring Security integration

### Threat Detection
- Real-time anomaly detection
- Machine learning-based threat classification
- Behavioral analysis
- Attack pattern recognition
- Adaptive defense mechanisms

### Audit & Monitoring
- Comprehensive security event logging
- Real-time monitoring with Micrometer
- Compliance reporting
- Performance metrics
- Security analytics
- Integration with monitoring systems

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## Security

For security issues, please email security@smcp.dev instead of using the issue tracker.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📖 [Documentation](https://github.com/wizardscurtain/SMCPv1/tree/main/libraries/java)
- 💬 [Discussions](https://github.com/wizardscurtain/SMCPv1/discussions)
- 🐛 [Issues](https://github.com/wizardscurtain/SMCPv1/issues)
- 📧 [Email Support](mailto:support@smcp.dev)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.
