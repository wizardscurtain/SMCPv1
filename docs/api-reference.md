# SMCP v1 API Reference

> **Canonical specification** — language-agnostic. All language implementations must conform to the contracts described here.

---

## Version Table

| Artifact | Version |
|---|---|
| SMCP Specification | **1.0** |
| Python library (`smcp-security`) | **1.0.0** |
| Node.js library (`smcp-security`) | **1.0.0** |

## Language Implementations

| Language | Status | Package |
|---|---|---|
| Python | **Stable** | `pip install smcp-security` |
| TypeScript / Node.js | **Stable** | `npm install smcp-security` |
| Go | Planned | — |
| Rust | Planned | — |
| Java | Planned | — |
| C# | Planned | — |

---

## Table of Contents

1. [Overview and Architecture](#1-overview-and-architecture)
2. [SecurityConfig](#2-securityconfig)
3. [SMCPSecurityFramework](#3-smcpsecurityframework)
4. [InputValidator](#4-inputvalidator)
5. [CommandInjectionPrevention](#5-commandinjectionprevention)
6. [PromptInjectionDetector](#6-promptinjectiondetector)
7. [JWTAuthenticator](#7-jwtauthenticator)
8. [MFAManager](#8-mfamanager)
9. [RBACManager](#9-rbacmanager)
10. [AdaptiveRateLimiter](#10-adaptiverate-limiter)
11. [DoSProtection](#11-dosprotection)
12. [SMCPCrypto](#12-smcpcrypto)
13. [Argon2KeyDerivation](#13-argon2keyderivation)
14. [SMCPAuditLogger](#14-smcpauditlogger)
15. [AIImmuneSystem](#15-aiimunesystem)
16. [ThreatClassifier](#16-threatclassifier)
17. [Exceptions](#17-exceptions)
18. [Framework Middleware](#18-framework-middleware)
19. [Environment Variables](#19-environment-variables)
20. [Quick Start](#20-quick-start)

---

## 1. Overview and Architecture

**SMCP** (Secure Model Context Protocol) is a security middleware layer designed to sit in front of any [Model Context Protocol](https://modelcontextprotocol.io/) server. It enforces a layered defense pipeline on every inbound MCP request before the request is handed to application logic, and it records a full audit trail after.

SMCP is transport-agnostic: it does not manage HTTP servers or socket connections itself. Instead, it exposes a single `processRequest` / `process_request` method that frameworks and transport adapters call. Ready-made adapters for Express, Fastify, and FastAPI are included (see §18).

### 1.1 The Six-Layer Defense Pipeline

Every request processed by `SMCPSecurityFramework.processRequest()` passes through the following layers in order:

```
Incoming MCP Request
        │
        ▼
┌───────────────────────┐
│  Layer 1              │
│  Input Validation     │  Schema check, size/depth limits, command injection,
│                       │  prompt injection, sanitization
└──────────┬────────────┘
           │
           ▼
┌───────────────────────┐
│  Layer 2              │
│  Authentication  +    │  JWT validation, MFA verification, RBAC permission
│  Authorization        │  check against required_permission for MCP method
└──────────┬────────────┘
           │
           ▼
┌───────────────────────┐
│  Layer 3              │
│  Rate Limiting        │  Sliding-window per-user + per-IP limits, adaptive
│                       │  CPU-based scaling, blacklist/whitelist bypass
└──────────┬────────────┘
           │
           ▼
┌───────────────────────┐
│  Layer 4              │  ┐
│  Cryptography         │  │  Degraded-mode layers:
│  (opt-in per request) │  │  non-security errors are caught and recorded
└──────────┬────────────┘  │  in security_metadata.errors; the pipeline
           │               │  continues rather than aborting.
           ▼               │
┌───────────────────────┐  │
│  Layer 5              │  │
│  AI Immune System     │  ┘
│                       │  Threat classification, anomaly detection,
│                       │  behavioral analysis, SecurityError on block
└──────────┬────────────┘
           │
           ▼
┌───────────────────────┐
│  Layer 6              │
│  Audit Logging        │  Degraded-mode; always attempted
└──────────┬────────────┘
           │
           ▼
    ProcessedResult
```

### 1.2 Degraded Mode

Layers 4 (Cryptography) and 6 (Audit Logging) operate in **degraded mode**: if they encounter a non-security error (e.g., a misconfigured key store, a transient I/O fault), the exception is caught, stored under `security_metadata.errors[layer_name]`, and the pipeline continues. Layers 1–3 and 5 are **hard-fail**: any error they raise immediately aborts the pipeline and propagates to the caller.

The AI Immune System (Layer 5) re-raises `SecurityError` when a block decision is made, but swallows unexpected internal exceptions (e.g., a numpy failure) in degraded mode.

---

## 2. SecurityConfig

Central configuration object. Pass one instance to `SMCPSecurityFramework` at construction time. All fields are optional; defaults are shown below.

### 2.1 Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `enableInputValidation` | `bool` | `true` | Enable Layer 1 (InputValidator). |
| `validationStrictness` | `"minimal" \| "standard" \| "maximum"` | `"standard"` | Controls how aggressively requests are validated. `maximum` adds 10 KB size cap and 10-level depth limit; see §4. |
| `enableMFA` | `bool` | `true` | Require MFA-verified tokens. |
| `jwtExpirySeconds` | `int` | `3600` | JWT token lifetime (seconds). Must be > 0. |
| `sessionTimeoutSeconds` | `int` | `7200` | Session inactivity timeout (seconds). Must be > 0. |
| `enableRBAC` | `bool` | `true` | Enable Layer 2 RBAC authorization. |
| `defaultPermissions` | `string[]` | `["read"]` | Permissions granted when no role is assigned. |
| `enableRateLimiting` | `bool` | `true` | Enable Layer 3 rate limiting. |
| `defaultRateLimit` | `int` | `100` | Default requests per minute per user. Must be > 0. |
| `adaptiveLimits` | `bool` | `true` | Scale limits down under high CPU load (see §10). |
| `enableEncryption` | `bool` | `true` | Enable Layer 4 cryptographic processing. |
| `keyRotationInterval` | `int` | `86400` | Key rotation interval (seconds, i.e., 24 hours). Must be > 0. |
| `enableAIImmune` | `bool` | `true` | Enable Layer 5 AI immune system. |
| `anomalyThreshold` | `float` | `0.7` | Risk score (0.0–1.0) above which a request is considered anomalous. |
| `learningMode` | `bool` | `false` | When `true`, the AI layer adds allowed requests to its baseline rather than enforcing blocks. |
| `enableAuditLogging` | `bool` | `true` | Enable Layer 6 audit logging. |
| `logLevel` | `"DEBUG" \| "INFO" \| "WARNING" \| "ERROR" \| "CRITICAL"` | `"INFO"` | Minimum severity level to emit. |

**Python field naming**: uses `snake_case` equivalents (`enable_input_validation`, `validation_strictness`, `enable_mfa`, etc.). All semantics are identical.

### 2.2 Static Factory Methods

Three convenience constructors set non-default overrides for common deployment scenarios.

#### `SecurityConfig.development()`

Suitable for local development. Relaxes enforcement so the developer loop is fast.

| Field | Override value |
|---|---|
| `enableMFA` | `false` |
| `validationStrictness` | `"minimal"` |
| `enableAIImmune` | `false` |
| `anomalyThreshold` | `0.9` |
| `defaultRateLimit` | `1000` |
| `learningMode` | `true` |
| `logLevel` | `"DEBUG"` |

#### `SecurityConfig.production()`

Hardened defaults for production. Equivalent to the standard defaults with `validationStrictness` raised to `"maximum"`.

| Field | Override value |
|---|---|
| `enableMFA` | `true` |
| `validationStrictness` | `"maximum"` |
| `enableAIImmune` | `true` |
| `anomalyThreshold` | `0.7` |
| `defaultRateLimit` | `100` |
| `learningMode` | `false` |
| `logLevel` | `"INFO"` |

#### `SecurityConfig.testing()`

Strips out stateful and slow layers so unit tests run in isolation.

| Field | Override value |
|---|---|
| `enableMFA` | `false` |
| `validationStrictness` | `"standard"` |
| `enableAIImmune` | `false` |
| `enableRateLimiting` | `false` |
| `enableAuditLogging` | `false` |
| `logLevel` | `"ERROR"` |

---

## 3. SMCPSecurityFramework

The primary entry point. Instantiate once per application and reuse.

### 3.1 Constructor

```typescript
new SMCPSecurityFramework(config?: Partial<SecurityConfig>)
```

```python
SMCPSecurityFramework(config: SecurityConfig = None)
```

Accepts an optional `SecurityConfig` (or partial overrides in TypeScript). If omitted, all defaults apply. Internally initialises all enabled security components and sets up default RBAC roles.

### 3.2 `processRequest`

```typescript
processRequest(requestData: object, userContext: object): Promise<ProcessedResult>
```

```python
async process_request(request_data: dict, user_context: dict = None) -> dict
```

The main pipeline entry point. Passes `requestData` through all six layers and returns a `ProcessedResult` on success, or raises a security exception on hard failure.

**`userContext` / `user_context` required fields:**

| Field | Type | Description |
|---|---|---|
| `token` | `string` | Bearer JWT token for the requesting user. |
| `ip_address` | `string` (optional) | Client IP, used by rate limiting and DoS detection. |
| `user_agent` | `string` (optional) | Client user agent, used by DoS pattern analysis. |
| `encrypt_payload` | `bool` (optional) | Set `true` to opt in to Layer 4 encryption of `params`/`data`/`body` fields. |

**Return shape — `ProcessedResult`:**

```
{
  request: <object>,          // sanitized and processed request
  context: {
    user_id:       string,
    roles:         string[],
    permissions:   string[],
    session_id:    string,    // JWT JTI claim
    threat_score:  float,
    security_level: "LOW_RISK" | "MEDIUM_RISK" | "HIGH_RISK" | "CRITICAL_RISK",
    ip_address:    string | null,
    user_agent:    string | null
  },
  security_metadata: {
    processing_time_ms:  float,
    security_level:      string,
    threat_score:        float,
    layers_processed:    string[],     // e.g. ["input_validation","authentication",...]
    timestamp:           string,       // ISO 8601 UTC
    user_roles:          string[],
    user_permissions:    string[],
    rate_limit_status: {               // null if rate limiting disabled
      user_id:             string,
      requests_in_window:  int
    } | null,
    ai_analysis: {
      threat_score:    float,
      recommendation:  "allow" | "monitor" | "block"
    },
    encryption_applied: bool,
    errors?: {                         // present only when degraded-mode errors occurred
      [layer_name: string]: string
    }
  }
}
```

**`security_level` thresholds:**

| `threat_score` | `security_level` |
|---|---|
| > 0.9 | `"CRITICAL_RISK"` |
| > 0.8 | `"HIGH_RISK"` |
| > 0.5 | `"MEDIUM_RISK"` |
| ≤ 0.5 | `"LOW_RISK"` |

### 3.3 `getSecurityMetrics`

```typescript
getSecurityMetrics(): SecurityMetrics
```

```python
get_security_metrics() -> dict
```

Returns a snapshot of cumulative metrics since the framework was instantiated.

**`SecurityMetrics` fields:**

| Field | Type | Description |
|---|---|---|
| `requests_processed` | `int` | Total requests that entered `processRequest`. |
| `attacks_blocked` | `int` | Requests blocked by any security layer. |
| `authentication_failures` | `int` | Failed JWT validations. |
| `authorization_failures` | `int` | RBAC permission denials. |
| `rate_limit_violations` | `int` | Requests rejected by the rate limiter. |
| `anomalies_detected` | `int` | Requests flagged above `anomalyThreshold`. |
| `false_positives` | `int` | Manually reported false positives. |
| `processing_time_ms` | `float[]` | Per-request processing times. |
| `avg_processing_time_ms` | `float` | Mean of the above array. |
| `max_processing_time_ms` | `float` | Maximum of the above array. |
| `success_rate` | `float` | `(requests_processed - attacks_blocked) / requests_processed`. |

### 3.4 `updateSecurityConfig`

```typescript
updateSecurityConfig(config: SecurityConfig): void
```

```python
update_security_config(new_config: SecurityConfig) -> None
```

Replaces the active configuration. **Note:** changing any field that affects a stateful component (e.g., `validationStrictness`, `defaultRateLimit`, `anomalyThreshold`) does not automatically reinitialise that component. Call `enable_layer` / `disable_layer` or restart the framework to apply component-level changes.

### 3.5 `decryptResponse`

```typescript
decryptResponse(responseData: object): object
```

```python
decrypt_response(response_data: dict) -> dict
```

Reverses the per-request payload encryption applied by Layer 4. Pass the `request` field from a `ProcessedResult` that was produced with `encrypt_payload: true`. Returns the decrypted version with `params` restored. If no `_encrypted_params` field is present, returns `responseData` unchanged.

### 3.6 `trainAIImmuneSystem`

```typescript
trainAIImmuneSystem(trainingRequests: object[]): Promise<void>
```

```python
async train_ai_immune_system(training_requests: list[dict]) -> None
```

Feeds a batch of known-good requests into the AI Immune System's baseline model. Only has an effect when `enableAIImmune` is `true`. In Python the training runs in a thread pool to avoid blocking the event loop.

---

## 4. InputValidator

Validates inbound MCP requests through a five-stage pipeline.

### 4.1 Constructor

```typescript
new InputValidator(strictness: "minimal" | "standard" | "maximum")
```

```python
InputValidator(strictness: str = "standard")
```

### 4.2 `validateRequest`

```typescript
validateRequest(requestData: object): ValidatedRequest       // sync
validateRequest(requestData: object): Promise<ValidatedRequest>  // awaitable
```

```python
validate_request(request_data: dict) -> dict    # sync and awaitable
```

Validates and sanitises a request. Returns the sanitised request dictionary. Both sync and async call patterns are supported in both implementations; Python returns an `_AwaitableDict` that resolves immediately when awaited.

### 4.3 `validateRequestAsync`

```typescript
// Not separately exposed; validateRequest is already awaitable.
```

```python
async validate_request_async(request_data: dict) -> dict
```

Async alias for `validate_request`. Provided for explicit async call sites.

### 4.4 The Five-Stage Validation Pipeline

**Stage 1 — Schema validation**

Validates against the MCP JSON-RPC 2.0 schema:

```json
{
  "type": "object",
  "required": ["jsonrpc", "method"],
  "properties": {
    "jsonrpc": { "type": "string", "enum": ["2.0"] },
    "method":  { "type": "string" },
    "id":      { "oneOf": [{ "type": "string" }, { "type": "number" }, { "type": "null" }] },
    "params":  { "type": "object" }
  }
}
```

Raises `ValidationError` on schema failure.

**Stage 2 — Size and depth check (`maximum` strictness only)**

| Limit | `minimal` | `standard` | `maximum` |
|---|---|---|---|
| Max request size (JSON-serialised) | 10 MB | 10 MB | **10 KB** |
| Max nesting depth | — | — | **10 levels** |

Raises `ValidationError` when exceeded.

**Stage 3 — Command injection check**

Calls `CommandInjectionPrevention.validateInput(params, context)` where `context` is derived from the MCP `method`:

| Method | Derived context |
|---|---|
| `tools/call` | `"shell"` |
| `resources/read`, `resources/write` | `"file_system"` |
| `database/query` | `"database"` |
| `api/call` | `"api"` |
| _(all others)_ | `null` (all-context rules apply) |

Raises `ValidationError` (wrapping `SecurityError`) on detection.

**Stage 4 — Prompt injection check**

Extracts all string content from the request and calls `PromptInjectionDetector.detectInjection()`. Raises `ValidationError` when `is_injection` is `true`.

**Stage 5 — Sanitisation**

Calls `CommandInjectionPrevention.sanitizeInput()` on the validated request. Strings are HTML-escaped and stripped of control characters (see §5). Returns the sanitised dict.

---

## 5. CommandInjectionPrevention

Detects and sanitises command-injection patterns in arbitrary input data.

### 5.1 `validateInput`

```typescript
validateInput(inputData: any, context?: string): boolean
```

```python
validate_input(input_data: Any, context: str = None) -> bool
```

Recursively inspects all string values in `inputData` against the rule set below. Returns `true` if safe. Raises `SecurityError` on detection.

**Context values:** `"shell"`, `"file_system"`, `"database"`, `"api"`. When `null`/`None`, all non-context-restricted rules apply.

### 5.2 `sanitizeInput`

```typescript
sanitizeInput(inputData: any): any
```

```python
sanitize_input(input_data: Any) -> Any
```

Returns a sanitised copy of `inputData`. Recursively transforms strings: HTML-escapes `<`, `>`, and `&`; strips control characters below code-point 32 except `\n` and `\t`. Dicts and lists are sanitised recursively; all other types are returned unchanged.

### 5.3 Validation Rules

| Rule name | Pattern (summary) | Applies to context | Severity |
|---|---|---|---|
| `shell_metacharacters` | `$(...)` `${...}` `` `cmd` `` `&&` `\|\|` | `"shell"` only | HIGH |
| `dangerous_commands` | `rm`, `del`, `shutdown`, `reboot`, `pkill`, `wget`, `curl`, `nc`, `netcat`, `bash`, `sh`, `zsh`, `ksh`, `python`, `perl`, `ruby`, `php`, `node`, `exec`, `eval` (word boundary) | `"shell"` only | CRITICAL |
| `cat_command` | `cat <path>` | `"shell"` only | HIGH |
| `path_traversal` | `../` or `..\` | All contexts | HIGH |
| `sql_injection` | `UNION SELECT`, `DROP TABLE`, `INSERT INTO`, `' OR '1'='1`, etc. | `"database"` only | HIGH |
| `xss_patterns` | `<script>`, `javascript:`, `on*=` event handlers | All contexts | MEDIUM |
| `code_execution` | `eval(`, `exec(`, `system(`, `shell_exec(`, `passthru(` | All contexts | CRITICAL |

**Important:** bare `;`, `|`, and `&` are intentionally **not flagged**. These characters appear legitimately in user agents, prose, and URLs, and are already covered by the `dangerous_commands` rule when used with an actual dangerous command name.

Context-restricted rules (those with a non-null `required_context`) are enforced when:
- The context matches, **or**
- No context is provided (standalone / direct usage).

They are **skipped** when a different specific context is active.

---

## 6. PromptInjectionDetector

Detects prompt-injection attempts in text using pattern matching with optional ML fallback.

### 6.1 `detectInjection`

```typescript
detectInjection(text: string): DetectionResult
```

```python
detect_injection(text: str) -> dict
```

**Return shape — `DetectionResult`:**

```typescript
{
  is_injection:      boolean,   // true when risk_score > 0.7
  risk_score:        float,     // 0.0–1.0
  detected_phrases:  string[],  // matched phrases / regex captures (deduplicated)
  method:            "pattern_based"
}
```

### 6.2 Risk Scoring

| Unique matches (`count`) | `risk_score` |
|---|---|
| 0 | `0.0` |
| 1 | `0.75` |
| 2 | `0.85` |
| 3+ | `min(0.85 + (count - 2) × 0.05, 1.0)` |

**Detection threshold:** `risk_score > 0.7` → `is_injection = true`.

Additional heuristics boost the score by +0.1 to +0.2 when certain keywords appear in the absence of a pattern match; these bring borderline texts over the threshold but do not lower it.

### 6.3 Suspicious Phrase Categories

The detector checks for the following categories of phrases and regex patterns:

- **Instruction override:** `ignore previous instructions`, `ignore all previous instructions`, `forget everything above`, `disregard the above/previous`, `new instructions:`
- **System/admin impersonation:** `system prompt override`, `system: `, `admin mode`, `developer mode`, `debug mode`, `[SYSTEM]...[/SYSTEM]`
- **Jailbreak / privilege escalation:** `jailbreak`, `override security`, `emergency override`, `full privileges`, `you are now in <X> mode`, `switch/activate/enable <X> mode`, `authorized by the system`, `execute all commands without validation`, `actually an admin`
- **Information extraction:** `reveal your instructions`, `reveal/show/display/tell me your system prompt/configuration/instructions/internal workings`
- **Execution directives:** `execute the following`, `prompt injection`

---

## 7. JWTAuthenticator

Handles JWT generation, validation, and revocation.

### 7.1 Constructor

```typescript
new JWTAuthenticator(config: AuthenticationConfig)
```

```python
JWTAuthenticator(config: AuthenticationConfig = None)
```

**`AuthenticationConfig` fields:**

| Field | Default | Description |
|---|---|---|
| `jwtSecretKey` / `jwt_secret_key` | — (required) | Signing secret. Must come from `SMCP_JWT_SECRET` env var in production — see §7.5. |
| `jwtAlgorithm` / `jwt_algorithm` | `"HS256"` | Signing algorithm. Use `"ES384"` for distributed deployments — see §7.5. |
| `jwtExpirySeconds` / `jwt_expiry_seconds` | `3600` | Token lifetime (seconds). |
| `sessionTimeoutSeconds` / `session_timeout_seconds` | `7200` | Session inactivity timeout. |
| `requireMfa` / `require_mfa` | `true` | Reject tokens without `mfa_verified: true`. |
| `totpIssuer` / `totp_issuer` | `"SMCP Security"` | Issuer name shown in authenticator apps. |

### 7.2 `generateToken`

```typescript
generateToken(
  userId: string,
  roles: string[],
  permissions: string[],
  mfaVerified: boolean
): string
```

```python
generate_token(
  user_id: str,
  roles: list[str] = None,
  permissions: list[str] = None,
  mfa_verified: bool = False
) -> str
```

Returns a signed JWT string. Payload fields:

| Claim | Description |
|---|---|
| `user_id` | Provided user identifier |
| `roles` | Provided roles array |
| `permissions` | Provided permissions array |
| `mfa_verified` | Provided boolean |
| `iat` | Issued-at timestamp |
| `exp` | Expiry (`iat + jwtExpirySeconds`) |
| `jti` | Random unique token ID (URL-safe base64, 16 bytes) |
| `iss` | Fixed: `"smcp-security"` |
| `aud` | Fixed: `"smcp-client"` |

### 7.3 `validateToken`

```typescript
validateToken(token: string): TokenPayload
```

```python
validate_token(token: str) -> dict
```

Decodes and validates a JWT. Verifies signature, expiry, issuer (`smcp-security`), and audience (`smcp-client`). Checks the revocation list. When `requireMfa` is `true`, rejects tokens with `mfa_verified: false`.

Raises `AuthenticationError` on:
- Expired token
- Revoked token (`jti` in revocation set)
- Invalid signature or malformed JWT
- Missing MFA verification when required

### 7.4 `revokeToken` / `isTokenRevoked`

```typescript
revokeToken(token: string): void
isTokenRevoked(token: string): boolean
```

```python
revoke_token(token: str) -> None
is_token_revoked(token: str) -> bool   # check by jti
```

`revokeToken` adds the token's `jti` claim to an in-memory revocation set. **Production note:** use a shared store (Redis, database) so revocations survive restarts and propagate across nodes.

### 7.5 Security Notes

> **CRITICAL:** The JWT secret must be loaded from the `SMCP_JWT_SECRET` environment variable. Never hardcode a default secret in production code. Minimum recommended length: 32 characters.

> **Algorithm guidance:** The default algorithm `HS256` is a symmetric HMAC — suitable only for single-server deployments where the same process both signs and verifies tokens. For distributed or microservice deployments, use `ES384` (ECDSA with P-384) and supply a P-384 key pair. P-384 is aligned with the CNSA 2.0 suite.

---

## 8. MFAManager

Manages TOTP-based multi-factor authentication and single-use backup codes.

### 8.1 `setupMFA`

```typescript
setupMFA(userId: string): { secret: string, qrCode: string, backupCodes: string[] }
```

```python
setup_totp(user_id: str) -> dict   # { secret, qr_code, provisioning_uri }
```

Generates a new TOTP secret for `userId`, stores it, and returns:

| Field | Description |
|---|---|
| `secret` | Base-32 TOTP secret key |
| `qrCode` / `qr_code` | `data:image/png;base64,...` QR code for authenticator app import |
| `backupCodes` | (TypeScript) 10 one-time backup codes |
| `provisioning_uri` | (Python) `otpauth://` URI |

Protocol: TOTP per RFC 6238, 30-second window, issuer `"SMCP Security"`.

### 8.2 `verifyToken`

```typescript
verifyToken(userId: string, token: string): boolean
```

```python
verify_totp(user_id: str, code: str) -> bool
```

Verifies a 6-digit TOTP code. Accepts the current and immediately adjacent 30-second windows (`valid_window=1`) to tolerate clock skew.

### 8.3 `generateBackupCodes`

```typescript
generateBackupCodes(userId: string): string[]
```

```python
generate_backup_codes(user_id: str, count: int = 10) -> list[str]
```

Generates `count` (default 10) single-use backup codes. Codes are 8-character uppercase alphabetic strings. Stored internally as SHA-256 hashes.

### 8.4 `verifyBackupCode`

```typescript
verifyBackupCode(userId: string, code: string): boolean
```

```python
verify_backup_code(user_id: str, code: str) -> bool
```

Verifies and **consumes** a backup code. Once used, the code is deleted and cannot be reused.

---

## 9. RBACManager

Role-Based Access Control with permission inheritance and wildcard matching.

### 9.1 Methods

| Method | Description |
|---|---|
| `defineRole(roleName, permissions[])` / `define_role(role_name, permissions)` | Define a role with a list of permission strings. Returns the created Role object. |
| `assignRole(userId, roleName)` / `assign_role(user_id, role_name)` | Assign an existing role to a user. Raises `AuthorizationError` if the role is not defined. |
| `revokeRole(userId, roleName)` / `revoke_role(user_id, role_name)` | Remove a role assignment. No-op if the user doesn't have the role. |
| `checkPermission(userId, permission)` / `check_permission(user_id, permission)` | Returns `true` if the user has the permission (including wildcards and inherited roles). Deny rules take precedence over allow rules. |
| `getUserRoles(userId)` / `get_user_roles(user_id)` | Returns `string[]` of role names assigned to the user. |
| `getUserPermissions(userId)` / `get_user_permissions(user_id)` | Returns `string[]` of all effective permission strings (including inherited). |

### 9.2 Permission Format

Permissions use a `namespace:action` or `namespace:*` format:

```
mcp:read                  # allow read access to all MCP resources
mcp:execute:safe_tools    # allow execution of safe-tagged tools
mcp:*                     # wildcard: all MCP actions
system:*                  # all system actions
security:*                # all security actions
```

Wildcard `*` in a permission string matches any suffix.

### 9.3 Default Roles

`SMCPSecurityFramework` initialises these roles automatically on startup:

| Role | Permissions |
|---|---|
| `user` | `mcp:read`, `mcp:execute:safe_tools` |
| `power_user` | `mcp:read`, `mcp:write`, `mcp:execute:all_tools` |
| `admin` | `mcp:*`, `system:*`, `security:*` |

### 9.4 Method→Permission Mapping

The framework maps the `method` field of an MCP request to a required RBAC permission:

| MCP method | Required permission |
|---|---|
| `tools/list` | `mcp:read` |
| `tools/call` | `mcp:read` |
| `resources/list` | `mcp:read` |
| `resources/read` | `mcp:read` |
| `resources/write` | `mcp:write` |
| `prompts/list` | `mcp:read` |
| `prompts/get` | `mcp:read` |
| `system/config` | `system:config` |
| _(all others)_ | `mcp:read` |

---

## 10. AdaptiveRateLimiter

Sliding-window per-user and per-IP rate limiter with adaptive CPU-based scaling.

### 10.1 Constructor

```typescript
new AdaptiveRateLimiter(config: RateLimitConfig)
// or convenience overload:
new AdaptiveRateLimiter(defaultLimit: number, windowSeconds: number, adaptive: boolean)
```

```python
AdaptiveRateLimiter(config: RateLimitConfig = None,
                    default_limit: int = 100,
                    window_seconds: int = 60,
                    adaptive: bool = True)
```

**`RateLimitConfig` fields:**

| Field | Default | Description |
|---|---|---|
| `defaultLimit` / `default_limit` | `100` | Baseline requests per window. |
| `windowSeconds` / `window_seconds` | `60` | Sliding window duration in seconds. |
| `burstLimit` / `burst_limit` | `150` | Limit when `allowBurst=true`. |
| `adaptive` | `true` | Enable CPU-based scaling. |

### 10.2 `checkRateLimit`

```typescript
checkRateLimit(
  userId: string,
  endpoint?: string,
  requestSize?: number,
  allowBurst?: boolean
): boolean
```

```python
check_rate_limit(
  user_id: str,
  endpoint: str = "default",
  request_size: int = 0,
  allow_burst: bool = False
) -> bool
```

Returns `true` if the request is within limits; raises `RateLimitError` otherwise. Whitelisted users always pass. Blacklisted users always fail.

### 10.3 Adaptive CPU Scaling

When `adaptiveLimits` is `true`, the effective limit for a request is:

| System CPU load | Effective limit |
|---|---|
| < 80% | Base limit (no reduction) |
| ≥ 80% | 75% of base limit |
| ≥ 90% | 50% of base limit |

### 10.4 Other Methods

| Method | Description |
|---|---|
| `checkRateLimitByIP(ipAddress)` / `check_rate_limit_by_ip(ip_address)` | Applies rate limit keyed on IP address rather than user ID. |
| `setUserLimit(userId, limit)` / `set_user_limit(user_id, limit)` | Override the rate limit for a specific user. |
| `addToWhitelist(userId)` / `add_to_whitelist(user_id)` | Exempt user from rate limits entirely. Removes from blacklist. |
| `removeFromWhitelist(userId)` / `remove_from_whitelist(user_id)` | Remove whitelist exemption. |
| `addToBlacklist(userId)` / `add_to_blacklist(user_id)` | Block all requests from user. Removes from whitelist. |
| `removeFromBlacklist(userId)` / `remove_from_blacklist(user_id)` | Remove blacklist entry. |
| `getRateLimitStatus(userId)` / `get_rate_limit_status(user_id)` | Returns `{ requests_made, limit, remaining, reset_time, window_seconds }`. |
| `getRateLimitHeaders(userId)` / `get_rate_limit_headers(user_id)` | Returns `{ X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-RateLimit-Window }` as strings. |
| `flagSuspiciousIP(ipAddress)` / `flag_suspicious_ip(ip_address)` | Marks an IP as suspicious for DoS correlation. Called automatically on auth/authz failures. |

---

## 11. DoSProtection

Detects and responds to Denial-of-Service patterns at the IP level.

### 11.1 `analyzeRequest`

```typescript
analyzeRequest(
  ipAddress: string,
  userId: string,
  requestPath?: string,
  requestData?: object
): { allowed: boolean, threat_level: float, reason: string }
```

```python
analyze_request(
  ip_address: str,
  user_id: str,
  request_path: str = None,
  request_data: dict = None
) -> dict
```

Tracks per-IP request timestamps. An IP is automatically marked suspicious when it makes **more than 50 requests within 60 seconds**. Returns `allowed: false` for blocked IPs.

### 11.2 IP Blocking

| Method | Description |
|---|---|
| `blockIP(ipAddress, durationSeconds, reason?)` / `block_ip(...)` | Block an IP for `durationSeconds`. Default: 3600 seconds. |
| `unblockIP(ipAddress)` / `unblock_ip(ip_address)` | Remove block immediately. |
| `isIPBlocked(ipAddress)` / `is_ip_blocked(ip_address)` | Returns `true` if IP is currently blocked (auto-expires). |

### 11.3 Whitelist

| Method | Description |
|---|---|
| `addToWhitelist(ipAddress)` / `add_to_whitelist(ip_address)` | Whitelist an IP (removes from suspicious). |
| `removeFromWhitelist(ipAddress)` / `remove_from_whitelist(ip_address)` | Remove whitelist entry. |

### 11.4 Analysis Methods

| Method | Return shape | Description |
|---|---|---|
| `getThreatLevel(ipAddress?)` / `get_threat_level(ip_address)` | `float` (0.0–1.0) | Global threat if `ipAddress` omitted; per-IP otherwise. |
| `generateChallenge(ipAddress)` / `generate_challenge(ip_address)` | `{ challenge_id, challenge_data, challenge_type: "hash", expires_at }` | Issues a proof-of-work style challenge (5-minute TTL). |
| `verifyChallengeResponse(challengeId, response)` / `verify_challenge_response(...)` | `bool` | Validates challenge response (SHA-256 of `challenge_data`). |
| `analyzeUserAgent(userAgent)` / `analyze_user_agent(user_agent)` | `{ suspicious, bot_score, indicators }` | Detects known bot/script user agents. |
| `analyzePatterns(ipAddress)` / `analyze_patterns(ip_address)` | `{ suspicious, pattern_score }` | Flags IPs with high admin-path request ratios or volume > 30. |

---

## 12. SMCPCrypto

Symmetric and asymmetric cryptographic operations.

### 12.1 Constructor

```typescript
new SMCPCrypto()
```

```python
SMCPCrypto(config: CryptoConfig = None)
```

### 12.2 Key Management

| Method | Description |
|---|---|
| `setMasterKey(keyBytes)` / `set_master_key(key: bytes)` | Store the master key and generate an initial working key via `rotateKeys`. |

### 12.3 Symmetric Encryption

**Algorithm:** ChaCha20-Poly1305 (256-bit key, 96-bit nonce, 128-bit authentication tag). Aligned with CNSA 2.0.

#### `encrypt`

```typescript
encrypt(data: Buffer): { ciphertext: Buffer, nonce: Buffer, tag: Buffer, key_id: string, algorithm: string }
```

```python
encrypt(plaintext: bytes, key: bytes = None) -> dict
# Returns: { ciphertext, nonce, key_id }
```

Encrypts `data` using the current active key. Returns the ciphertext envelope. The `key_id` is needed for decryption.

#### `decrypt`

```typescript
decrypt(encrypted: object): Buffer
```

```python
decrypt(encrypted_data: dict, key: bytes = None) -> bytes
```

Decrypts a ciphertext envelope produced by `encrypt`. Raises `CryptographicError` on failure (wrong key, corrupted tag, etc.).

### 12.4 Asymmetric Operations

**Algorithm:** EC P-384 (NIST P-384, SECP384R1). Keys are serialised as PEM-encoded DER (PKCS#8 private key, SubjectPublicKeyInfo public key).

| Method | Description |
|---|---|
| `generateKeyPair()` / `generate_key_pair()` | Returns `{ privateKey, publicKey }` (PEM bytes / tuple). |
| `sign(data, privateKey)` / `sign_data(private_key_bytes, data)` | ECDSA signature with SHA-256. |
| `verify(data, signature, publicKey)` / `verify_signature(public_key_bytes, data, signature)` | Returns `bool`. |
| `deriveSharedSecret(privateKey, peerPublicKey)` / `key_exchange(private_key_bytes, peer_public_key_bytes)` | ECDH P-384 key exchange; returns a 32-byte shared secret derived via HKDF-SHA256. |

### 12.5 `analyzeRequest`

```typescript
analyzeRequest(requestData: object, authContext: object): void
```

```python
analyze_request(request_data: dict, context: dict = None) -> dict
```

Integrity check hook for the pipeline. Validates that any `_encrypted_params` field is well-formed. Raises `CryptographicError` on malformed input. This method can be patched by test harnesses to simulate crypto failures triggering degraded mode.

---

## 13. Argon2KeyDerivation

Argon2id-based password hashing and key derivation.

### 13.1 Constructor

```typescript
new Argon2KeyDerivation()
```

```python
Argon2KeyDerivation(
  time_cost: int = 3,
  memory_cost: int = 65536,  # 64 MB
  parallelism: int = 1,
  hash_length: int = 32,
  salt_length: int = 16
)
```

Default parameters follow OWASP recommendations for Argon2id:

| Parameter | Default | Description |
|---|---|---|
| `memory` | `65536` KB (64 MB) | Memory hardness |
| `iterations` / `time_cost` | `3` | Time cost (iterations) |
| `parallelism` | `1` | Degree of parallelism |
| `hash_length` | `32` bytes | Output key length |

### 13.2 `deriveKey`

```typescript
deriveKey(password: string, salt?: Buffer, keyLength?: number): { key: Buffer, salt: Buffer, params: object }
```

```python
derive_key(password: str, salt: bytes) -> bytes
derive_key_with_salt(password: str) -> { key: bytes, salt: bytes }
```

Derives a key from `password` using Argon2id. When `salt` is not provided (`deriveKey_with_salt` / TypeScript optional), a cryptographically random salt is generated automatically.

Raises `TypeError` if `password` is `None`; raises `ValueError` if `password` or `salt` is empty.

---

## 14. SMCPAuditLogger

Structured event logging with in-memory buffer and optional file output.

### 14.1 Constructor

```typescript
new SMCPAuditLogger(logLevel: string)
```

```python
SMCPAuditLogger(
  config: AuditConfig = None,
  log_level: str = "INFO",
  max_events_memory: int = 10000,
  enable_file_logging: bool = True,
  log_file_path: str = "smcp_audit.log"
)
```

### 14.2 Logging Methods

| Method | Description |
|---|---|
| `logEvent(category, severity, message, context?)` / `log_event(category, severity, message, **kwargs)` | Log a generic event. Returns `event_id` (string). |
| `logAuthenticationEvent(userId, eventType, success, ipAddress?)` / `log_authentication_event(...)` | Log an authentication success or failure. |
| `logAuthorizationEvent(userId, resource, action, granted, ipAddress?)` / `log_authorization_event(...)` | Log an authorization decision. |
| `logSecurityEvent(eventType, userId, details, level?)` / `log_security_event(...)` | Log a general security event. |

### 14.3 Event Retrieval

```typescript
getEvents(filters?: EventFilters): AuditEvent[]
```

```python
get_events(
  limit: int = None,
  category: EventCategory = None,
  min_severity: EventSeverity = None,
  severity: EventSeverity = None,
  user_id: str = None,
  start_time: datetime = None,
  end_time: datetime = None
) -> list[dict]
```

When `limit` is provided, returns the oldest `limit` matching events (ascending). When omitted, returns all matching events newest-first.

### 14.4 Enumerations

**`EventCategory`:**

| Value | Description |
|---|---|
| `INPUT_VALIDATION` | Layer 1 validation events |
| `AUTHENTICATION` | JWT / token events |
| `AUTHORIZATION` | RBAC decisions |
| `RATE_LIMITING` | Rate limit hits |
| `CRYPTOGRAPHY` | Encryption / key operations |
| `AI_IMMUNE` / `ANOMALY_DETECTION` | AI layer analysis events |
| `AUDIT` | Audit system self-events |
| `SECURITY_VIOLATION` | Policy / rule violations |

**`EventSeverity`** (ordered LOW < MEDIUM < HIGH < CRITICAL):

| Value |
|---|
| `LOW` |
| `MEDIUM` |
| `HIGH` |
| `CRITICAL` |

---

## 15. AIImmuneSystem

Multi-signal anomaly detection combining pattern matching, statistical analysis, and optional ML.

### 15.1 Constructor

```typescript
new AIImmuneSystem(threshold: float, learningMode: boolean)
```

```python
AIImmuneSystem(
  config: AIImmuneConfig = None,
  threshold: float = 0.7,
  learning_mode: bool = False
)
```

### 15.2 `analyzeRequest`

```typescript
analyzeRequest(requestData: object, authContext: object): AnalysisResult
```

```python
analyze_request(request: dict, context: dict) -> dict
```

Performs three analyses and combines them into a single `overall_risk_score`:

```
overall_risk_score = max(
  threat_score × 0.6 + anomaly_score × 0.25 + behavioral_score × 0.15,
  threat_score × 0.85
)
```

**Return shape:**

```typescript
{
  threat_analysis:     object,   // from ThreatClassifier
  anomaly_analysis:    object,   // from AnomalyDetector
  behavioral_analysis: object,   // from user behavior profile
  overall_risk_score:  float,    // 0.0–1.0
  recommendation:      "allow" | "monitor" | "block"
}
```

**Recommendation thresholds:**

| `overall_risk_score` | `recommendation` |
|---|---|
| ≥ `threshold` | `"block"` |
| ≥ `threshold × 0.6` | `"monitor"` |
| < `threshold × 0.6` | `"allow"` |

**Exception behaviour:** Raises `SecurityError` (propagated as hard-fail through the pipeline) when `overall_risk_score > anomalyThreshold` AND (`overall_risk_score > 0.9` OR `recommendation == "block"`).

In learning mode (`learningMode: true`), requests that receive `"allow"` recommendations are added to the anomaly detector's baseline.

### 15.3 `train`

```typescript
train(normalRequests: object[]): void
```

```python
train(normal_requests: list[dict]) -> None
```

Updates the anomaly detection baseline with a batch of known-good requests. No-op when ML libraries are unavailable. Called indirectly by `SMCPSecurityFramework.trainAIImmuneSystem`.

### 15.4 `getStats`

```typescript
getStats(): { total_analyzed: int, threats_blocked: int, false_positives: int, model_accuracy: float }
```

```python
get_system_health() -> dict
```

Returns performance statistics for the AI layer.

---

## 16. ThreatClassifier

Classifies requests into named threat categories using pattern matching (with optional ML hybrid).

### 16.1 `classifyThreat`

```typescript
classifyThreat(requestData: object): { threat_type: string, confidence: float, indicators: string[] }
```

```python
classify_request(request_data: dict) -> dict
# Returns: { threat_level, threat_type, confidence, features, method }
```

**`threat_type` values:**

| Value | Description |
|---|---|
| `"prompt_injection"` | Prompt override / jailbreak patterns |
| `"command_injection"` | Shell metacharacters, dangerous commands |
| `"dos_attack"` | High-rate or DDoS traffic patterns |
| `"data_exfiltration"` | Attempts to read sensitive files or data |
| `"privilege_escalation"` | SQL injection, auth bypass patterns |
| `"xss_attack"` | Cross-site scripting payloads |
| `"code_execution"` | `eval()`, `exec()`, `system()` calls |
| `"path_traversal"` | `../` directory traversal |
| `"normal"` / `"none"` | No threat detected |

Classification uses a pattern-matching engine against the full JSON serialisation of the request. When scikit-learn is available, results from a trained IsolationForest model are combined with pattern scores.

---

## 17. Exceptions

All SMCP exceptions extend a common base. HTTP status code mappings are listed for use in middleware adapters.

| Exception | HTTP status | Description |
|---|---|---|
| `SecurityError` | 403 | Base class for all security-related exceptions. Raised by the AI immune system, command injection checks, and policy blocks. |
| `ValidationError` | 400 | Input failed schema, size, injection, or prompt injection checks. Has `validationErrors: string[]` field listing specific failures. |
| `AuthenticationError` | 401 | JWT is missing, expired, revoked, malformed, or missing MFA verification. |
| `AuthorizationError` | 403 | User lacks the required RBAC permission. Has optional `requiredPermission: string` field. |
| `RateLimitError` | 429 | Request count exceeded the sliding window limit. Has `retryAfter: int` (seconds until window resets). |
| `CryptographicError` | 500 | Cryptographic operation failed (malformed ciphertext, missing key, etc.). Handled in degraded mode by Layer 4; does not abort the pipeline unless thrown by `analyzeRequest`. |

**Python exception hierarchy:**

```
SMCPSecurityError (base)
├── SecurityError
│   └── AuthorizationError
├── ValidationError
├── AuthenticationError
├── RateLimitError
├── CryptographicError
└── AnomalyDetectionError
```

---

## 18. Framework Middleware

Ready-made adapters that wire `SMCPSecurityFramework` into popular web frameworks.

### 18.1 Express Middleware

```typescript
import { createExpressMiddleware } from 'smcp-security';

const smcpMiddleware = createExpressMiddleware(framework, options?);
app.use(smcpMiddleware);
```

**Behaviour:**

1. Reads the `Authorization: Bearer <token>` header.
2. Calls `framework.processRequest(req.body, { token, ip_address: req.ip, user_agent: req.headers['user-agent'] })`.
3. On success: attaches the full `ProcessedResult` to `req.smcpContext` and calls `next()`.
4. On failure: returns an appropriate HTTP error response without calling `next()`.

**Error → HTTP status mapping:**

| Exception | Status |
|---|---|
| `AuthenticationError` | `401 Unauthorized` |
| `AuthorizationError` | `403 Forbidden` |
| `RateLimitError` | `429 Too Many Requests` |
| `ValidationError` | `400 Bad Request` |
| `SecurityError` | `403 Forbidden` |
| Any other | `500 Internal Server Error` |

### 18.2 Fastify Plugin

```typescript
import { createFastifyPlugin } from 'smcp-security';

await fastify.register(createFastifyPlugin(framework, options?));
```

Same semantics as the Express adapter, implemented as a Fastify `onRequest` hook. Attaches `ProcessedResult` to `request.smcpContext`.

### 18.3 Python / FastAPI (ASGI Middleware)

```python
from smcp_security.middleware import SMCPSecurityMiddleware

app.add_middleware(SMCPSecurityMiddleware, security_framework=framework)
```

Implemented as a Starlette `BaseHTTPMiddleware`. Skips security for `/health`, `/metrics`, `/static`, and `/favicon.ico`. Validates the `Authorization: Bearer <token>` header and attaches `user_id` and `user_context` to `request.state`.

---

## 19. Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SMCP_JWT_SECRET` | **YES (production)** | JWT signing secret. Minimum 32 characters. If absent, the framework generates a random ephemeral secret (tokens won't survive restarts). |
| `SMCP_LOG_LEVEL` | No | Override the `logLevel` config field at startup. Accepted values: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `SMCP_ANOMALY_THRESHOLD` | No | Override the `anomalyThreshold` config field at startup. Must be a float between 0.0 and 1.0. |

---

## 20. Quick Start

### 20.1 Minimal Setup

```typescript
import { SMCPSecurityFramework, SecurityConfig } from 'smcp-security';

const framework = new SMCPSecurityFramework(
  SecurityConfig.development()
);

const result = await framework.processRequest(
  {
    jsonrpc: '2.0',
    method: 'tools/list',
    id: 1
  },
  {
    token: myJwtToken,
    ip_address: '127.0.0.1'
  }
);

console.log(result.context.user_id);
console.log(result.security_metadata.layers_processed);
```

```python
from smcp_security import SMCPSecurityFramework, SecurityConfig
import asyncio

framework = SMCPSecurityFramework(SecurityConfig())  # all defaults

async def main():
    result = await framework.process_request(
        {"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        {"token": my_jwt_token, "ip_address": "127.0.0.1"}
    )
    print(result["context"]["user_id"])
    print(result["security_metadata"]["layers_processed"])

asyncio.run(main())
```

---

### 20.2 Full Production Setup

```typescript
import { SMCPSecurityFramework, SecurityConfig } from 'smcp-security';

// SMCP_JWT_SECRET must be set in the environment
const framework = new SMCPSecurityFramework(
  SecurityConfig.production()
  // production() sets: validationStrictness="maximum", enableMFA=true,
  // enableAIImmune=true, anomalyThreshold=0.7, logLevel="INFO"
);

// Optional: pre-train the AI layer with known-good traffic samples
await framework.trainAIImmuneSystem(normalTrafficSamples);

// Inspect live metrics
const metrics = framework.getSecurityMetrics();
console.log(`Success rate: ${(metrics.success_rate * 100).toFixed(1)}%`);
console.log(`Attacks blocked: ${metrics.attacks_blocked}`);
```

```python
import os
from smcp_security import SMCPSecurityFramework, SecurityConfig
from smcp_security.authentication import AuthenticationConfig

# Override with a custom JWT config pointing at the env-var secret
config = SecurityConfig(
    validation_strictness="maximum",
    enable_mfa=True,
    enable_ai_immune=True,
    anomaly_threshold=0.7,
    log_level="INFO",
)

framework = SMCPSecurityFramework(config)
# Note: JWTAuthenticator reads SMCP_JWT_SECRET from environment internally
```

---

### 20.3 Express Middleware Integration

```typescript
import express from 'express';
import { SMCPSecurityFramework, SecurityConfig, createExpressMiddleware } from 'smcp-security';

const app = express();
app.use(express.json());

const framework = new SMCPSecurityFramework(SecurityConfig.production());

// Apply SMCP to all routes
app.use(createExpressMiddleware(framework));

app.post('/mcp', (req, res) => {
  // req.smcpContext is populated by the middleware
  const { context, security_metadata } = req.smcpContext;
  res.json({
    user: context.user_id,
    threat_score: security_metadata.threat_score
  });
});

app.listen(3000);
```

---

### 20.4 Generating and Validating a Token Manually

```typescript
import {
  JWTAuthenticator,
  MFAManager,
  RBACManager,
  SecurityConfig
} from 'smcp-security';

// Initialise authenticator (reads SMCP_JWT_SECRET from env)
const auth = new JWTAuthenticator({
  secret: process.env.SMCP_JWT_SECRET!,
  expiresIn: 3600
});

// Set up MFA for a user
const mfa = new MFAManager();
const { secret, qrCode } = mfa.setupMFA('alice');
// → display qrCode to user in enrolment UI

// After user scans QR code, verify their first code:
const mfaOk = mfa.verifyToken('alice', userSuppliedCode);

// Generate a JWT for alice
const token = auth.generateToken(
  'alice',
  ['user'],
  ['mcp:read', 'mcp:execute:safe_tools'],
  mfaOk  // mfa_verified
);

// Later: validate the token
try {
  const payload = auth.validateToken(token);
  console.log(payload.user_id);   // "alice"
  console.log(payload.roles);     // ["user"]
  console.log(payload.mfa_verified); // true
} catch (e) {
  // AuthenticationError: expired, revoked, or invalid
}

// Revoke token on logout
auth.revokeToken(token);
```

```python
import os
from smcp_security.authentication import (
    JWTAuthenticator, MFAManager, AuthenticationConfig
)

config = AuthenticationConfig(
    jwt_secret_key=os.environ["SMCP_JWT_SECRET"],
    jwt_expiry_seconds=3600,
    require_mfa=True,
)
auth = JWTAuthenticator(config)

# Set up TOTP for a user
mfa = MFAManager()
setup = mfa.setup_totp("alice")
# setup["qr_code"] → display to user

# After user scans, verify their first TOTP code
mfa_ok = mfa.verify_totp("alice", user_supplied_code)

# Generate a signed JWT
token = auth.generate_token(
    user_id="alice",
    roles=["user"],
    permissions=["mcp:read", "mcp:execute:safe_tools"],
    mfa_verified=mfa_ok,
)

# Validate later
try:
    payload = auth.validate_token(token)
    print(payload["user_id"])       # "alice"
    print(payload["mfa_verified"])  # True
except AuthenticationError as e:
    print(f"Auth failed: {e}")

# Revoke on logout
auth.revoke_token(token)
```
