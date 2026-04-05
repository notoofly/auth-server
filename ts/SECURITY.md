# Security Guide

This document outlines security best practices and considerations for using @notoofly/auth-server in production.

## 🔒 Core Security Features

### JWT Verification
- **Algorithm Validation**: Only supports RS256 and ES256 algorithms
- **Claims Verification**: Validates `iss`, `aud`, `exp`, `nbf` claims
- **Key Validation**: Ensures `kid` header matches JWKS keys
- **Token Expiration**: Rejects expired tokens automatically

### JWKS Caching
- **Race-Safe**: Prevents duplicate JWKS fetch requests
- **Memory Management**: Automatic cleanup of expired keys
- **TTL Enforcement**: Configurable cache lifetime with secure defaults
- **Poison Prevention**: Validates key structure before caching

### Input Validation
- **Token Format**: Validates JWT structure before processing
- **Header Validation**: Ensures required headers are present
- **Parameter Sanitization**: Removes malicious input from URLs
- **Type Checking**: Strict TypeScript validation

## 🛡️ Production Security Checklist

### ✅ Required Configuration

#### Environment Variables
```bash
# Production required
NODE_ENV=production
JWT_ISSUER=https://your-auth-domain.com
JWT_AUDIENCE=your-api-audience
JWKS_URI=https://your-auth-domain.com/.well-known/jwks.json

# Security headers
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
```

#### TLS/HTTPS
- [ ] API endpoints use HTTPS only
- [ ] JWKS endpoint serves valid TLS certificate
- [ ] Redirect HTTP to HTTPS
- [ ] HSTS headers configured

#### CORS Configuration
```typescript
const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS?.split(',') || [],
  credentials: true,
  optionsSuccessStatus: 200
};
```

### ✅ Security Headers

#### Required Headers
```typescript
// Automatically added by security middleware
{
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin'
}
```

#### Content Security Policy
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'
```

### ✅ Rate Limiting

#### Implementation
```typescript
import rateLimit from 'express-rate-limit';

const limiter = rateLimit({
  windowMs: 60000, // 1 minute
  max: 100,        // 100 requests per minute
  message: 'Too many requests',
  standardHeaders: true,
  legacyHeaders: false
});
```

#### Rate Limiting Strategy
- **Public Endpoints**: 100 requests/minute
- **Auth Endpoints**: 10 requests/minute
- **Sensitive Operations**: 5 requests/minute
- **IP-based**: Limit by client IP
- **User-based**: Limit by authenticated user

## 🔍 Security Monitoring

### Logging Strategy
```typescript
// Security event logging
interface SecurityEvent {
  timestamp: string;
  event: 'auth_success' | 'auth_failure' | 'token_invalid' | 'rate_limit_exceeded';
  ip: string;
  userAgent?: string;
  userId?: string;
  details?: Record<string, any>;
}

// Log security events
function logSecurityEvent(event: SecurityEvent) {
  if (process.env.NODE_ENV === 'production') {
    // Send to security monitoring
    securityMonitor.log(event);
  }
}
```

### Error Handling
```typescript
// Sanitize error messages
function sanitizeError(error: Error): string {
  const message = error.message;
  
  if (process.env.NODE_ENV === 'production') {
    // Remove sensitive information
    return message
      .replace(/password|token|secret|key/gi, '[REDACTED]')
      .replace(/\b\d{4}\b/g, '[XXXX]'); // Redact last 4 digits
  }
  
  return message;
}
```

### Intrusion Detection
```typescript
// Detect suspicious patterns
interface SuspiciousActivity {
  multipleFailedLogins: boolean;
  rapidTokenRequests: boolean;
  unusualUserAgent: boolean;
  geoAnomaly: boolean;
}

function analyzeSuspiciousActivity(requests: Request[]): SuspiciousActivity {
  // Implement detection logic
  return {
    multipleFailedLogins: detectFailedLogins(requests),
    rapidTokenRequests: detectRapidRequests(requests),
    unusualUserAgent: detectUnusualUA(requests),
    geoAnomaly: detectGeoAnomaly(requests)
  };
}
```

## 🔐 Key Management

### JWKS Rotation
```bash
# Rotate keys regularly (recommended every 90 days)
#!/bin/bash
# generate-new-keys.sh
openssl ecparam -name prime256v1 -genkey -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem

# Update JWKS endpoint
# Add new key, keep old key for overlap period
```

### Key Storage
- [ ] Private keys stored securely (HSM/KMS)
- [ ] Access logs for key operations
- [ ] Key backup procedures documented
- [ ] Key destruction procedures documented

### Key Distribution
- [ ] JWKS served over HTTPS
- [ ] JWKS endpoint rate-limited
- [ ] Cache headers properly configured
- [ ] Failover JWKS endpoint configured

## 🚨 Incident Response

### Security Incident Categories
1. **Critical**: Token compromise, key exposure
2. **High**: Brute force attacks, DoS
3. **Medium**: Unauthorized access attempts
4. **Low**: Suspicious activity patterns

### Response Procedures
```typescript
// Immediate actions for critical incidents
async function handleCriticalIncident(incident: SecurityIncident) {
  // 1. Rotate all keys
  await rotateAllKeys();
  
  // 2. Invalidate all tokens
  await invalidateAllTokens();
  
  // 3. Update security headers
  updateSecurityHeaders();
  
  // 4. Notify security team
  await notifySecurityTeam(incident);
  
  // 5. Log incident
  await logSecurityIncident(incident);
}
```

### Communication Plan
- **Internal**: Security team within 15 minutes
- **Management**: Security lead within 30 minutes
- **Customers**: Within 2 hours (if customer impact)
- **Public**: Within 24 hours (if required)

## 🧪 Security Testing

### Penetration Testing
```bash
# Test JWT validation
curl -X POST https://api.example.com/protected \
  -H "Authorization: Bearer INVALID_TOKEN"

# Test rate limiting
for i in {1..200}; do
  curl https://api.example.com/auth/signin
done

# Test input validation
curl -X POST https://api.example.com/auth/signin \
  -H "Content-Type: application/json" \
  -d '{"email":"<script>alert(1)</script>","password":"test"}'
```

### Automated Security Scanning
```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run security scan
        run: |
          npm audit
          npx audit-ci --moderate
      - name: SAST scan
        run: |
          npx semgrep --config=auto .
```

## 📊 Security Metrics

### Key Performance Indicators
- **Mean Time to Detect (MTTD)**: < 5 minutes
- **Mean Time to Respond (MTTR)**: < 30 minutes
- **False Positive Rate**: < 1%
- **Authentication Success Rate**: > 99.5%
- **Zero-Day Exploitation Time**: 0 days

### Monitoring Dashboard
```typescript
// Security metrics collection
interface SecurityMetrics {
  authenticationAttempts: number;
  successfulAuthentications: number;
  failedAuthentications: number;
  tokenRefreshes: number;
  rateLimitHits: number;
  suspiciousActivities: number;
}

// Send to monitoring system
function reportMetrics(metrics: SecurityMetrics) {
  monitoring.send('security.metrics', {
    timestamp: new Date().toISOString(),
    ...metrics
  });
}
```

## 🔧 Security Configuration

### Environment-Specific Settings
```typescript
// Development
const devConfig = {
  logLevel: 'debug',
  rateLimiting: false,
  corsOrigins: ['*']
};

// Production
const prodConfig = {
  logLevel: 'error',
  rateLimiting: true,
  corsOrigins: ['https://yourdomain.com']
};
```

### Security Headers Configuration
```typescript
const securityHeaders = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
};
```

## 📚 Additional Security Resources

- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Cybersecurity Framework](https://csrc.nist.gov/publications/fipsnistpub/800-53-r4/final/)
- [Security Best Practices](https://docs.notoofly.com/security/best-practices)

## 🚨 Reporting Security Issues

If you discover a security vulnerability, please report it responsibly:

1. **Email**: security@notoofly.com
2. **Encryption**: Use our PGP key for sensitive information
3. **Timeline**: We'll respond within 48 hours
4. **Disclosure**: Coordinate public disclosure timeline

### Do NOT
- Create public issues for security vulnerabilities
- Use public channels to report security issues
- Exploit vulnerabilities in production

### Reward Program
- Critical: $1,000 - $5,000
- High: $500 - $1,000
- Medium: $100 - $500
- Low: $50 - $100
