# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-04-05

### Added
- Initial production release
- JWT verification with JWKS caching
- Express.js middleware adapter
- Elysia framework adapter
- Role-based authorization guards
- Permission-based authorization guards
- Race-safe JWKS fetching
- TypeScript support with strict typing
- Comprehensive error handling

### Security
- Token validation with issuer and audience verification
- Secure caching with TTL
- Input validation and sanitization
- Error message sanitization

### Performance
- In-memory JWKS caching
- Deduplicated concurrent requests
- Optimized token verification

### Documentation
- Complete API documentation
- Usage examples
- Migration guide
