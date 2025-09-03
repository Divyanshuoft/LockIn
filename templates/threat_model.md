# Threat Model - LockIn Authentication System

## STRIDE Analysis

### S - Spoofing
- **Threat**: Attackers may attempt to impersonate legitimate users through:
  - Brute force attacks on user passwords
  - Credential stuffing using leaked passwords
  - Session hijacking
- **Mitigations**:
  - Passwords are hashed using bcrypt with 12 rounds of hashing
  - Rate limiting (5 attempts per minute) on login and signup endpoints
  - Generic error messages for failed logins (no indication of which field is wrong)
  - Session management through Flask-Login with secure session configuration
  - Strong password requirements (minimum 8 characters)

### T - Tampering
- **Threat**: Attackers may try to modify:
  - Form submissions to inject malicious data
  - SQL queries to manipulate database
  - Session data to elevate privileges
- **Mitigations**:
  - CSRF tokens required on all forms
  - SQLAlchemy ORM used for all database operations (no raw SQL)
  - Server-side validation of all form inputs
  - Parameterized queries for all database operations
  - Secure session cookies with HttpOnly, Secure, and SameSite flags

### R - Repudiation
- **Threat**: Users may deny their actions:
  - Login attempts
  - Account creation
  - Administrative actions
- **Mitigations**:
  - Comprehensive security logging to security.log including:
    - Timestamps for all events
    - IP addresses for all security events
    - Success/failure status of authentication attempts
    - User creation events
    - Logout events
  - Logs are append-only and centrally stored

### I - Information Disclosure
- **Threat**: Sensitive information may be exposed through:
  - Man-in-the-middle attacks
  - Session cookie theft
  - Error messages
  - Database breaches
- **Mitigations**:
  - HTTPS enforced through Secure cookie flag
  - HttpOnly cookie flag prevents XSS access to session cookie
  - Generic error messages that don't leak user existence
  - Passwords never stored in plaintext (bcrypt hashed)
  - Sensitive data never logged (passwords, tokens)
  - Database access restricted to application only

### D - Denial of Service
- **Threat**: System availability may be impacted by:
  - Brute force login attempts
  - Mass account creation
  - Resource exhaustion
- **Mitigations**:
  - Rate limiting on critical endpoints:
    - Login: 5 attempts per minute
    - Signup: 5 attempts per minute
  - Global rate limits (200/day, 50/hour per IP)
  - Efficient bcrypt work factor (12 rounds) balancing security and performance
  - Database indexes on username and email fields

### E - Elevation of Privilege
- **Threat**: Attackers may attempt to:
  - Access admin features without authorization
  - Modify user roles
  - Bypass authentication checks
- **Mitigations**:
  - Role-based access control (RBAC) implemented
  - Server-side verification of user role for admin access
  - Login required decorator on protected routes
  - Session validation on every request
  - No client-side role determination
  - Logging of unauthorized access attempts

## Additional Security Considerations

### Session Management
- Secure session configuration
- Session cookies are HttpOnly, Secure, and SameSite=Lax
- Session invalidation on logout

### Input Validation
- WTForms validation for all form inputs
- Server-side validation of all data
- Email format validation
- Username and password requirements enforced

### Error Handling
- Generic error messages that don't leak information
- Proper exception handling
- Errors logged for monitoring

### Monitoring and Logging
- Security events logged with timestamps
- IP addresses logged for security events
- Login attempts (success/failure) logged
- Admin access attempts logged
