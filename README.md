# LockIn - Secure Authentication System

A secure Flask-based authentication system implementing best practices for web security.

## Features

- User registration and authentication
- Role-based access control
- Security features:
  - bcrypt password hashing
  - CSRF protection
  - Rate limiting
  - Secure session cookies
  - Security event logging
  - Server-side validation
  - Protected routes
  - Generic error messages

## Requirements

- Python 3.8+
- Requirements listed in requirements.txt

## Setup

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   ```bash
   cp .env.example .env
   ```
   Edit .env and set a secure SECRET_KEY (at least 32 bytes)

4. Initialize the database:
   ```bash
   python app.py
   ```

## Running the Application

1. Make sure your virtual environment is activated
2. Run the Flask application:
   ```bash
   python app.py
   ```
3. Visit http://localhost:5000 in your browser

## Security Features

See threat_model.md for a comprehensive analysis of security features and mitigations.

## Directory Structure

```
├── app.py              # Main application file
├── models.py           # Database models
├── forms.py            # WTForms definitions
├── requirements.txt    # Python dependencies
├── security.log        # Security event logs
├── users.db           # SQLite database
├── .env               # Environment variables
└── templates/         # HTML templates
    ├── base.html
    ├── home.html
    ├── login.html
    ├── signup.html
    ├── profile.html
    └── admin.html
```

## Security Considerations

- All passwords are hashed using bcrypt
- CSRF protection on all forms
- Rate limiting on authentication endpoints
- Secure session configuration
- Comprehensive security logging
- Role-based access control
- Server-side validation
- Generic error messages
- Protected routes with login_required

## Contributing

This is an MVP implementation. Feel free to contribute by implementing stretch goals:

- Password reset functionality
- Email verification
- Account locking after failed attempts
- 2FA TOTP
- CSP/HSTS headers
