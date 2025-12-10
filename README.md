# Fortify Auth

A secure end-to-end authentication module built with Nest.js, featuring advanced security practices, token rotation, multi-session management, and comprehensive user flows. This project demonstrates enterprise-level authentication patterns with a focus on security, scalability, and maintainability.

Designed as a learning project to explore modern authentication architecture, this system implements industry-standard security measures including Argon2 password hashing, JWT-based token management with automatic rotation, multi-device session handling, and comprehensive audit logging. The codebase emphasizes clean architecture principles, type safety with TypeScript, and defensive programming practices to handle edge cases and security threats.

### Hybrid Token-Session Authentication

This implementation uses a **hybrid token-session authentication model** that combines the best of both worlds. Access tokens are JWT-based for stateless API authentication, allowing for fast verification without database lookups on every request. However, each JWT is tied to a database-backed session that stores a hashed refresh token, device information, and metadata—enabling powerful server-side controls that pure JWT systems lack.

The hybrid approach provides significant advantages: refresh tokens are stored securely in the database (not in JWTs), enabling immediate revocation when needed; sessions can be managed with concurrent limits and automatic cleanup; and detailed audit trails track every login attempt, device, and IP address. This architecture delivers the performance benefits of stateless JWTs for frequent API calls while maintaining the security and administrative control of session-based systems, including token rotation, forced logouts, and real-time session monitoring.

## Architecture

Fortify Auth is designed with a **modular, secure, and scalable architecture** using Nest.js and TypeScript. The system combines stateless JWT authentication with stateful session management for enhanced security and control.

### Authentication Flow

```
Registration → Email Verification → Login → Session Creation → Access/Refresh Tokens
```

- **Registration**: Users create an account and verify their email via OTP.
- **Login**: Credentials are verified, and a new session is created.
- **Session**: Stores device info, IP, user agent, and refresh token hash. Limits concurrent sessions per user.
- **Tokens**: Short-lived access tokens (JWT) and long-lived refresh tokens (rotating) manage secure API access.

### Hybrid Token-Session Model

- **Access Token**: Stateless JWT stored in an HTTP-only cookie.
- **Refresh Token**: Stored hashed in the database for rotation and revocation.
- **Benefits**:
  - Fast API verification with JWTs.
  - Full server-side session control.
  - Forced logouts and automatic session cleanup.

### Session Management

- Tracks device, IP, and user agent per session.
- Limits maximum concurrent sessions per user.

### Security Considerations

- Argon2 password hashing.
- Rotating tokens with timing-safe comparisons.
- Device fingerprints and IP logging.
- CSRF protection
- Rate limiting

### Modular Design

- **Auth Module**: Handles registration, login, password resets, token rotation.
- **OTP Module**: Secure OTP generation and validation.
- **Email Module**: Sends verification and notification emails.
- **Prisma Module**: Database access and schema management.

## Features

### Core Authentication

- **User Registration** with email verification
- **Secure Login** with password hashing (Argon2)
- **JWT access tokens** with session-based **refresh token rotation**
- **Token rotation** with refresh token invalidation
- **Password Reset Flow** with OTP verification
- **Email Notifications** for all critical actions

### Security Features

- **Account Lockout** after multiple failed login attempts
- **Session Management** with configurable concurrent session limits
- **Device Tracking** (IP address, user agent, device info)
- **Timing-Safe Token Comparison** to prevent timing attacks
- **Secure Cookie Handling** (HttpOnly, SameSite, Secure flags)
- **OTP System** with expiration and single-use enforcement
- **Login Activity Tracking** for audit trails
- **CSRF Protection** to prevent cross-site request forgery attacks
- **Rate Limiting** to mitigate brute-force and abuse attempts

### User Experience

- Email verification before account activation
- Password reset via secure OTP
- Multiple active sessions support
- Automatic session cleanup
- Detailed error messages with remaining attempts

## Tech Stack

- **Framework**: Nest.js
- **Language**: TypeScript
- **Database**: PostgreSQL
- **ORM**: Prisma
- **Authentication**: Passport.js + JWT
- **Password Hashing**: Argon2
- **Email Service**: Nodemailer
- **Device Detection**: ua-parser-js

## Security Implementation

### Password Security

- Hashed with Argon2 (memory-hard algorithm)
- No plaintext password storage

### Account Protection

- Configurable failed login attempt threshold
- Temporary account lockout duration
- Automatic unlock after cooldown period

### Token Security

- Short-lived access tokens
- Refresh token rotation on every use
- SHA-256 hashing for refresh tokens
- Timing-safe comparison to prevent timing attacks

### Session Security

- HTTP-only cookies (JavaScript cannot access)
- Secure flag in production
- SameSite protection against CSRF
- Device fingerprinting
- IP address tracking

### OTP Security

- 6-digit cryptographically secure codes
- 5-minute expiration window
- Single-use enforcement
- Argon2 hashing for storage
- Automatic invalidation of previous codes

### Rate Limiting

- Limit repeated requests to endpoints
- Prevents brute-force attacks and abuse

## Project Structure

```
fortify-auth-api/
├── prisma/
│   ├── migrations/              # Database migration files
│   └── schema.prisma            # Database schema definition
├── src/
│   ├── auth/
│   │   ├── decorators/          # Custom parameter decorators
│   │   ├── dto/                 # Data transfer objects
│   │   ├── guards/              # Route protection guards
│   │   ├── strategies/          # Authentication strategies
│   │   ├── types/               # TypeScript type definitions
│   │   ├── auth.controller.ts   # Authentication endpoints
│   │   ├── auth.service.ts      # Authentication business logic
│   │   └── auth.module.ts       # Auth module configuration
│   ├── otp/
│   │   ├── otp.service.ts       # OTP generation and validation
│   │   └── otp.module.ts        # OTP module configuration
│   ├── email/
│   │   ├── types/               # Email-related types
│   │   ├── email.service.ts     # Email sending service
│   │   └── email.module.ts      # Email module configuration
│   ├── prisma/
│   │   ├── prisma.service.ts    # Prisma client wrapper
│   │   └── prisma.module.ts     # Prisma module configuration
│   ├── generated/
│   │   └── prisma/              # Prisma generated client
│   ├── app.controller.ts        # Root controller
│   ├── app.service.ts           # Root service
│   ├── app.module.ts            # Root module
│   └── main.ts                  # Application entry point
```

## Getting Started

### Prerequisites

- Node.js: v18 (LTS) or higher
- PostgreSQL database
- npm: v9 or higher (comes with Node 18+)

### Installation

1. Clone the repository

```bash
git clone https://github.com/Jeyaprabakar01/fortify-auth-api.git
cd fortify-auth-api
```

2. Install dependencies

```bash
npm install
```

3. Create a .env file

```env
# Application
NODE_ENV="development"
WEB_APP_URL="http://localhost:3000"

# Database
DATABASE_URL="postgresql://user:password@localhost:5432/authdb"

# JWT Configuration
JWT_SECRET="your-super-secret-jwt-key"
JWT_EXPIRY=15m

# Token Configuration
ACCESS_TOKEN_MAXAGE=15    # minutes
REFRESH_TOKEN_MAXAGE=7    # days

# Session Configuration
SESSION_EXPIRY=7           # days
SESSION_MAX_CONCURRENT=5

# Account Lock Configuration
ACCOUNT_LOCK_MAX_ATTEMPTS=5
ACCOUNT_LOCK_DURATION=15   # minutes

# Email Configuration (configure based on your provider)
SMTP_HOST="smtp.example.com"
SMTP_PORT=465
SMTP_USER="your-email@example.com"
SMTP_PASS="your-email-password"
```

4. Run database migrations

```bash
npx prisma migrate dev
```

5. Start the development server

```bash
npm run start:dev
```

## API Endpoints

### Public Endpoints

#### Register User

```http
POST /auth/register
Content-Type: application/json

{
  "fullName": "John Doe",
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

#### Verify Email

```http
POST /auth/verify-email
Content-Type: application/json

{
  "email": "john@example.com",
  "otpCode": "123456"
}
```

#### Login

```http
POST /auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

#### Request Password Reset

```http
POST /auth/reset-password
Content-Type: application/json

{
  "email": "john@example.com"
}
```

#### Update Password

```http
POST /auth/update-password
Content-Type: application/json

{
  "email": "john@example.com",
  "otpCode": "123456",
  "password": "NewSecurePass123!"
}
```

#### Refresh Access Token

```http
POST /auth/refresh
Cookie: refresh_token=<token>
```

### Protected Endpoints

#### Logout

```http
POST /auth/logout
Cookie: access_token=<token>
Authorization: Bearer <token>
```

## Future Enhancements

- [ ] Two-Factor Authentication (2FA) via email/authenticator app
- [ ] Social OAuth integration (Google)
- [ ] Remember device functionality
- [ ] Suspicious activity detection and alerts
- [ ] Email notification for new device login
- [ ] Password history to prevent reuse
- [ ] Account self-deletion with confirmation
- [ ] Magic link authentication (passwordless login)
- [ ] Backup codes for account recovery
- [ ] Session timeout based on inactivity

## Contributing

This is a practice project, but feedback and suggestions are welcome! Feel free to:

- Report bugs
- Suggest new features
- Submit pull requests
- Share security concerns

**Note**: This is a practice project demonstrating secure authentication patterns. While it implements industry-standard security practices, please conduct a thorough security audit before using in production environments.

