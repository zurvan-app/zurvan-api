# 🧠 Zurvan API

The **Zurvan API** is the core backend service powering the [Zurvan](https://github.com/zurvan-app) ecosystem — a cross-platform, AI-powered productivity suite designed to help users plan, track, and improve their daily life.

Built with **Golang**, it provides a modular architecture supporting:
- **User authentication** with JWT tokens and email verification
- Task and habit management
- AI-driven planning and insights
- Real-time synchronization across all platforms

## ⚙️ Tech Stack

| Layer | Technology |
|-------|-------------|
| Language | Go (v1.25+) |
| Framework | GraphQL (gqlgen) |
| Database | PostgreSQL |
| Authentication | JWT + Email Verification |
| Architecture | Clean Architecture |
| Password Hashing | bcrypt |

## 🚀 Quick Start

### Prerequisites

- Go 1.25 or higher (for local development)
- PostgreSQL database (for local development)
- Docker and Docker Compose (recommended)
- Git

### Option 1: Docker Setup (Recommended)

#### Development Environment

```bash
# Clone the repository
git clone https://github.com/zurvan-app/zurvan-api.git
cd zurvan-api

# Start development environment
./scripts/dev-start.sh

# Or manually:
cp .env.development .env
docker-compose up --build
```

**Development Services:**
- API: `http://localhost:8080`
- GraphQL Playground: `http://localhost:8080/`
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`
- pgAdmin (optional): `http://localhost:5050` (admin@zurvan.local / admin)

#### Production Environment

```bash
# Create production environment file
cp .env.production .env
# Edit .env with your production settings

# Start production environment
./scripts/prod-start.sh

# Or manually:
docker-compose -f docker-compose.prod.yml up --build -d
```

**Production Features:**
- SSL termination with Let's Encrypt
- Nginx reverse proxy with rate limiting
- Redis with authentication
- Database backups
- Optional monitoring (Prometheus + Grafana)

### Option 2: Local Development

```bash
# Clone the repository
git clone https://github.com/zurvan-app/zurvan-api.git
cd zurvan-api

# Setup environment
cp .sample.env .env
# Edit .env with your database credentials

# Install dependencies
go mod download

# Setup database
createdb zurvan
go run cmd/setup/main.go

# Start the server
go run server.go
```

### Docker Commands

```bash
# Development
docker-compose up -d                    # Start all services
docker-compose logs -f app              # View API logs
docker-compose exec postgres psql -U postgres -d zurvan  # Access database
docker-compose down                     # Stop all services

# Production
docker-compose -f docker-compose.prod.yml up -d         # Start production
docker-compose -f docker-compose.prod.yml logs -f app   # View logs
./scripts/backup.sh                     # Create database backup

# Optional services
docker-compose --profile tools up -d pgadmin           # Development tools
docker-compose --profile monitoring up -d              # Production monitoring
docker-compose --profile ssl run --rm certbot          # Setup SSL
```

## 📋 API Documentation

### Authentication Flow

#### 1. Register a New User

```graphql
mutation Register {
  register(input: {
    email: "user@example.com"
    password: "securepassword123"
  })
}
```

**Response:** Success message with instruction to check email for verification code.

#### 2. Verify Email

```graphql
mutation VerifyEmail {
  verifyEmail(input: {
    email: "user@example.com"
    code: "123456"
  })
}
```

**Note:** In development, verification codes are logged to console.

#### 3. Login

```graphql
mutation Login {
  login(input: {
    email: "user@example.com"
    password: "securepassword123"
  }) {
    user {
      id
      email
      isVerified
      createdAt
    }
    accessToken
    refreshToken
    expiresIn
  }
}
```

#### 4. Refresh Token

```graphql
mutation RefreshToken {
  refreshToken(input: {
    refreshToken: "your_refresh_token"
  }) {
    user {
      id
      email
    }
    accessToken
    refreshToken
    expiresIn
  }
}
```

#### 5. Resend Verification Code

```graphql
mutation ResendVerification {
  resendVerificationCode(input: {
    email: "user@example.com"
  })
}
```

### Additional Mutations

- `me` query (requires authentication)

## 🏗️ Architecture

The project follows **Clean Architecture** principles:

```
zurvan-api/
├── feature/auth/              # Authentication feature
│   ├── domain/                # Business logic & interfaces
│   │   ├── models/            # Domain entities
│   │   └── repositories/      # Repository interfaces
│   ├── application/           # Use cases & business rules
│   │   └── usecases/         # Authentication use cases
│   └── infrastructure/        # External concerns
│       └── repositories/      # Database implementations
├── graph/                     # GraphQL layer
│   ├── schema.graphqls       # GraphQL schema
│   ├── schema.resolvers.go   # GraphQL resolvers
│   └── model/                # Generated GraphQL models
├── config/                    # Configuration management
├── migrations/                # Database migrations
└── cmd/                      # CLI commands
```

### Key Components

- **Domain Layer**: Contains business entities (`User`, `EmailVerification`) and repository interfaces
- **Application Layer**: Implements business use cases (register, login, verify email, etc.)
- **Infrastructure Layer**: Concrete implementations (PostgreSQL repositories)
- **Presentation Layer**: GraphQL resolvers and schema

## 🔐 Security Features

- **Password Hashing**: bcrypt with salt
- **JWT Tokens**: HS256 algorithm with configurable expiration
- **Email Verification**: 6-digit codes with 15-minute expiry
- **Input Validation**: Comprehensive validation on all inputs
- **SQL Injection Protection**: Parameterized queries
- **Token Refresh**: Secure token refresh mechanism

## 🗄️ Database Schema

### Users Table
```sql
- id (UUID, PK)
- email (VARCHAR, UNIQUE)
- password_hash (TEXT)
- is_verified (BOOLEAN)
- created_at (TIMESTAMP)
- updated_at (TIMESTAMP)
- last_login_at (TIMESTAMP, NULLABLE)
```

### Email Verifications Table
```sql
- id (UUID, PK)
- user_id (UUID, FK)
- email (VARCHAR)
- verification_code (VARCHAR(6))
- expires_at (TIMESTAMP)
- is_used (BOOLEAN)
- created_at (TIMESTAMP)
- updated_at (TIMESTAMP)
```

## 🛠️ Development

### Project Structure

The authentication feature is implemented using Clean Architecture:

1. **Domain Models**: `feature/auth/domain/models/`
2. **Repository Interfaces**: `feature/auth/domain/repositories/`
3. **Use Cases**: `feature/auth/application/usecases/`
4. **Infrastructure**: `feature/auth/infrastructure/repositories/`

### Adding New Features

1. Create feature directory: `feature/new-feature/`
2. Implement domain models and repository interfaces
3. Create use cases in application layer
4. Implement repositories in infrastructure layer
5. Add GraphQL schema and resolvers
6. Update server.go with dependency injection

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `8080` |
| `DB_HOST` | Database host | `localhost` |
| `DB_PORT` | Database port | `5432` |
| `DB_USER` | Database user | `postgres` |
| `DB_PASSWORD` | Database password | `` |
| `DB_NAME` | Database name | `zurvan` |
| `DB_SSL_MODE` | SSL mode | `disable` |
| `JWT_SECRET` | JWT signing secret | `your-super-secret...` |
| `JWT_ACCESS_TOKEN_TTL` | Access token TTL | `15m` |
| `JWT_REFRESH_TOKEN_TTL` | Refresh token TTL | `168h` |

## 📝 TODO

- [ ] Add middleware for JWT authentication
- [ ] Implement email service integration
- [ ] Add rate limiting
- [ ] Add logging middleware
- [ ] Add metrics and monitoring
- [ ] Add API documentation
- [ ] Add unit tests
- [ ] Add integration tests
- [ ] Add Docker support

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add some amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.