# rvault

Secure proxy service that handles encryption and access control between users and database storage. While designed to support multiple database backends, currently only MongoDB is implemented.

## Features

- Shamir's Secret Sharing for master key encryption
- Policy-based access control system
- Topic and secret hierarchy
- Secret versioning
- Multiple encryption modes
- JWT-based auth with refresh tokens
- OpenAPI documentation
- MongoDB support (additional databases planned)
- Redis caching with graceful degradation
- Prometheus metrics for monitoring

## Getting Started

1. Clone repo
2. Build docker image of rvault
```bash
docker build -t rvault:0.0.1 .
```
2. Go to `example/` directory
3. Create `.env` file from `.env.sample`
4. Run with Docker:
```bash
docker-compose up -d
```

## Core Components

- **Storage**: Root level, can be sealed/unsealed
- **Topics**: Containers for secrets, support none/generate/provided encryption
- **Secrets**: Versioned items with none/generate/provided encryption modes
- **Auth**: Root token -> admin tokens -> user tokens with policies
- **Cache**: Redis-based caching for frequently accessed data with automatic fallback to MongoDB
- **Monitoring**: Prometheus metrics endpoint for system health tracking

## API Documentation

OpenAPI spec available at `/docs/openapi.yml`

## Environment Variables

| Variable | Description |
|----------|-------------|
| RVAULT_CONFIG | Config file path |
| RVAULT_ROOT_TOKEN | Token for admin access |
| RVAULT_AUTH_SECRET | JWT signing key |
| RVAULT_DEFAULT_TOPIC_KEY | Default topic encryption key |
| RVAULT_DEFAULT_SECRET_KEY | Default secret encryption key |
| RVAULT_DB_TYPE | Database type (mongodb) |
| RVAULT_MONGO_DB_NAME | MongoDB database name |
| RVAULT_MONGO_URI | MongoDB connection string |
| RVAULT_REDIS_URI | Redis connection string |

## Development

### Requirements:
- Rust 1.86+
- MongoDB
- Redis
- Docker & Docker Compose (optional)

### Testing
```bash
make test
```

#### Verbose testing
```bash
make test-verbose
```

### Build
#### Debug
```bash
make build-debug
```

#### Release
```bash
make build-release
```

### Run
#### Debug
```bash
make run-debug
```

#### Release
```bash
make run-release
```
