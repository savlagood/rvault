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

## Getting Started

1. Clone repo
2. Create `.env` file from `.env.sample`
3. Run with Docker:
```bash
docker-compose up -d
```

## Core Components

- **Storage**: Root level, can be sealed/unsealed
- **Topics**: Containers for secrets, support none/generate/provided encryption
- **Secrets**: Versioned items with none/generate/provided encryption modes
- **Auth**: Root token -> admin tokens -> user tokens with policies
- **Cache**: Redis-based caching for frequently accessed data with automatic fallback to MongoDB

## API Usage

```bash
# Get admin token
curl -X POST http://localhost:9200/api/auth/token/issue/admin \
  -d '{"token":"ROOT_TOKEN"}'

# Initialize storage
curl -X POST http://localhost:9200/api/storage/init \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -d '{"threshold": 3, "total_keys": 5}'

# Unseal storage
curl -X POST http://localhost:9200/api/storage/unseal \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -d '{"shares":["key1","key2","key3"]}'
```

Full API docs in `/docs/openapi.yml`

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

### Build
```bash
make build-release
```

### Run
```bash
make run-release
```

## API Documentation

OpenAPI spec available at `/docs/openapi.yml`
