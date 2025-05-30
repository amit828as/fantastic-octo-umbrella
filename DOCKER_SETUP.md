# Docker Setup Guide

This document provides instructions for setting up and running the Organization Management API using Docker and Docker Compose.

## Prerequisites

- Docker Engine 20.10 or later
- Docker Compose 2.0 or later

## Environment Configuration

### 1. Create Environment File

Copy the example environment file and customize it:

```bash
cp docker.env.example .env
```

### 2. Environment Variables

The following environment variables can be configured in your `.env` file:

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTGRES_DB` | PostgreSQL database name | `org_management` |
| `POSTGRES_USER` | PostgreSQL username | `postgres` |
| `POSTGRES_PASSWORD` | PostgreSQL password | `postgres_docker_password` |
| `POSTGRES_PORT` | PostgreSQL port (host) | `5432` |
| `API_PORT` | FastAPI port (host) | `8000` |
| `JWT_SECRET_KEY` | JWT signing secret | **Change in production!** |
| `JWT_ALGORITHM` | JWT algorithm | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token expiration time | `30` |

### 3. Security Notes

- **Always change `JWT_SECRET_KEY`** in production
- Use strong passwords for `POSTGRES_PASSWORD`
- Consider using Docker secrets for production deployments

## Running the Application

### Development Mode (with live reload)

```bash
# Start all services
docker-compose up

# Start in background
docker-compose up -d

# View logs
docker-compose logs -f
```

### Production Mode

For production, modify the `docker-compose.yml`:

1. Remove the volume mount: `- .:/app`
2. Change command to: `["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]`
3. Set appropriate environment variables

### Database Migrations

Migrations run automatically via the `migrate` service. To run manually:

```bash
docker-compose run --rm migrate
```

## Service Management

### Individual Services

```bash
# Start only database
docker-compose up db

# Start API (after database is ready)
docker-compose up api

# Run migrations
docker-compose run --rm migrate
```

### Stopping Services

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (WARNING: deletes data)
docker-compose down -v
```

## Accessing the Application

- **API Documentation**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc
- **Health Check**: http://localhost:8000/health
- **Database**: localhost:5432 (if port is exposed)

## Troubleshooting

### Common Issues

1. **Port conflicts**: Change `API_PORT` or `POSTGRES_PORT` in `.env`
2. **Database connection errors**: Ensure PostgreSQL service is healthy
3. **Permission errors**: Check Docker permissions and file ownership

### Checking Service Health

```bash
# View service status
docker-compose ps

# Check service logs
docker-compose logs db
docker-compose logs api

# Access container shell
docker-compose exec api bash
docker-compose exec db psql -U postgres -d org_management
```

### Rebuilding Services

```bash
# Rebuild API image
docker-compose build api

# Rebuild and restart
docker-compose up --build
```

## Data Persistence

- Database data is stored in the `postgres_data` named volume
- Data persists between container restarts
- To reset database: `docker-compose down -v` (WARNING: deletes all data)

## Network Configuration

All services communicate via the `app-network` bridge network:
- Database accessible at `db:5432` from API container
- API accessible at `api:8000` from other containers 