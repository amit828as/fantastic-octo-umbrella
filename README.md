# Organization Management API

A FastAPI-based REST API for managing organizations with admin authentication, dynamic database creation, and JWT token-based security.

## Table of Contents

- [Organization Management API](#organization-management-api)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Quick Start](#quick-start)
    - [Using Docker (Recommended)](#using-docker-recommended)
    - [Local Development](#local-development)
  - [Installation](#installation)
    - [Local Development](#local-development-1)
    - [Docker Deployment](#docker-deployment)
  - [API Endpoints](#api-endpoints)
    - [Organization Management](#organization-management)
      - [Create Organization](#create-organization)
      - [Get Organization](#get-organization)
    - [Authentication](#authentication)
      - [Admin Login](#admin-login)
      - [Protected Endpoint Access](#protected-endpoint-access)
  - [Usage Examples](#usage-examples)
    - [Complete Workflow](#complete-workflow)
    - [Python Client Example](#python-client-example)
  - [Environment Configuration](#environment-configuration)
    - [Required Environment Variables](#required-environment-variables)
    - [Docker Environment Variables](#docker-environment-variables)
  - [Database Management](#database-management)
    - [Migrations](#migrations)
    - [Database Structure](#database-structure)
  - [Testing](#testing)
    - [Run Tests](#run-tests)
    - [Test Categories](#test-categories)
  - [API Documentation](#api-documentation)
    - [Interactive Documentation](#interactive-documentation)
    - [Health Checks](#health-checks)
    - [Error Handling](#error-handling)

## Features

- 🏢 **Organization Management**: Create and retrieve organizations with dynamic database allocation
- 🔐 **JWT Authentication**: Secure admin login with token-based authentication
- 🗄️ **Dynamic Databases**: Automatic creation of isolated databases per organization
- 🐳 **Docker Support**: Complete containerization with docker-compose
- 📊 **Health Monitoring**: Comprehensive health checks for all services
- 🧪 **Testing Suite**: Extensive test coverage with pytest
- 📚 **API Documentation**: Auto-generated docs with FastAPI/OpenAPI

## Quick Start

### Using Docker (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd fantastic-octo-umbrella

# Copy environment configuration
cp docker.env.example .env

# Start all services
docker-compose up -d

# Access the API documentation
open http://localhost:8000/docs
```

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env

# Run database migrations
alembic upgrade head

# Start the development server
uvicorn app.main:app --reload
```

## Installation

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd fantastic-octo-umbrella
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your database credentials
   ```

5. **Run database migrations**
   ```bash
   alembic upgrade head
   ```

6. **Start the server**
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

### Docker Deployment

1. **Copy environment configuration**
   ```bash
   cp docker.env.example .env
   ```

2. **Start services**
   ```bash
   docker-compose up -d
   ```

3. **View logs**
   ```bash
   docker-compose logs -f
   ```

4. **Stop services**
   ```bash
   docker-compose down
   ```

For detailed Docker instructions, see [DOCKER_SETUP.md](DOCKER_SETUP.md).

## API Endpoints

### Organization Management

#### Create Organization
```http
POST /api/v1/org/create
Content-Type: application/json

{
  "email": "admin@acmecorp.com",
  "password": "SecurePassword123!",
  "organization_name": "Acme Corporation"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Organization created successfully",
  "organization_id": 1,
  "organization_name": "Acme Corporation",
  "admin_email": "admin@acmecorp.com"
}
```

#### Get Organization
```http
GET /api/v1/org/get?organization_name=Acme Corporation
```

**Response:**
```json
{
  "success": true,
  "organization_id": 1,
  "organization_name": "Acme Corporation",
  "admin_email": "admin@acmecorp.com",
  "created_at": "2025-01-30T08:00:00Z"
}
```

### Authentication

#### Admin Login
```http
POST /api/v1/auth/admin/login
Content-Type: application/json

{
  "email": "admin@acmecorp.com",
  "password": "SecurePassword123!"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "admin_id": 1,
  "email": "admin@acmecorp.com",
  "organization_id": 1,
  "organization_name": "Acme Corporation"
}
```

#### Protected Endpoint Access
```http
GET /api/v1/auth/me
Authorization: Bearer <your-jwt-token>
```

## Usage Examples

### Complete Workflow

1. **Create an organization**
   ```bash
   curl -X POST "http://localhost:8000/api/v1/org/create" \
        -H "Content-Type: application/json" \
        -d '{
          "email": "admin@tech-corp.com",
          "password": "SecurePass123!",
          "organization_name": "Tech Corporation"
        }'
   ```

2. **Login as admin**
   ```bash
   curl -X POST "http://localhost:8000/api/v1/auth/admin/login" \
        -H "Content-Type: application/json" \
        -d '{
          "email": "admin@tech-corp.com",
          "password": "SecurePass123!"
        }'
   ```

3. **Use the JWT token for authenticated requests**
   ```bash
   curl -X GET "http://localhost:8000/api/v1/auth/me" \
        -H "Authorization: Bearer <your-jwt-token>"
   ```

4. **Retrieve organization information**
   ```bash
   curl "http://localhost:8000/api/v1/org/get?organization_name=Tech Corporation"
   ```

### Python Client Example

```python
import requests

# Create organization
response = requests.post(
    "http://localhost:8000/api/v1/org/create",
    json={
        "email": "admin@example.com",
        "password": "SecurePassword123!",
        "organization_name": "Example Corp"
    }
)
print(response.json())

# Login
login_response = requests.post(
    "http://localhost:8000/api/v1/auth/admin/login",
    json={
        "email": "admin@example.com",
        "password": "SecurePassword123!"
    }
)
token = login_response.json()["access_token"]

# Access protected resource
headers = {"Authorization": f"Bearer {token}"}
user_info = requests.get(
    "http://localhost:8000/api/v1/auth/me",
    headers=headers
)
print(user_info.json())
```

## Environment Configuration

### Required Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Master database connection string | `postgresql://...` |
| `JWT_SECRET_KEY` | Secret key for JWT tokens | **Change in production!** |
| `JWT_ALGORITHM` | JWT algorithm | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token expiration time | `30` |

### Docker Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTGRES_DB` | PostgreSQL database name | `org_management` |
| `POSTGRES_USER` | PostgreSQL username | `postgres` |
| `POSTGRES_PASSWORD` | PostgreSQL password | `postgres_docker_password` |
| `API_PORT` | FastAPI port (host) | `8000` |

## Database Management

### Migrations

```bash
# Create a new migration
alembic revision --autogenerate -m "Description of changes"

# Apply migrations
alembic upgrade head

# Rollback to previous migration
alembic downgrade -1

# View migration history
alembic history
```

### Database Structure

- **Master Database**: Stores organization metadata and admin users
- **Dynamic Databases**: One per organization, contains organization-specific data

## Testing

### Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app

# Run specific test file
pytest tests/test_organization_endpoint.py

# Run tests with verbose output
pytest -v
```

### Test Categories

- **Unit Tests**: Individual component testing
- **Integration Tests**: API endpoint testing
- **Authentication Tests**: JWT and security testing
- **Database Tests**: Data persistence and migration testing

## API Documentation

### Interactive Documentation

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Health Checks

- **Application Health**: http://localhost:8000/health
- **Database Health**: Included in main health endpoint

### Error Handling

The API returns consistent error responses:

```json
{
  "detail": {
    "error": "Error Type",
    "message": "Detailed error message",
    "error_type": "error_category"
  }
}
```

Common HTTP status codes:
- `200`: Success
- `201`: Created
- `400`: Bad Request
- `401`: Unauthorized
- `404`: Not Found
- `409`: Conflict (duplicate data)
- `422`: Validation Error
- `500`: Internal Server Error
