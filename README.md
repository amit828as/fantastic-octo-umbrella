# Organization Management API

A REST API built with FastAPI for managing organizations and admin authentication.

## Features

- **Organization Creation**: Create organizations with admin users
- **Admin Authentication**: JWT-based login system for organization admins
- **Organization Retrieval**: Get organization details by name
- **Multi-tenant Architecture**: Each organization gets its own isolated database
- **Dockerized Deployment**: Complete containerization for easy deployment

## API Endpoints

- `POST /org/create` - Create a new organization with admin user
- `POST /admin/login` - Admin authentication with JWT token response
- `GET /org/get` - Retrieve organization information by name

## Tech Stack

- **FastAPI** - Modern, fast web framework for APIs
- **SQLAlchemy** - SQL toolkit and ORM
- **PostgreSQL** - Primary database for production
- **JWT** - JSON Web Tokens for authentication
- **Docker** - Containerization and deployment
- **Alembic** - Database migration tool

## Getting Started

### Prerequisites

- Python 3.8+
- PostgreSQL
- Docker (optional)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd organization-management-api

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your database credentials and JWT secret

# Run database migrations
alembic upgrade head

# Start the application
uvicorn app.main:app --reload
```

### Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up --build
```

## Project Structure

```
organization-management-api/
├── app/
│   ├── models/         # Database models
│   ├── schemas/        # Pydantic schemas
│   ├── routers/        # API route handlers
│   ├── database/       # Database configuration
│   └── utils/          # Utility functions
├── alembic/            # Database migrations
├── tests/              # Test files
├── requirements.txt    # Python dependencies
├── Dockerfile         # Docker configuration
└── docker-compose.yml # Multi-service setup
```

## Development

This project follows clean architecture principles with clear separation of concerns.

## License

MIT License 