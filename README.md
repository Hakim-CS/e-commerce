# Microservice-Based E-Commerce Platform

A robust microservices-based e-commerce application designed for scalable online shopping experiences. The platform provides comprehensive user management and product services with a focus on reliability and user interaction.

## Architecture Overview

This application follows a microservice architecture with the following components:

1. **User Service**: Handles user authentication, authorization, and profile management
2. **Product Service**: Manages products, shopping cart operations, and order processing
3. **PostgreSQL Database**: Stores all application data
4. **React Frontend**: Provides the user interface for the application

## Services

### User Service

The User Service manages all aspects of user accounts, including:

- User authentication (login, logout)
- User registration
- JWT token generation and validation
- Role-based authorization
- User profile management
- Address and contact information management
- Password reset functionality
- Admin panel for user management

For more details, see the [User Service README](./user_service/README.md).

### Product Service

The Product Service handles everything related to products and purchasing, including:

- Product listing and management
- Shopping cart operations
- Order processing and history
- Integration with user service for authentication
- Admin panel for product management

For more details, see the [Product Service README](./product_service/README.md).

## Technology Stack

- **Backend**: Flask (Python 3.11)
- **Database**: PostgreSQL
- **ORM**: SQLAlchemy
- **Authentication**: JWT (JSON Web Tokens)
- **Frontend**: React with Bootstrap
- **API Design**: RESTful API
- **Containerization**: Docker

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Git

### Run with Docker Compose

The easiest way to run the entire application is with Docker Compose:

```bash
# Clone the repository
git clone <repository-url>
cd e-commerce

# Start all services
docker-compose up --build
```

After starting the services, you can access:
- User Service API: http://localhost:8000
- Product Service API: http://localhost:8001
- Frontend: http://localhost:3000

### Default Admin Credentials

Username: `admin`  
Password: `admin123`

## API Documentation

### API Endpoints Overview

The application provides several API endpoints across its microservices. Here's a brief overview:

**User Service API:**
- Authentication endpoints (`/auth/*`) 
- Authorization endpoints (`/authz/*`)
- User management endpoints (`/user/*`)
- Address and contact endpoints (`/address/*`, `/contact/*`)

**Product Service API:**
- Product management endpoints (`/product/*`)
- Shopping cart endpoints (`/cart/*`)
- Order management endpoints (`/order/*`)

For detailed API documentation, you can:
1. Refer to the Swagger documentation available at `/api/docs` when running each service
2. Import the Postman collection from the `postman` directory
3. Check the README.md file in each service directory

## Development

### Running Services Individually

To run each service independently during development:

**User Service:**
```bash
cd user_service
pip install -r requirements.txt
export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/user_service
export JWT_SECRET_KEY=supersecretkey
export SESSION_SECRET=sessionsecretsuperkey
export FLASK_APP=main.py
flask run --host=0.0.0.0 --port=8000
```

**Product Service:**
```bash
cd product_service
pip install -r requirements.txt
export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/product_service
export USER_SERVICE_URL=http://localhost:8000
export SESSION_SECRET=sessionsecretsuperkey
export FLASK_APP=main.py
flask run --host=0.0.0.0 --port=8001
```

### Database Migrations

To run migrations when models change:

```bash
cd service_directory
flask db migrate -m "Description of changes"
flask db upgrade
```
