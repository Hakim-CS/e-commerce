# User Service

This microservice handles user authentication, authorization, and user profile management for the e-commerce application.

## Features

- User authentication (login, logout)
- User registration
- JWT token generation and validation
- Role-based authorization
- User profile management
- Address and contact information management
- Password reset functionality
- Admin panel for user management

## Technologies Used

- Python 3.11
- Flask web framework
- SQLAlchemy ORM
- PostgreSQL database
- Flask-JWT-Extended for JWT authentication
- Flask-Migrate for database migrations
- Flask-WTF for form handling

## API Endpoints

### Authentication Endpoints (Path: /auth)

| Method | Path         | Description             | Role       | Required Permissions |
|--------|--------------|-------------------------|------------|----------------------|
| POST   | /auth/login  | Log in                  | -          | -                    |
| POST   | /auth/logout | Sign out                | User,Admin | -                    |
| GET    | /auth/checkLogin | Token validity check | User,Admin | -                    |

### Authorization Endpoints (Path: /authz)

| Method | Path                   | Description                     | Role       | Required Permissions |
|--------|------------------------|---------------------------------|------------|----------------------|
| GET    | /authz/permissions     | Fetch all permissions of the user | User,Admin | -                    |
| GET    | /authz/hasRole/{role}  | Check if user has a specific role | User,Admin | -                    |
| GET    | /authz/hasPermission/{permission} | Check if user has a specific permission | User,Admin | -     |

### User Endpoints (Path: /user)

| Method | Path                 | Description                  | Role       | Required Permissions |
|--------|----------------------|------------------------------|------------|----------------------|
| GET    | /user                | Get all users                | Admin      | user.view            |
| GET    | /user/{id}           | Get user details             | Admin      | user.view            |
| POST   | /user                | Create new user              | Admin      | user.create          |
| PUT    | /user/{id}           | Update user                  | Admin      | user.edit            |
| DELETE | /user/{id}           | Delete user (soft delete)    | Admin      | user.delete          |
| PUT    | /user/changePassword | Change password (old→new)    | User       | -                    |
| PUT    | /user/resetPassword  | Reset password               | Admin      | user.edit            |
| GET    | /user/profile        | Get logged in user information | User,Admin | -                    |
| PUT    | /user/deactivate/{id}| Deactivate another user      | Admin      | user.edit            |
| PUT    | /user/deactivate     | Deactivate your own account  | User       | -                    |

### Address and Contact Endpoints (Path: /address and /contact)

| Method | Path           | Description          | Role       | Required Permissions |
|--------|----------------|----------------------|------------|----------------------|
| GET    | /address       | List addresses       | User       | address.view         |
| POST   | /address       | Add new address      | User       | address.create       |
| PUT    | /address/{id}  | Update address       | User       | address.edit         |
| DELETE | /address/{id}  | Delete address       | User       | address.delete       |
| GET    | /contact       | List contacts        | User       | contact.view         |
| POST   | /contact       | Add new contact      | User       | contact.create       |
| PUT    | /contact/{id}  | Update contact       | User       | contact.edit         |
| DELETE | /contact/{id}  | Delete contact       | User       | contact.delete       |

## Setup & Run Instructions

### Using Docker

```bash
# Build and run with Docker Compose
docker-compose up --build user_service

# Or for the entire application
docker-compose up --build
```

### Manual Setup

```bash
# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/user_service
export JWT_SECRET_KEY=supersecretkey
export SESSION_SECRET=sessionsecretsuperkey
export FLASK_APP=main.py

# Run database migrations
flask db upgrade

# Run the application
flask run --host=0.0.0.0 --port=8000
# Or with gunicorn (production)
gunicorn --bind 0.0.0.0:8000 --workers 2 main:app
```

## Default Admin Credentials

Username: `admin`  
Password: `admin123`

The admin user has full access to all aspects of the application and is created automatically when the application first runs.

## Database Schema

The service uses the following main models:
- User: Stores user information and credentials
- Role: Defines user roles (admin, user)
- Permission: Defines granular permissions
- Address: Stores user addresses
- Contact: Stores user contact information
- Token: Manages JWT token tracking

## Development

To run migrations when models change:

```bash
flask db migrate -m "Description of changes"
flask db upgrade
```