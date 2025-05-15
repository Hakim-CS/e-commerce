# E-Commerce Frontend

This is the frontend application for the microservices-based e-commerce platform. It provides a user interface for interacting with the user service and product service.

## Features

- User authentication (login/logout)
- Product browsing
- Shopping cart management
- Order placement and management
- User profile management

## Technologies Used

- React 18
- Bootstrap 5
- Docker
- Nginx (for production)

## Setup & Run Instructions

### Using Docker

```bash
# Build and run with Docker Compose
docker-compose up --build frontend

# Or for the entire application
docker-compose up --build
```

### Manual Development Setup

```bash
# Install dependencies
npm install

# Start development server
npm start
```

## API Integration

The frontend integrates with two microservices:

1. **User Service**: Handles user authentication, authorization, and profile management
2. **Product Service**: Handles product catalog, shopping cart, and order management

The integration is done through the `api.js` file, which provides methods for interacting with both services. The API client handles:

- Authentication with JWT tokens
- Token refresh when expired
- Error handling
- Service discovery

## Environment Variables

The following environment variables can be set to configure the application:

- `REACT_APP_USER_SERVICE_URL`: URL for the user service (default: http://localhost:8000)
- `REACT_APP_PRODUCT_SERVICE_URL`: URL for the product service (default: http://localhost:8001)

## Project Structure

- `src/components/`: React components
- `src/api.js`: API client for microservices
- `public/`: Static assets
- `Dockerfile`: Docker configuration for production
- `nginx.conf`: Nginx configuration for production

## Production Deployment

For production deployment, the application is built as a static site and served through Nginx. The Nginx configuration provides reverse proxy capabilities to route API requests to the appropriate microservices.