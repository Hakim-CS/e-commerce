# Product Service

This microservice handles product management, shopping cart operations, and order processing for the e-commerce application.

## Features

- Product listing and management
- Shopping cart operations
- Order processing and history
- Integration with user service for authentication
- Admin panel for product management

## Technologies Used

- Python 3.11
- Flask web framework
- SQLAlchemy ORM
- PostgreSQL database
- Flask-Migrate for database migrations
- Flask-WTF for form handling
- Requests library for service communication

## API Endpoints

### Product Endpoints (Path: /product)

| Method | Path               | Description                    | Role       | Required Permissions |
|--------|-------------------|--------------------------------|------------|----------------------|
| GET    | /product          | List all products              | -          | -                    |
| GET    | /product/{id}     | Get product details            | -          | -                    |
| POST   | /product          | Create a new product           | Admin      | product.create       |
| PUT    | /product/{id}     | Update product                 | Admin      | product.edit         |
| DELETE | /product/{id}     | Delete product (soft delete)   | Admin      | product.delete       |
| GET    | /product/admin    | Admin product management panel | Admin      | product.view         |

### Cart Endpoints (Path: /cart)

| Method | Path                    | Description               | Role       | Required Permissions |
|--------|-----------------------|----------------------------|------------|----------------------|
| GET    | /cart                   | View shopping cart         | -          | -                    |
| POST   | /cart/add/{product_id}  | Add product to cart        | -          | -                    |
| POST   | /cart/update/{item_id}  | Update cart item quantity  | -          | -                    |
| POST   | /cart/remove/{item_id}  | Remove item from cart      | -          | -                    |
| POST   | /cart/clear             | Clear cart                 | -          | -                    |

### Order Endpoints (Path: /order)

| Method | Path                  | Description                | Role       | Required Permissions |
|--------|---------------------|----------------------------|------------|----------------------|
| GET    | /order                | List user's orders         | User       | -                    |
| GET    | /order/{id}           | Get order details          | User       | -                    |
| POST   | /order                | Create order from cart     | User       | -                    |
| GET    | /order/checkout       | Checkout page              | User       | -                    |
| POST   | /order/{id}/cancel    | Cancel an order            | User       | -                    |
| GET    | /order/admin          | Admin order management     | Admin      | order.view           |

## Setup & Run Instructions

### Using Docker

```bash
# Build and run with Docker Compose
docker-compose up --build product_service

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
export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/product_service
export USER_SERVICE_URL=http://localhost:8000
export SESSION_SECRET=sessionsecretsuperkey
export FLASK_APP=main.py

# Run database migrations
flask db upgrade

# Run the application
flask run --host=0.0.0.0 --port=8001
# Or with gunicorn (production)
gunicorn --bind 0.0.0.0:8001 --workers 2 main:app
```

## Sample Products

The service automatically creates sample products on first run:
- Smartphone X Pro
- Wireless Earbuds
- Smart Watch Series 5
- Laptop Pro 15
- Wireless Charging Pad

## Database Schema

The service uses the following main models:
- Product: Stores product information
- Cart: Represents a user's shopping cart
- CartItem: Items in a shopping cart
- Order: Represents a completed purchase
- OrderItem: Items in an order

## Integration with User Service

This service interacts with the User Service for:
- Authentication verification
- User information retrieval
- Role and permission checks

The interaction happens through HTTP requests to the User Service API endpoints.