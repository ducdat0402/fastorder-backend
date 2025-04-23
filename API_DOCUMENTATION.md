# FastOrder API Documentation

Base URL: `http://localhost:3000/api`

## Authentication
- **POST /register**
  - Body: `{name, email, password, phone}`
  - Response: `{token, user: {id, name, email, phone, role}}`
- **POST /login**
  - Body: `{email, password}`
  - Response: `{token, user: {id, name, email, role}}`

## Categories
- **GET /categories**
  - Response: `[{id, name}]`
- **POST /categories** (Admin only)
  - Headers: `Authorization: Bearer <token>`
  - Body: `{name}`
  - Response: `{id, name}`

## Food
- **GET /foods**
  - Query: `?category_id=<id>` (optional)
  - Response: `[{id, name, description, price, img_url, is_available, category_id, category_name}]`
- **POST /foods** (Admin only)
  - Headers: `Authorization: Bearer <token>`
  - Body: `{name, description, price, img_url, is_available, category_id}`
  - Response: `{id, name, description, price, img_url, is_available, category_id}`
- **PUT /foods/:id** (Admin only)
  - Headers: `Authorization: Bearer <token>`
  - Body: `{name, description, price, img_url, is_available, category_id}`
  - Response: `{id, name, description, price, img_url, is_available, category_id}`
- **DELETE /foods/:id** (Admin only)
  - Headers: `Authorization: Bearer <token>`
  - Response: `{message: "Food deleted successfully"}`

## Orders
- **POST /orders**
  - Headers: `Authorization: Bearer <token>`
  - Body: `{items: [{food_id, quantity}]}`
  - Response: `{order_id, total_price, status, ticket_code}`
- **GET /orders**
  - Headers: `Authorization: Bearer <token>`
  - Response: `[{id, user_id, total_price, status, created_at, ticket_code, items: [{id, order_id, food_id, quantity, unit_price, name}]}]`

## Payments
- **POST /payments**
  - Headers: `Authorization: Bearer <token>`
  - Body: `{order_id, method, amount}`
  - Response: `{payment_id, order_id, amount, method, status, transaction_id}`

## Tickets
- **GET /tickets/:order_id**
  - Headers: `Authorization: Bearer <token>`
  - Response: `{id, order_id, ticket_code, issued_at}`