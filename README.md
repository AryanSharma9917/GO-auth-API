Perfect — below is a **fully rewritten, professional `docs.md`** tailored **specifically** for your `GO-auth-API` project.
You can **copy–paste this directly** into `docs.md`.

---

# Authorization & Authentication API – Documentation

This document provides detailed technical documentation for the **Authorization and Authentication API** built using **Golang**.
The service is designed to handle **secure authentication**, **role-based authorization**, and **organization-level user management** using RESTful principles.

---

## Overview

The API enables users within an organization to authenticate and interact with other users based on their assigned roles.

### Key Capabilities

* JWT-based authentication
* Role-based access control (Admin / User)
* Organization-scoped user isolation
* Secure user lifecycle management
* REST-compliant API design

---

## Authentication Model

The API uses **JSON Web Tokens (JWT)** for authentication.

### Token Flow

1. User logs in using valid credentials
2. Server issues an **access token**
3. Token is sent via `Authorization: Bearer <token>`
4. Middleware validates token for protected routes
5. Token can be refreshed using `/refresh`

---

## Roles & Permissions

| Role  | Permissions                                |
| ----- | ------------------------------------------ |
| User  | View users within own organization         |
| Admin | Create users, delete users, view all users |

> All access is strictly limited to the user’s organization.

---

## API Endpoints

### Public Routes (No Authentication Required)

#### `POST /login`

Authenticate a user and generate a JWT.

**Request Body**

```json
{
  "username": "string",
  "password": "string"
}
```

**Response**

```json
{
  "token": "jwt_token",
  "expires_in": "duration"
}
```

---

#### `POST /logout`

Invalidate the current session.

**Request Body**

```json
{
  "username": "string"
}
```

**Response**

```json
{
  "message": "Successfully logged out"
}
```

---

#### `POST /refresh`

Refresh an existing JWT.

**Request Body**

```json
{
  "username": "string"
}
```

**Response**

```json
{
  "token": "new_jwt_token"
}
```

---

## Protected Routes

All routes below require a valid JWT in the request header:

```
Authorization: Bearer <token>
```

---

### User Routes

#### `GET /`

Retrieve all users in the same organization.

**Access:** User, Admin

**Response**

```json
{
  "users": [
    {
      "username": "string",
      "isAdmin": false,
      "organization": "string"
    }
  ]
}
```

---

### Admin Routes

#### `POST /add`

Create a new user within the organization.

**Access:** Admin only

**Request Body**

```json
{
  "username": "admin_user",
  "newUsername": "string",
  "newPassword": "string",
  "isAdmin": false,
  "organization": "string"
}
```

**Response**

```json
{
  "message": "User created successfully"
}
```

---

#### `POST /delete`

Delete an existing user.

**Access:** Admin only

**Request Body**

```json
{
  "username": "admin_user",
  "delUsername": "string"
}
```

**Response**

```json
{
  "message": "User deleted successfully"
}
```

---

## Error Handling

The API returns standard HTTP status codes:

| Code | Description             |
| ---- | ----------------------- |
| 200  | Success                 |
| 400  | Invalid request payload |
| 401  | Unauthorized            |
| 403  | Forbidden               |
| 404  | Resource not found      |
| 500  | Internal server error   |

Error responses follow this structure:

```json
{
  "error": "error message"
}
```

---

## Security Measures

* Passwords are **hashed before storage**
* JWT verification enforced via middleware
* Admin privileges checked per route
* Organization-level access enforced
* No sensitive data exposed in responses

---

## Configuration

All application-level configuration is defined in:

```
configs/config.go
```

Includes:

* Server port
* MongoDB connection URI
* JWT secret key
* Token expiration duration

---

## Future Improvements

* Password reset functionality
* Rate limiting
* OAuth2 / SSO support
* Audit logging
* Swagger / OpenAPI documentation

---

## Notes

This API is designed to be:

* Modular
* Easily extendable
* Production-ready
* Cloud-deployment friendly
