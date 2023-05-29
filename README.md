# Authorization and Authentication API in Golang
This is a backend API service in Golang that handles authorization and authentication for a web app where users in an organization can sign in and list all other users in their organization. The API follows REST API conventions and covers the following functionalities:

- User Login
- User Logout
- Admin User adds a new User account (by providing the username & password)
- Admin User deletes an existing User account from their organization
- List all Users in their organization

## Setup
### Prerequisites

- Prerequisites
- Go 1.16 or later
- MongoDB 4.4 or later
- Postman or any API development environment

### Installation


#### Clone the repository
```
$ git clone https://github.com/<username>/<repository>.git
$ cd <repository>
```
#### Install dependencies
```
$ go mod tidy
```
#### Setup environment variables
- Switch to the `/configs/config.go` and set the values for your desired variables.

#### Run the API
```
$ go run main.go
```
The API will be available at `http://localhost:<configs.Cfg.Port>`. (Set the value for the Port according to your own requirement.)


## Design Decisions

#### Framework
I chose to use the Echo framework for this project due to its simplicity, performance, and ease of use. Echo is a lightweight web framework that provides a minimalistic approach to building web applications and APIs.

#### Database
I chose MongoDB as the database for this project due to its flexibility, scalability, and ease of use. MongoDB is a document-oriented NoSQL database that allows for easy data modeling and flexible data structures.

#### ORM
I decided not to use an ORM for this project due to the simplicity of the data model and the limited number of database operations required by the API. Instead, I used the official MongoDB driver for Go to interact with the database.

#### JWT
For JWT token generation, I used the golang-jwt library, which provides a simple and easy-to-use interface for generating and verifying JWT tokens.


## API Design

I followed REST API conventions for designing the API endpoints and used HTTP methods and status codes to represent the different actions and outcomes of the API requests. I also used middleware to handle authentication and authorization and to enforce input validation and error handling. This API consists of the following routes:


##### Public Routes

-  `POST /login` - For logging in an user
    Paramenters: `username`, `password`
-  `POST /logout` - For logginf out an user
    Parameters: `username`, `password`
-  `POST /refresh` - For refreshing a token
    Parameters: `username`, `passowrd`
##### User Routes
-  `GET /` - For getting all users in an organization
    Parameters- `username`
##### Admin Routes
-  `POST /add` - For adding one user to the organization
    Parameters- `username`, `newUsername`, `newPassword`, `isAdmin`, `organization`
-  `POST /delete` - For deleting a user from the organization
    Parameters- `username`, `delUsername`

