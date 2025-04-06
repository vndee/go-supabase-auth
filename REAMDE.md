# Go Supabase Auth SDK

A comprehensive authentication SDK for Supabase in Go, providing both client and admin functionality.

[![Go Reference](https://pkg.go.dev/badge/github.com/vndee/go-supabase-auth.svg)](https://pkg.go.dev/github.com/vndee/go-supabase-auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/vndee/go-supabase-auth)](https://goreportcard.com/report/github.com/vndee/go-supabase-auth)
[![License](https://img.shields.io/github/license/vndee/go-supabase-auth)](https://github.com/vndee/go-supabase-auth/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/vndee/go-supabase-auth)](https://github.com/vndee/go-supabase-auth/releases)

## Features

- **User Management**: Create, read, update, delete users
- **Authentication**: Token verification, JWT parsing
- **Admin Functions**: User management, auth settings, audit logs
- **Session Management**: List and invalidate sessions
- **Role Management**: Set and verify user roles
- **Multi-factor Authentication**: Manage MFA factors
- **Email Actions**: Send password resets, email confirmations, and more
- **Middleware**: Authentication and role-based authorization middleware for HTTP servers

## Installation

```bash
go get github.com/vndee/go-supabase-auth
```

## Quick Start

### Basic Usage

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/vndee/go-supabase-auth/auth"
)

func main() {
	// Get Supabase credentials from environment variables
	projectURL := os.Getenv("SUPABASE_URL")
	apiKey := os.Getenv("SUPABASE_SERVICE_ROLE_KEY") // Service role key for admin functions

	// Create an admin client
	admin := auth.NewAdmin(projectURL, apiKey)
	ctx := context.Background()

	// List users
	users, err := admin.ListUsers(ctx, &auth.ListUsersOptions{
		PerPage: 10,
	})
	if err != nil {
		log.Fatalf("Error listing users: %v", err)
	}

	fmt.Printf("Found %d users (out of %d total)\n", len(users.Users), users.TotalCount)
	for i, user := range users.Users {
		fmt.Printf("%d. %s - %s\n", i+1, user.Email, user.ID)
	}
}
```

### Authentication Middleware

```go
package main

import (
	"context"
	"net/http"
	"os"

	"github.com/yourusername/go-supabase-auth/auth"
)

func main() {
	client := auth.NewClient(
		os.Getenv("SUPABASE_URL"),
		os.Getenv("SUPABASE_SERVICE_ROLE_KEY"),
	)

	// Create middleware
	authMiddleware := AuthMiddleware(client)
	
	// Use middleware
	http.Handle("/api/protected", authMiddleware(http.HandlerFunc(protectedHandler)))
	http.ListenAndServe(":8080", nil)
}

// AuthMiddleware creates middleware for authenticating requests using Supabase tokens
func AuthMiddleware(client *auth.Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			// ... (token extraction code) ...

			// Verify token with Supabase
			user, err := client.VerifyToken(r.Context(), token)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Add user to request context
			ctx := context.WithValue(r.Context(), "user", user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
```

## Admin API Examples

### User Management

```go
// Create a user
user, err := admin.CreateUser(ctx, &auth.CreateUserOptions{
	Email:        "user@example.com",
	Password:     "securepassword",
	EmailConfirm: true,
	UserMetadata: map[string]interface{}{
		"name": "John Doe",
	},
})

// Update a user
updatedUser, err := admin.UpdateUser(ctx, user.ID, &auth.UpdateUserOptions{
	UserMetadata: map[string]interface{}{
		"name": "Jane Doe",
	},
})

// Delete a user
err = admin.DeleteUser(ctx, user.ID)
```

### User Queries

```go
// Get a user by ID
user, err := admin.GetUser(ctx, "user-id")

// List users with filtering
users, err := admin.ListUsers(ctx, &auth.ListUsersOptions{
	Page:       1,
	PerPage:    20,
	Filter:     auth.BuildFilter("email", "eq", "user@example.com"),
	SortBy:     "created_at",
	SortOrder:  "desc",
})
```

### Authentication Links

```go
// Generate a password reset link
link, err := admin.Client().GenerateLink(ctx, auth.LinkActionRecovery, &auth.GenerateLinkOptions{
	Email:      "user@example.com",
	RedirectTo: "https://yourapp.com/reset-password",
})

// Send an invite to a new user
user, err := admin.Client().InviteUserByEmail(ctx, "newuser@example.com", &auth.InviteOptions{
	RedirectTo: "https://yourapp.com/welcome",
	UserMetadata: map[string]interface{}{
		"invited_by": "admin",
	},
})
```

### Session Management

```go
// List user sessions
sessions, err := admin.Client().ListUserSessions(ctx, user.ID)

// Delete all user sessions
err = admin.Client().DeleteUserSessions(ctx, user.ID)
```

### User Access Control

```go
// Set user role
user, err := admin.Client().SetUserRole(ctx, user.ID, "admin")

// Ban a user
user, err := admin.Client().BanUser(ctx, user.ID)

// Unban a user
user, err := admin.Client().UnbanUser(ctx, user.ID)
```

### JWT Utilities

```go
// Decode a JWT token without verification
payload, err := auth.DecodeJWT(token)

// Check if a token is expired
expired, err := auth.IsTokenExpired(token)

// Get user ID from token
userID, err := auth.GetUserIDFromToken(token)

// Get role from token
role, err := auth.GetRoleFromToken(token)
```

## Error Handling

The SDK provides helper functions to check error types:

```go
if err != nil {
	switch {
	case auth.IsNotFoundError(err):
		// Handle not found error
	case auth.IsAuthenticationError(err):
		// Handle authentication error
	case auth.IsAuthorizationError(err):
		// Handle authorization error
	case auth.IsConflictError(err):
		// Handle conflict error (e.g., email already taken)
	case auth.IsRateLimitError(err):
		// Handle rate limit error
	case auth.IsServerError(err):
		// Handle server error
	default:
		// Handle other errors
	}
}
```

## Configuration

```go
// Create a client with custom configuration
client := auth.NewClient(projectURL, apiKey).WithConfig(&auth.Config{
	ProjectURL:        projectURL,
	APIKey:            apiKey,
	AutoRefreshTokens: true,
	PersistSession:    true,
	Debug:             true,
})

// Set a custom HTTP client
client = client.WithHTTPClient(&http.Client{
	Timeout: time.Second * 30,
})
```

## Complete Examples

See the [examples](./examples) directory for complete working examples:

- [Basic Usage](./examples/basic/main.go)
- [HTTP Middleware](./examples/middleware/main.go)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This is not an official Supabase product. It is maintained by the community.