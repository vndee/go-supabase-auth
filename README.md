# Go Supabase Auth SDK

A comprehensive authentication SDK for Supabase in Go, providing a unified interface for client and admin operations.

[![Go Reference](https://pkg.go.dev/badge/github.com/vndee/go-supabase-auth.svg)](https://pkg.go.dev/github.com/vndee/go-supabase-auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/vndee/go-supabase-auth)](https://goreportcard.com/report/github.com/vndee/go-supabase-auth)
[![License](https://img.shields.io/github/license/vndee/go-supabase-auth)](https://github.com/vndee/go-supabase-auth/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/vndee/go-supabase-auth)](https://github.com/vndee/go-supabase-auth/releases)
[![Test Coverage](https://img.shields.io/badge/coverage-80%25-brightgreen)](https://github.com/vndee/go-supabase-auth)

## Features

- **User Management**: Create, read, update, delete users
- **Authentication**: Sign up, sign in, token verification, JWT parsing
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

	// Create a Supabase client
	client := auth.NewClient(projectURL, apiKey)
	ctx := context.Background()

	// List users
	users, err := client.ListUsers(ctx, &auth.ListUsersOptions{
		PerPage: 10,
	})
	if err != nil {
		log.Fatalf("Error listing users: %v", err)
	}

	fmt.Printf("Found %d users\n", len(users.Users))
	for i, user := range users.Users {
		fmt.Printf("%d. %s - %s\n", i+1, user.Email, user.ID)
	}
	
	// Create a user
	newUser, err := client.CreateUser(ctx, &auth.CreateUserOptions{
		Email:    "new@example.com",
		Password: "password123",
		UserMetadata: map[string]interface{}{
			"name": "New User",
		},
	})
	if err != nil {
		log.Fatalf("Error creating user: %v", err)
	}
	
	fmt.Printf("Created user: %s\n", newUser.ID)
}
```

## User Management

### Creating Users

```go
// Create a user
user, err := client.CreateUser(ctx, &auth.CreateUserOptions{
	Email:        "user@example.com",
	Password:     "securepassword",
	EmailConfirm: true,
	UserMetadata: map[string]interface{}{
		"name": "John Doe",
	},
})

// Create multiple users in batch
users := []*auth.CreateUserOptions{
    {
        Email:    "user1@example.com",
        Password: "password1",
    },
    {
        Email:    "user2@example.com",
        Password: "password2",
    },
}
results, err := client.CreateManyUsers(ctx, users)
```

### Reading Users

```go
// Get a user by ID
user, err := client.GetUser(ctx, "user-id")

// List users with filtering
users, err := client.ListUsers(ctx, &auth.ListUsersOptions{
	Page:      1,
	PerPage:   20,
	Filter:    auth.BuildFilter("email", "eq", "user@example.com"),
	SortBy:    "created_at",
	SortOrder: "desc",
})
```

### Updating Users

```go
// Update a user
updatedUser, err := client.UpdateUser(ctx, user.ID, &auth.UpdateUserOptions{
	UserMetadata: map[string]interface{}{
		"name": "Jane Doe",
		"preferences": map[string]interface{}{
			"theme": "dark",
		},
	},
})

// Set user role
user, err := client.SetUserRole(ctx, user.ID, "admin")

// Ban a user
user, err := client.BanUser(ctx, user.ID)

// Unban a user
user, err := client.UnbanUser(ctx, user.ID)
```

### Deleting Users

```go
// Delete a user
err = client.DeleteUser(ctx, user.ID)
```

## Authentication

### Sign Up and Sign In

```go
// Sign up a new user
user, err := client.SignUp(ctx, "user@example.com", "password123", map[string]interface{}{
    "name": "New User",
})

// Sign in
user, err := client.SignIn(ctx, "user@example.com", "password123")

// Sign out
err = client.SignOut(ctx)
```

### Token Handling

```go
// Verify a token
user, err := client.VerifyToken(ctx, token)

// Check if a token is expired
expired, err := auth.IsTokenExpired(token)

// Decode a JWT token without verification
payload, err := auth.DecodeJWT(token)

// Get user ID from token
userID, err := auth.GetUserIDFromToken(token)

// Get role from token
role, err := auth.GetRoleFromToken(token)
```

### Session Management

```go
// List user sessions
sessions, err := client.ListUserSessions(ctx, user.ID)

// Delete all user sessions
err = client.DeleteUserSessions(ctx, user.ID)

// Refresh the current session
err = client.RefreshSession(ctx)

// Set session tokens (for example, after getting tokens from another source)
client.SetSession(accessToken, refreshToken, 3600) // expires in 1 hour

// Get current session tokens
accessToken, refreshToken, expiry := client.GetSession()
```

## Email and Invitation Actions

```go
// Generate a password reset link
link, err := client.GenerateLink(ctx, auth.LinkActionRecovery, &auth.GenerateLinkOptions{
	Email:      "user@example.com",
	RedirectTo: "https://yourapp.com/reset-password",
})

// Send an invite to a new user
user, err := client.InviteUserByEmail(ctx, "newuser@example.com", &auth.InviteOptions{
	RedirectTo: "https://yourapp.com/welcome",
	UserMetadata: map[string]interface{}{
		"invited_by": "admin",
	},
})

// Send a password reset email
err = client.ResetPasswordForEmail(ctx, "user@example.com")
```

## Authentication Provider Management

```go
// Create an auth provider
err = client.CreateAuthProvider(ctx, "github", map[string]interface{}{
    "client_id":     "your-github-client-id",
    "client_secret": "your-github-client-secret",
    "redirect_uri":  "https://your-app.com/auth/callback",
})

// Update an auth provider configuration
err = client.UpdateAuthProvider(ctx, "github", map[string]interface{}{
    "redirect_uri": "https://your-updated-app.com/auth/callback",
})

// Delete an auth provider
err = client.DeleteAuthProvider(ctx, "github")
```

## Auth Settings

```go
// Get auth settings
settings, err := client.GetAuthSettings(ctx)

// Update auth settings
err = client.UpdateAuthSettings(ctx, map[string]interface{}{
    "disable_signup": true,
    "jwt_expiry": 3600,
})
```

## Audit Logs

```go
// Get audit logs
logs, err := client.ListAuditLogs(ctx, map[string]string{
    "page":     "1",
    "per_page": "10",
})
```

## Multi-Factor Authentication

```go
// List MFA factors for a user
factors, err := client.ListFactors(ctx, user.ID)
```

## Using Middleware

```go
// Create a Supabase client
client := auth.NewClient(projectURL, apiKey)

// Create middleware
authMiddleware := AuthMiddleware(client)
adminMiddleware := RoleMiddleware("admin")

// Use middleware in routes
http.Handle("/hello", authMiddleware(http.HandlerFunc(helloHandler)))
http.Handle("/admin", authMiddleware(adminMiddleware(http.HandlerFunc(adminHandler))))

// Middleware implementations:

// AuthMiddleware creates middleware for authenticating requests using Supabase tokens
func AuthMiddleware(client *auth.Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				http.Error(w, "Invalid auth header format", http.StatusUnauthorized)
				return
			}

			token := parts[1]

			// Verify token with Supabase
			user, err := client.VerifyToken(r.Context(), token)
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Add user to request context
			ctx := context.WithValue(r.Context(), "user", user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
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

// Set token callback to persist tokens
client.SetTokenCallback(func(accessToken, refreshToken string) {
    // Save tokens to database, file, etc.
    saveTokensToDatabase(accessToken, refreshToken)
})
```

## Complete Examples

See the [examples](./examples) directory for complete working examples:

- [Basic Usage](./examples/unified/main.go)
- [HTTP Middleware](./examples/middleware/main.go)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This is not an official Supabase product. It is maintained by the community.