package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vndee/go-supabase-auth/auth"
)

// UserContext is the key for the user in the request context
type UserContext string

const (
	// UserKey is the key for the user in the request context
	UserKey UserContext = "user"
)

// AuthMiddleware creates middleware for authenticating requests using Supabase tokens
func AuthMiddleware(client *auth.Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				handleError(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				handleError(w, "Authorization header format must be Bearer {token}", http.StatusUnauthorized)
				return
			}

			token := parts[1]

			// Check if token is expired
			expired, err := auth.IsTokenExpired(token)
			if err != nil {
				handleError(w, "Invalid token format", http.StatusUnauthorized)
				return
			}

			if expired {
				handleError(w, "Token expired", http.StatusUnauthorized)
				return
			}

			// Verify token with Supabase
			user, err := client.VerifyToken(r.Context(), token)
			if err != nil {
				handleError(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Add user to request context
			ctx := context.WithValue(r.Context(), UserKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RoleMiddleware creates middleware for checking user roles
func RoleMiddleware(requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := r.Context().Value(UserKey).(*auth.User)
			if !ok {
				handleError(w, "User not authenticated", http.StatusUnauthorized)
				return
			}

			if user.Role != requiredRole {
				handleError(w, fmt.Sprintf("Role '%s' required", requiredRole), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func handleError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(UserKey).(*auth.User)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"message": fmt.Sprintf("Hello, %s!", user.Email),
		"user_id": user.ID,
		"email":   user.Email,
		"role":    user.Role,
	}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(UserKey).(*auth.User)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Admin area",
		"user_id":   user.ID,
		"email":     user.Email,
		"role":      user.Role,
		"timestamp": time.Now().Format(time.RFC3339),
	}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func main() {
	// Get Supabase credentials from environment variables
	projectURL := os.Getenv("SUPABASE_URL")
	apiKey := os.Getenv("SUPABASE_SERVICE_ROLE_KEY") // Service role key required for token verification

	if projectURL == "" || apiKey == "" {
		log.Fatal("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY environment variables must be set")
	}

	// Create a new client
	client := auth.NewClient(projectURL, apiKey)

	// Create middleware
	authMiddleware := AuthMiddleware(client)
	adminMiddleware := RoleMiddleware("admin")

	// Create handlers
	http.Handle("/hello", authMiddleware(http.HandlerFunc(helloHandler)))
	http.Handle("/admin", authMiddleware(adminMiddleware(http.HandlerFunc(adminHandler))))

	// Public handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"message": "Public endpoint, no authentication required",
		})
	})

	// Start server
	fmt.Println("Server starting on :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
