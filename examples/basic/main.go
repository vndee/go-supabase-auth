package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/vndee/go-supabase-auth/auth"
)

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: Error loading .env file:", err)
	}

	// Get Supabase credentials from environment variables
	projectURL := os.Getenv("SUPABASE_URL")
	apiKey := os.Getenv("SUPABASE_SERVICE_ROLE_KEY") // Service role key for admin functions

	if projectURL == "" || apiKey == "" {
		log.Fatal("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY environment variables must be set")
	}

	// Create a Supabase client
	client := auth.NewClient(projectURL, apiKey)
	ctx := context.Background()

	// Example 1: List users (admin operation)
	fmt.Println("Listing users...")
	users, err := client.ListUsers(ctx, &auth.ListUsersOptions{
		PerPage: 10,
	})
	if err != nil {
		log.Fatalf("Error listing users: %v", err)
	}

	fmt.Printf("Found %d users\n", len(users.Users))
	for i, user := range users.Users {
		fmt.Printf("%d. %s (%s)\n", i+1, user.Email, user.ID)
	}

	// Example 2: Create a user (admin operation)
	fmt.Println("\nCreating a new user...")
	newUser, err := client.CreateUser(ctx, &auth.CreateUserOptions{
		Email:        "test@example.com",
		Password:     "password123",
		EmailConfirm: true,
		UserMetadata: map[string]interface{}{
			"name": "Test User",
		},
	})

	// Handle case where user might already exist
	if err != nil {
		// Check for conflict (email already exists) error
		if auth.IsConflictError(err) {
			fmt.Println("User already exists, trying to find them...")
			// Get all users and find the one with matching email
			allUsers, err := client.ListUsers(ctx, &auth.ListUsersOptions{
				PerPage: 100,
			})
			if err != nil {
				log.Fatalf("Error listing users: %v", err)
			}

			var foundUser *auth.User
			for _, user := range allUsers.Users {
				if user.Email == "test@example.com" {
					foundUser = &user
					break
				}
			}

			if foundUser != nil {
				newUser = foundUser
				fmt.Printf("Found existing user with ID: %s\n", newUser.ID)
			} else {
				log.Fatalf("User should exist but couldn't be found")
			}
		} else {
			log.Fatalf("Error creating user: %v", err)
		}
	} else {
		fmt.Printf("Created new user with ID: %s\n", newUser.ID)
	}

	// Example 3: Sign in a user
	fmt.Println("\nSigning in user...")
	signInUser, err := client.SignIn(ctx, "test@example.com", "password123")
	if err != nil {
		log.Fatalf("Error signing in user: %v", err)
	}
	fmt.Printf("Signed in user with ID: %s\n", signInUser.User.ID)
	fmt.Printf("Access token: %s\n", signInUser.AccessToken)

	// Example 4: Verify the access token with the API
	fmt.Println("\nVerifying user...")
	verifiedUser, err := client.VerifyTokenWithAPI(ctx, signInUser.AccessToken)
	if err != nil {
		log.Fatalf("Error verifying user: %v", err)
	}
	fmt.Printf("Verified user with ID: %s\n", verifiedUser.ID)

	// Example 5: Verify access token with jwt
	fmt.Println("\nVerifying access token with jwt...")
	jwtSecret := os.Getenv("SUPABASE_JWT_SECRET")
	issuer := os.Getenv("SUPABASE_JWT_ISSUER")
	jwtPayload, err := client.VerifyJWT(signInUser.AccessToken, jwtSecret, issuer)
	if err != nil {
		log.Fatalf("Error verifying user: %v", err)
	}
	fmt.Printf("Verified user with ID: %s\n", jwtPayload.Sub)

	// Example 6: Delete the user
	fmt.Println("\nDeleting user...")
	err = client.DeleteUser(ctx, newUser.ID)
	if err != nil {
		log.Fatalf("Error deleting user: %v", err)
	}
	fmt.Println("User deleted successfully!")
}
