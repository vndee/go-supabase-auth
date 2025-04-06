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
		Email:    "test@example.com",
		Password: "password123",
		UserMetadata: map[string]interface{}{
			"name": "Test User",
		},
	})

	// Handle case where user might already exist
	if err != nil {
		if auth.IsConflictError(err) {
			fmt.Println("User already exists, trying to find them...")
			// Try to find the user by email
			userList, err := client.ListUsers(ctx, &auth.ListUsersOptions{
				Filter: auth.BuildFilter("email", "eq", "test@example.com"),
			})
			if err != nil {
				log.Fatalf("Error finding user: %v", err)
			}

			if len(userList.Users) > 0 {
				newUser = &userList.Users[0]
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

	// Example 3: Generate a password reset link (auth operation)
	fmt.Println("\nGenerating password reset link...")
	linkOptions := &auth.GenerateLinkOptions{
		Email:      "test@example.com",
		RedirectTo: "https://yourapp.com/reset-password",
	}

	link, err := client.GenerateLink(ctx, auth.LinkActionRecovery, linkOptions)
	if err != nil {
		log.Fatalf("Error generating link: %v", err)
	}
	fmt.Printf("Password reset link generated: %s\n", link.Link)

	// Example 4: Update auth settings (admin operation)
	fmt.Println("\nGetting auth settings...")
	settings, err := client.GetAuthSettings(ctx)
	if err != nil {
		log.Fatalf("Error getting auth settings: %v", err)
	}
	fmt.Printf("Current auth settings: %v\n", settings)

	// Example 5: Ban a user (admin operation + convenience method)
	fmt.Println("\nBanning user...")
	bannedUser, err := client.BanUser(ctx, newUser.ID)
	if err != nil {
		log.Fatalf("Error banning user: %v", err)
	}
	fmt.Printf("User banned: %v\n", bannedUser.Banned)

	// Example 6: Unban the user
	fmt.Println("\nUnbanning user...")
	unbannedUser, err := client.UnbanUser(ctx, newUser.ID)
	if err != nil {
		log.Fatalf("Error unbanning user: %v", err)
	}
	fmt.Printf("User unbanned: %v\n", !unbannedUser.Banned)

	// Example 7: Delete the user
	fmt.Println("\nDeleting user...")
	err = client.DeleteUser(ctx, newUser.ID)
	if err != nil {
		log.Fatalf("Error deleting user: %v", err)
	}
	fmt.Println("User deleted successfully!")
}
