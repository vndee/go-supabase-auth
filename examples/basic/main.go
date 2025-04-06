package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/vndee/go-supabase-auth/auth"
)

func main() {
	// Get Supabase credentials from environment variables
	projectURL := os.Getenv("SUPABASE_URL")
	apiKey := os.Getenv("SUPABASE_SERVICE_ROLE_KEY") // Service role key for admin functions

	if projectURL == "" || apiKey == "" {
		log.Fatal("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY environment variables must be set")
	}

	// Create a new admin client
	admin := auth.NewAdmin(projectURL, apiKey)
	ctx := context.Background()

	// List users
	fmt.Println("Listing users...")
	users, err := admin.ListUsers(ctx, &auth.ListUsersOptions{
		PerPage: 10,
	})
	if err != nil {
		log.Fatalf("Error listing users: %v", err)
	}

	fmt.Printf("Found %d users (out of %d total)\n", len(users.Users), users.TotalCount)
	for i, user := range users.Users {
		fmt.Printf("%d. %s - %s (created: %s)\n",
			i+1, user.Email, user.ID, user.CreatedAt.Format(time.RFC3339))
	}

	// Create a user
	fmt.Println("\nCreating a new user...")
	newUser, err := admin.CreateUser(ctx, &auth.CreateUserOptions{
		Email:        "test@example.com",
		Password:     "password123",
		EmailConfirm: true, // Auto-confirm email
		UserMetadata: map[string]interface{}{
			"name": "Test User",
			"org":  "Test Organization",
		},
		AppMetadata: map[string]interface{}{
			"plan": "free",
		},
	})

	if err != nil {
		if auth.IsConflictError(err) {
			fmt.Println("User already exists. Fetching instead...")
			// Try to fetch the user by email (using a filter)
			usersWithEmail, err := admin.ListUsers(ctx, &auth.ListUsersOptions{
				Filter: auth.BuildFilter("email", "eq", "test@example.com"),
			})
			if err != nil {
				log.Fatalf("Error fetching user: %v", err)
			}

			if len(usersWithEmail.Users) > 0 {
				newUser = &usersWithEmail.Users[0]
			} else {
				log.Fatalf("User exists but couldn't fetch: %v", err)
			}
		} else {
			log.Fatalf("Error creating user: %v", err)
		}
	} else {
		fmt.Printf("Created user: %s with ID: %s\n", newUser.Email, newUser.ID)
	}

	// Update the user
	fmt.Println("\nUpdating user...")
	updatedUser, err := admin.UpdateUser(ctx, newUser.ID, &auth.UpdateUserOptions{
		UserMetadata: map[string]interface{}{
			"name": "Updated Test User",
			"org":  "Updated Test Organization",
		},
	})
	if err != nil {
		log.Fatalf("Error updating user: %v", err)
	}
	fmt.Printf("Updated user metadata: %v\n", updatedUser.UserMetadata)

	// Generate a password reset link
	fmt.Println("\nGenerating password reset link...")
	linkOptions := &auth.GenerateLinkOptions{
		Email:      newUser.Email,
		RedirectTo: "https://your-app.com/reset-password",
	}

	link, err := admin.Client().GenerateLink(ctx, auth.LinkActionRecovery, linkOptions)
	if err != nil {
		log.Fatalf("Error generating link: %v", err)
	}
	fmt.Printf("Password reset link: %s\n", link.Link)
	fmt.Printf("Link expires at: %s\n", link.ExpiresAt.Format(time.RFC3339))

	// Set user role
	fmt.Println("\nSetting user role...")
	roleUser, err := admin.Client().SetUserRole(ctx, newUser.ID, "editor")
	if err != nil {
		log.Fatalf("Error setting user role: %v", err)
	}
	fmt.Printf("User role set to: %s\n", roleUser.Role)

	// Ban the user
	fmt.Println("\nBanning user...")
	bannedUser, err := admin.Client().BanUser(ctx, newUser.ID)
	if err != nil {
		log.Fatalf("Error banning user: %v", err)
	}
	fmt.Printf("User banned: %t\n", bannedUser.Banned)

	// Unban the user
	fmt.Println("\nUnbanning user...")
	unbannedUser, err := admin.Client().UnbanUser(ctx, newUser.ID)
	if err != nil {
		log.Fatalf("Error unbanning user: %v", err)
	}
	fmt.Printf("User banned: %t\n", unbannedUser.Banned)

	// List user's sessions
	fmt.Println("\nListing user sessions...")
	sessions, err := admin.Client().ListUserSessions(ctx, newUser.ID)
	if err != nil {
		log.Fatalf("Error listing sessions: %v", err)
	}
	fmt.Printf("User has %d active sessions\n", len(sessions))

	// Delete the user sessions
	fmt.Println("\nDeleting user sessions...")
	err = admin.Client().DeleteUserSessions(ctx, newUser.ID)
	if err != nil {
		log.Fatalf("Error deleting sessions: %v", err)
	}
	fmt.Println("All user sessions deleted")

	// Delete the user
	fmt.Println("\nDeleting user...")
	err = admin.DeleteUser(ctx, newUser.ID)
	if err != nil {
		log.Fatalf("Error deleting user: %v", err)
	}
	fmt.Println("User deleted successfully")
}
