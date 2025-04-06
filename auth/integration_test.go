package auth

import (
	"context"
	"os"
	"testing"
)

// TestIntegration_Client tests integration with a real Supabase instance
// Skip this test unless SUPABASE_INTEGRATION_TEST is set to "true"
func TestIntegration_Client(t *testing.T) {
	if os.Getenv("SUPABASE_INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test; set SUPABASE_INTEGRATION_TEST=true to run")
	}

	projectURL := os.Getenv("SUPABASE_URL")
	apiKey := os.Getenv("SUPABASE_SERVICE_ROLE_KEY")

	if projectURL == "" || apiKey == "" {
		t.Fatal("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set")
	}

	// Create client
	client := NewClient(projectURL, apiKey)
	ctx := context.Background()

	// Test creating a user
	testEmail := "integration-test@example.com"
	createOptions := &CreateUserOptions{
		Email:        testEmail,
		Password:     "securepassword123",
		EmailConfirm: true,
		UserMetadata: map[string]interface{}{
			"name": "Integration Test User",
		},
	}

	var user *User
	var err error

	// Try to create the user, but don't fail if it already exists
	user, err = client.CreateUser(ctx, createOptions)
	if err != nil && !IsConflictError(err) {
		t.Fatalf("Failed to create user: %v", err)
	}

	// If user already exists, try to find them
	if err != nil && IsConflictError(err) {
		// Find the user by email
		users, err := client.ListUsers(ctx, &ListUsersOptions{
			Filter: BuildFilter("email", "eq", testEmail),
		})
		if err != nil {
			t.Fatalf("Failed to list users: %v", err)
		}

		if len(users.Users) == 0 {
			t.Fatalf("User with email %s exists but couldn't be found", testEmail)
		}

		user = &users.Users[0]
	}

	t.Logf("User ID: %s", user.ID)

	// Test updating the user
	updateOptions := &UpdateUserOptions{
		UserMetadata: map[string]interface{}{
			"name": "Updated Integration Test User",
			"test": "integration",
		},
	}

	updatedUser, err := client.UpdateUser(ctx, user.ID, updateOptions)
	if err != nil {
		t.Fatalf("Failed to update user: %v", err)
	}

	if updatedUser.UserMetadata["test"] != "integration" {
		t.Errorf("Expected UserMetadata to contain test=integration")
	}

	// Test getting the user
	fetchedUser, err := client.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	if fetchedUser.ID != user.ID {
		t.Errorf("Expected fetched user ID to match created user ID")
	}

	// Don't delete the user in case we need it for other tests
	t.Log("Integration test completed successfully")
}

// TestIntegration_Admin tests integration with a real Supabase instance using the Admin API
// Skip this test unless SUPABASE_INTEGRATION_TEST is set to "true"
func TestIntegration_Admin(t *testing.T) {
	if os.Getenv("SUPABASE_INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test; set SUPABASE_INTEGRATION_TEST=true to run")
	}

	projectURL := os.Getenv("SUPABASE_URL")
	apiKey := os.Getenv("SUPABASE_SERVICE_ROLE_KEY")

	if projectURL == "" || apiKey == "" {
		t.Fatal("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set")
	}

	// Create admin
	admin := NewAdmin(projectURL, apiKey)
	ctx := context.Background()

	// Test getting auth settings
	settings, err := admin.GetAuthSettings(ctx)
	if err != nil {
		t.Fatalf("Failed to get auth settings: %v", err)
	}

	t.Logf("Auth settings: JWT expiry = %v", settings["jwt_expiry"])

	// Test listing users
	users, err := admin.ListUsers(ctx, &ListUsersOptions{
		Page:    1,
		PerPage: 10,
	})
	if err != nil {
		t.Fatalf("Failed to list users: %v", err)
	}

	t.Logf("Found %d users (out of %d)", len(users.Users), users.TotalCount)

	// Test audit logs if available
	logs, err := admin.ListAuditLogs(ctx, map[string]string{
		"page":     "1",
		"per_page": "5",
	})
	if err != nil {
		t.Logf("Note: Failed to list audit logs (might not be available): %v", err)
	} else {
		t.Logf("Found %d audit logs", len(logs))
	}

	t.Log("Admin integration test completed successfully")
}
