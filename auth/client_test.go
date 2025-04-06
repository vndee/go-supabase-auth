package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	authtest "github.com/vndee/go-supabase-auth/auth/mock"
)

const (
	testProjectURL = "https://example.supabase.co"
	testAPIKey     = "test-api-key"
)

func TestNewClient(t *testing.T) {
	client := NewClient(testProjectURL, testAPIKey)

	if client.config.ProjectURL != testProjectURL {
		t.Errorf("Expected ProjectURL to be %s, got %s", testProjectURL, client.config.ProjectURL)
	}

	if client.config.APIKey != testAPIKey {
		t.Errorf("Expected APIKey to be %s, got %s", testAPIKey, client.config.APIKey)
	}

	if client.config.AutoRefreshTokens != true {
		t.Error("Expected AutoRefreshTokens to be true by default")
	}
}

func TestClientWithConfig(t *testing.T) {
	client := NewClient(testProjectURL, testAPIKey)
	config := &Config{
		ProjectURL:        "https://new.supabase.co",
		APIKey:            "new-api-key",
		AutoRefreshTokens: false,
		PersistSession:    false,
		Debug:             true,
	}

	updatedClient := client.WithConfig(config)

	if updatedClient.config.ProjectURL != config.ProjectURL {
		t.Errorf("Expected ProjectURL to be %s, got %s", config.ProjectURL, updatedClient.config.ProjectURL)
	}

	if updatedClient.config.APIKey != config.APIKey {
		t.Errorf("Expected APIKey to be %s, got %s", config.APIKey, updatedClient.config.APIKey)
	}

	if updatedClient.config.AutoRefreshTokens != config.AutoRefreshTokens {
		t.Error("Expected AutoRefreshTokens to match config")
	}
}

func TestClientWithHTTPClient(t *testing.T) {
	client := NewClient(testProjectURL, testAPIKey)
	customHTTPClient := &http.Client{
		Timeout: time.Second * 30,
	}

	updatedClient := client.WithHTTPClient(customHTTPClient)

	if updatedClient.httpClient != customHTTPClient {
		t.Error("Expected HTTPClient to be updated with custom client")
	}
}

func TestVerifyToken(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/verify-token": {
			StatusCode: http.StatusOK,
			Body: map[string]interface{}{
				"id":    "user123",
				"email": "test@example.com",
				"role":  "user",
			},
		},
		"/auth/v1/admin/verify-token-invalid": {
			StatusCode: http.StatusUnauthorized,
			Body: map[string]interface{}{
				"error":   "invalid_token",
				"message": "Invalid token",
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test valid token verification
	user, err := client.VerifyToken(ctx, "valid-token")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if user.ID != "user123" {
		t.Errorf("Expected user ID to be 'user123', got %s", user.ID)
	}

	if user.Email != "test@example.com" {
		t.Errorf("Expected email to be 'test@example.com', got %s", user.Email)
	}

	if user.Role != "user" {
		t.Errorf("Expected role to be 'user', got %s", user.Role)
	}
}

func TestGetUser(t *testing.T) {
	// Setup test server
	server, _ := authtest.SetupTestServer()
	defer server.Close()

	// Create client using test server URL
	client := NewClient(server.URL, testAPIKey)
	ctx := context.Background()

	// Test getting user
	user, err := client.GetUser(ctx, "user123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if user.ID != "user123" {
		t.Errorf("Expected user ID to be 'user123', got %s", user.ID)
	}

	if user.Email != "test@example.com" {
		t.Errorf("Expected email to be 'test@example.com', got %s", user.Email)
	}
}

func TestGenerateLink(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/generate_link": {
			StatusCode: http.StatusOK,
			Body: map[string]interface{}{
				"link":         "https://example.supabase.co/auth/v1/verify?token=test-token",
				"email":        "test@example.com",
				"user_id":      "user123",
				"generated_at": time.Now().Format(time.RFC3339),
				"expires_at":   time.Now().Add(time.Hour).Format(time.RFC3339),
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test generating a link
	options := &GenerateLinkOptions{
		Email:      "test@example.com",
		RedirectTo: "https://example.com/reset-password",
	}

	link, err := client.GenerateLink(ctx, LinkActionRecovery, options)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if link.Email != "test@example.com" {
		t.Errorf("Expected email to be 'test@example.com', got %s", link.Email)
	}

	if link.UserID != "user123" {
		t.Errorf("Expected user ID to be 'user123', got %s", link.UserID)
	}
}

func TestListUsers(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users": {
			StatusCode: http.StatusOK,
			Body: map[string]interface{}{
				"users": []map[string]interface{}{
					{
						"id":    "user123",
						"email": "test@example.com",
						"role":  "user",
					},
					{
						"id":    "user456",
						"email": "another@example.com",
						"role":  "admin",
					},
				},
				"total_count": 2,
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test listing users
	options := &ListUsersOptions{
		Page:    1,
		PerPage: 10,
	}

	users, err := client.ListUsers(ctx, options)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(users.Users) != 2 {
		t.Errorf("Expected 2 users, got %d", len(users.Users))
	}

	if users.TotalCount != 2 {
		t.Errorf("Expected total count to be 2, got %d", users.TotalCount)
	}

	if users.Users[0].ID != "user123" {
		t.Errorf("Expected first user ID to be 'user123', got %s", users.Users[0].ID)
	}

	if users.Users[1].Role != "admin" {
		t.Errorf("Expected second user role to be 'admin', got %s", users.Users[1].Role)
	}
}

func TestCreateUser(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users": {
			StatusCode: http.StatusCreated,
			Body: map[string]interface{}{
				"id":    "new-user-id",
				"email": "new@example.com",
				"role":  "user",
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test creating a user
	options := &CreateUserOptions{
		Email:    "new@example.com",
		Password: "password123",
		UserMetadata: map[string]interface{}{
			"name": "New User",
		},
	}

	user, err := client.CreateUser(ctx, options)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if user.ID != "new-user-id" {
		t.Errorf("Expected user ID to be 'new-user-id', got %s", user.ID)
	}

	if user.Email != "new@example.com" {
		t.Errorf("Expected email to be 'new@example.com', got %s", user.Email)
	}
}

func TestUpdateUser(t *testing.T) {
	// Setup test server
	server, _ := authtest.SetupTestServer()
	defer server.Close()

	// Create client using test server URL
	client := NewClient(server.URL, testAPIKey)
	ctx := context.Background()

	// Test updating a user
	options := &UpdateUserOptions{
		Role: stringPtr("admin"),
		UserMetadata: map[string]interface{}{
			"name": "Updated User",
		},
	}

	user, err := client.UpdateUser(ctx, "user123", options)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if user.ID != "user123" {
		t.Errorf("Expected user ID to be 'user123', got %s", user.ID)
	}

	if user.Role != "admin" {
		t.Errorf("Expected role to be 'admin', got %s", user.Role)
	}
}

func TestDeleteUser(t *testing.T) {
	// Setup test server
	server, _ := authtest.SetupTestServer()
	defer server.Close()

	// Create client using test server URL
	client := NewClient(server.URL, testAPIKey)
	ctx := context.Background()

	// Test deleting a user
	err := client.DeleteUser(ctx, "user123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

// Helper function to create string pointer
func stringPtr(s string) *string {
	return &s
}

// TestInviteUserByEmail tests the invite user by email functionality
func TestInviteUserByEmail(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/invite": {
			StatusCode: http.StatusOK,
			Body: map[string]interface{}{
				"id":    "invited-user-id",
				"email": "invited@example.com",
				"role":  "user",
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test inviting a user
	options := &InviteOptions{
		RedirectTo: "https://example.com/welcome",
		UserMetadata: map[string]interface{}{
			"invited_by": "admin",
		},
	}

	user, err := client.InviteUserByEmail(ctx, "invited@example.com", options)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if user.ID != "invited-user-id" {
		t.Errorf("Expected user ID to be 'invited-user-id', got %s", user.ID)
	}

	if user.Email != "invited@example.com" {
		t.Errorf("Expected email to be 'invited@example.com', got %s", user.Email)
	}
}

// TestListFactors tests the list factors functionality
func TestListFactors(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users/user123/factors": {
			StatusCode: http.StatusOK,
			Body: []map[string]interface{}{
				{
					"id":            "factor1",
					"user_id":       "user123",
					"type":          "totp",
					"status":        "verified",
					"friendly_name": "Google Authenticator",
				},
				{
					"id":            "factor2",
					"user_id":       "user123",
					"type":          "recovery",
					"status":        "verified",
					"friendly_name": "Recovery Codes",
				},
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test listing factors
	factors, err := client.ListFactors(ctx, "user123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(factors) != 2 {
		t.Errorf("Expected 2 factors, got %d", len(factors))
	}

	if factors[0].ID != "factor1" {
		t.Errorf("Expected first factor ID to be 'factor1', got %s", factors[0].ID)
	}

	if factors[0].Type != "totp" {
		t.Errorf("Expected first factor type to be 'totp', got %s", factors[0].Type)
	}

	if factors[1].Type != "recovery" {
		t.Errorf("Expected second factor type to be 'recovery', got %s", factors[1].Type)
	}
}

// TestListUserSessions tests the list user sessions functionality
func TestListUserSessions(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users/user123/sessions": {
			StatusCode: http.StatusOK,
			Body: []map[string]interface{}{
				{
					"id":         "session1",
					"user_id":    "user123",
					"factor":     "password",
					"ip_address": "127.0.0.1",
					"user_agent": "Mozilla/5.0",
				},
				{
					"id":         "session2",
					"user_id":    "user123",
					"factor":     "mfa",
					"ip_address": "192.168.1.1",
					"user_agent": "Chrome/91.0",
				},
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test listing user sessions
	sessions, err := client.ListUserSessions(ctx, "user123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(sessions) != 2 {
		t.Errorf("Expected 2 sessions, got %d", len(sessions))
	}

	if sessions[0].ID != "session1" {
		t.Errorf("Expected first session ID to be 'session1', got %s", sessions[0].ID)
	}

	if sessions[0].UserID != "user123" {
		t.Errorf("Expected first session user ID to be 'user123', got %s", sessions[0].UserID)
	}

	if sessions[1].Factor != "mfa" {
		t.Errorf("Expected second session factor to be 'mfa', got %s", sessions[1].Factor)
	}
}

// TestDeleteUserSessions tests the delete user sessions functionality
func TestDeleteUserSessions(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users/user123/sessions": {
			StatusCode: http.StatusNoContent,
			Body:       map[string]interface{}{},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test deleting user sessions
	err := client.DeleteUserSessions(ctx, "user123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

// TestSetUserRole tests the set user role functionality
func TestSetUserRole(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users/user123": {
			StatusCode: http.StatusOK,
			Body: map[string]interface{}{
				"id":    "user123",
				"email": "test@example.com",
				"role":  "admin",
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test setting user role
	user, err := client.SetUserRole(ctx, "user123", "admin")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if user.ID != "user123" {
		t.Errorf("Expected user ID to be 'user123', got %s", user.ID)
	}

	if user.Role != "admin" {
		t.Errorf("Expected role to be 'admin', got %s", user.Role)
	}
}

// TestBanUser tests the ban user functionality
func TestBanUser(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users/user123": {
			StatusCode: http.StatusOK,
			Body: map[string]interface{}{
				"id":     "user123",
				"email":  "test@example.com",
				"role":   "user",
				"banned": true,
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test banning a user
	user, err := client.BanUser(ctx, "user123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if user.ID != "user123" {
		t.Errorf("Expected user ID to be 'user123', got %s", user.ID)
	}

	if !user.Banned {
		t.Errorf("Expected user to be banned, got %v", user.Banned)
	}
}

// TestUnbanUser tests the unban user functionality
func TestUnbanUser(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users/user123": {
			StatusCode: http.StatusOK,
			Body: map[string]interface{}{
				"id":     "user123",
				"email":  "test@example.com",
				"role":   "user",
				"banned": false,
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test unbanning a user
	user, err := client.UnbanUser(ctx, "user123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if user.ID != "user123" {
		t.Errorf("Expected user ID to be 'user123', got %s", user.ID)
	}

	if user.Banned {
		t.Errorf("Expected user to not be banned, got %v", user.Banned)
	}
}
