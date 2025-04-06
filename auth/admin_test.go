package auth

import (
	"context"
	"net/http"
	"strings"
	"testing"

	authtest "github.com/vndee/go-supabase-auth/auth/mock"
)

func TestNewAdmin(t *testing.T) {
	admin := NewAdmin(testProjectURL, testAPIKey)

	if admin.client.config.ProjectURL != testProjectURL {
		t.Errorf("Expected ProjectURL to be %s, got %s", testProjectURL, admin.client.config.ProjectURL)
	}

	if admin.client.config.APIKey != testAPIKey {
		t.Errorf("Expected APIKey to be %s, got %s", testAPIKey, admin.client.config.APIKey)
	}
}

func TestAdminWithClient(t *testing.T) {
	admin := NewAdmin(testProjectURL, testAPIKey)
	client := NewClient("https://new.supabase.co", "new-api-key")

	updatedAdmin := admin.WithClient(client)

	if updatedAdmin.client != client {
		t.Error("Expected admin client to be updated with new client")
	}
}

func TestAdminClient(t *testing.T) {
	admin := NewAdmin(testProjectURL, testAPIKey)
	client := admin.Client()

	if client != admin.client {
		t.Error("Expected Client() to return the admin's client")
	}
}

func TestCreateAuthProvider(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/providers": {
			StatusCode: http.StatusCreated,
			Body:       map[string]interface{}{},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create admin with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	admin := NewAdmin(testProjectURL, testAPIKey).WithClient(client)
	ctx := context.Background()

	// Test creating an auth provider
	options := map[string]interface{}{
		"client_id":     "test-client-id",
		"client_secret": "test-client-secret",
		"redirect_uri":  "https://example.com/callback",
	}

	err := admin.CreateAuthProvider(ctx, "github", options)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestUpdateAuthProvider(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/providers/github": {
			StatusCode: http.StatusOK,
			Body:       map[string]interface{}{},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create admin with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	admin := NewAdmin(testProjectURL, testAPIKey).WithClient(client)
	ctx := context.Background()

	// Test updating an auth provider
	options := map[string]interface{}{
		"client_id":     "updated-client-id",
		"client_secret": "updated-client-secret",
	}

	err := admin.UpdateAuthProvider(ctx, "github", options)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestDeleteAuthProvider(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/providers/github": {
			StatusCode: http.StatusNoContent,
			Body:       map[string]interface{}{},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create admin with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	admin := NewAdmin(testProjectURL, testAPIKey).WithClient(client)
	ctx := context.Background()

	// Test deleting an auth provider
	err := admin.DeleteAuthProvider(ctx, "github")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestGetAuthSettings(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/config": {
			StatusCode: http.StatusOK,
			Body: map[string]interface{}{
				"site_url": "https://example.com",
				"additional_redirect_urls": []string{
					"https://example.com/callback",
				},
				"jwt_expiry":                          3600,
				"disable_signup":                      false,
				"enable_email_signup":                 true,
				"enable_email_autoconfirm":            true,
				"enable_phone_signup":                 false,
				"enable_phone_autoconfirm":            false,
				"disable_login_for_non_invited_users": false,
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create admin with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	admin := NewAdmin(testProjectURL, testAPIKey).WithClient(client)
	ctx := context.Background()

	// Test getting auth settings
	settings, err := admin.GetAuthSettings(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if settings["site_url"] != "https://example.com" {
		t.Errorf("Expected site_url to be 'https://example.com', got %v", settings["site_url"])
	}

	if settings["jwt_expiry"].(float64) != 3600 {
		t.Errorf("Expected jwt_expiry to be 3600, got %v", settings["jwt_expiry"])
	}
}

func TestUpdateAuthSettings(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/config": {
			StatusCode: http.StatusOK,
			Body:       map[string]interface{}{},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create admin with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	admin := NewAdmin(testProjectURL, testAPIKey).WithClient(client)
	ctx := context.Background()

	// Test updating auth settings
	settings := map[string]interface{}{
		"site_url":            "https://updated.example.com",
		"jwt_expiry":          7200,
		"enable_email_signup": false,
		"enable_phone_signup": true,
	}

	err := admin.UpdateAuthSettings(ctx, settings)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestListAuditLogs(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/audit": {
			StatusCode: http.StatusOK,
			Body: []map[string]interface{}{
				{
					"id":        "log1",
					"timestamp": "2023-01-01T00:00:00Z",
					"event":     "user.create",
					"user_id":   "user123",
					"ip":        "127.0.0.1",
				},
				{
					"id":        "log2",
					"timestamp": "2023-01-02T00:00:00Z",
					"event":     "user.login",
					"user_id":   "user123",
					"ip":        "127.0.0.1",
				},
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create admin with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	admin := NewAdmin(testProjectURL, testAPIKey).WithClient(client)
	ctx := context.Background()

	// Test listing audit logs
	options := map[string]string{
		"page":     "1",
		"per_page": "10",
	}

	logs, err := admin.ListAuditLogs(ctx, options)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(logs) != 2 {
		t.Errorf("Expected 2 logs, got %d", len(logs))
	}

	if logs[0]["event"] != "user.create" {
		t.Errorf("Expected first log event to be 'user.create', got %v", logs[0]["event"])
	}

	if logs[1]["event"] != "user.login" {
		t.Errorf("Expected second log event to be 'user.login', got %v", logs[1]["event"])
	}
}

func TestCreateManyUsers(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users/batch": {
			StatusCode: http.StatusCreated,
			Body: []map[string]interface{}{
				{
					"id":    "user1",
					"email": "user1@example.com",
					"role":  "user",
				},
				{
					"id":    "user2",
					"email": "user2@example.com",
					"role":  "user",
				},
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create admin with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	admin := NewAdmin(testProjectURL, testAPIKey).WithClient(client)
	ctx := context.Background()

	// Test creating many users
	users := []*CreateUserOptions{
		{
			Email:    "user1@example.com",
			Password: "password1",
		},
		{
			Email:    "user2@example.com",
			Password: "password2",
		},
	}

	results, err := admin.CreateManyUsers(ctx, users)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}
}

func TestGenerateUserMigration(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users/user123/migrate": {
			StatusCode: http.StatusOK,
			Body: map[string]interface{}{
				"token":      "migration-token",
				"expires_at": "2023-01-01T00:00:00Z",
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create admin with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	admin := NewAdmin(testProjectURL, testAPIKey).WithClient(client)
	ctx := context.Background()

	// Test generating a user migration token
	options := map[string]interface{}{
		"target_host": "https://new-project.supabase.co",
	}

	result, err := admin.GenerateUserMigration(ctx, "user123", options)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result["token"] != "migration-token" {
		t.Errorf("Expected token to be 'migration-token', got %v", result["token"])
	}
}

// TestAdminGetUser tests the convenience method for getting a user
func TestAdminGetUser(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users/user123": {
			StatusCode: http.StatusOK,
			Body: map[string]interface{}{
				"id":    "user123",
				"email": "test@example.com",
				"role":  "user",
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	admin := NewAdmin(testProjectURL, testAPIKey).WithClient(client)
	ctx := context.Background()

	// Test getting a user
	user, err := admin.GetUser(ctx, "user123")
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

// TestAdminListUsers tests the convenience method for listing users
func TestAdminListUsers(t *testing.T) {
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
	admin := NewAdmin(testProjectURL, testAPIKey).WithClient(client)
	ctx := context.Background()

	// Test listing users
	options := &ListUsersOptions{
		Page:    1,
		PerPage: 10,
	}

	users, err := admin.ListUsers(ctx, options)
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

// TestAdminCreateUser tests the convenience method for creating a user
func TestAdminCreateUser(t *testing.T) {
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
	admin := NewAdmin(testProjectURL, testAPIKey).WithClient(client)
	ctx := context.Background()

	// Test creating a user
	options := &CreateUserOptions{
		Email:    "new@example.com",
		Password: "password123",
		UserMetadata: map[string]interface{}{
			"name": "New User",
		},
	}

	user, err := admin.CreateUser(ctx, options)
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

// TestAdminUpdateUser tests the convenience method for updating a user
func TestAdminUpdateUser(t *testing.T) {
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
	admin := NewAdmin(testProjectURL, testAPIKey).WithClient(client)
	ctx := context.Background()

	// Test updating a user
	role := "admin"
	options := &UpdateUserOptions{
		Role: &role,
		UserMetadata: map[string]interface{}{
			"name": "Updated User",
		},
	}

	user, err := admin.UpdateUser(ctx, "user123", options)
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

// TestAdminDeleteUser tests the convenience method for deleting a user
func TestAdminDeleteUser(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users/user123": {
			StatusCode: http.StatusNoContent,
			Body:       map[string]interface{}{},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	admin := NewAdmin(testProjectURL, testAPIKey).WithClient(client)
	ctx := context.Background()

	// Test deleting a user
	err := admin.DeleteUser(ctx, "user123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

// TestCreateUserEdgeCases tests edge cases for the CreateUser function
func TestCreateUserEdgeCases(t *testing.T) {
	testCases := []struct {
		name          string
		options       *CreateUserOptions
		responseCode  int
		responseBody  map[string]interface{}
		expectedError bool
		errorContains string
	}{
		{
			name:          "nil options",
			options:       nil,
			expectedError: true,
			errorContains: "options cannot be nil",
		},
		{
			name: "missing email and phone",
			options: &CreateUserOptions{
				Password: "password123",
			},
			expectedError: true,
			errorContains: "either email or phone must be provided",
		},
		{
			name: "email already taken",
			options: &CreateUserOptions{
				Email:    "existing@example.com",
				Password: "password123",
			},
			responseCode: http.StatusConflict,
			responseBody: map[string]interface{}{
				"error":   "conflict",
				"message": "Email already taken",
				"code":    "409.1",
			},
			expectedError: true,
			errorContains: "Email already taken",
		},
		{
			name: "invalid password",
			options: &CreateUserOptions{
				Email:    "test@example.com",
				Password: "short",
			},
			responseCode: http.StatusBadRequest,
			responseBody: map[string]interface{}{
				"error":   "invalid_password",
				"message": "Password too short",
				"code":    "400.1",
			},
			expectedError: true,
			errorContains: "Password too short",
		},
		{
			name: "server error",
			options: &CreateUserOptions{
				Email:    "test@example.com",
				Password: "password123",
			},
			responseCode: http.StatusInternalServerError,
			responseBody: map[string]interface{}{
				"error":   "internal_server_error",
				"message": "Internal server error",
			},
			expectedError: true,
			errorContains: "Internal server error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var mockResponses map[string]authtest.MockResponse

			if tc.responseCode > 0 {
				mockResponses = map[string]authtest.MockResponse{
					"/auth/v1/admin/users": {
						StatusCode: tc.responseCode,
						Body:       tc.responseBody,
					},
				}
			}

			httpClient := authtest.MockHTTPClient(t, mockResponses)
			client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
			ctx := context.Background()

			_, err := client.CreateUser(ctx, tc.options)

			// Check if error was expected
			if tc.expectedError && err == nil {
				t.Fatalf("Expected error, got nil")
			}

			if !tc.expectedError && err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			// If error was expected, check the error message
			if tc.expectedError && err != nil {
				if !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("Expected error to contain '%s', got '%s'", tc.errorContains, err.Error())
				}
			}
		})
	}
}

// TestUpdateUserEdgeCases tests edge cases for the UpdateUser function
func TestUpdateUserEdgeCases(t *testing.T) {
	testCases := []struct {
		name          string
		userID        string
		options       *UpdateUserOptions
		responseCode  int
		responseBody  map[string]interface{}
		expectedError bool
		errorContains string
	}{
		{
			name:          "nil options",
			userID:        "user123",
			options:       nil,
			expectedError: true,
			errorContains: "options cannot be nil",
		},
		{
			name:   "user not found",
			userID: "nonexistent",
			options: &UpdateUserOptions{
				UserMetadata: map[string]interface{}{
					"name": "Updated User",
				},
			},
			responseCode: http.StatusNotFound,
			responseBody: map[string]interface{}{
				"error":   "not_found",
				"message": "User not found",
			},
			expectedError: true,
			errorContains: "User not found",
		},
		{
			name:   "invalid email format",
			userID: "user123",
			options: &UpdateUserOptions{
				Email: stringPtr("not-an-email"),
			},
			responseCode: http.StatusBadRequest,
			responseBody: map[string]interface{}{
				"error":   "invalid_email",
				"message": "Invalid email format",
			},
			expectedError: true,
			errorContains: "Invalid email format",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var mockResponses map[string]authtest.MockResponse

			if tc.responseCode > 0 {
				mockResponses = map[string]authtest.MockResponse{
					"/auth/v1/admin/users/" + tc.userID: {
						StatusCode: tc.responseCode,
						Body:       tc.responseBody,
					},
				}
			}

			httpClient := authtest.MockHTTPClient(t, mockResponses)
			client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
			ctx := context.Background()

			_, err := client.UpdateUser(ctx, tc.userID, tc.options)

			// Check if error was expected
			if tc.expectedError && err == nil {
				t.Fatalf("Expected error, got nil")
			}

			if !tc.expectedError && err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			// If error was expected, check the error message
			if tc.expectedError && err != nil {
				if !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("Expected error to contain '%s', got '%s'", tc.errorContains, err.Error())
				}
			}
		})
	}
}

// TestCreateManyUsersEdgeCases tests edge cases for the CreateManyUsers function
func TestCreateManyUsersEdgeCases(t *testing.T) {
	// Setup mock HTTP client with error response
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users/batch": {
			StatusCode: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":   "validation_error",
				"message": "Invalid user data",
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create admin with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	admin := NewAdmin(testProjectURL, testAPIKey).WithClient(client)
	ctx := context.Background()

	// Test with invalid user data
	users := []*CreateUserOptions{
		{
			// Missing email and phone
			Password: "password",
		},
	}

	_, err := admin.CreateManyUsers(ctx, users)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !strings.Contains(err.Error(), "Invalid user data") {
		t.Errorf("Expected error message to contain 'Invalid user data', got %v", err)
	}
}

// TestGenerateLinkEdgeCases tests edge cases for the GenerateLink function
func TestGenerateLinkEdgeCases(t *testing.T) {
	testCases := []struct {
		name          string
		action        LinkAction
		options       *GenerateLinkOptions
		mockResponse  authtest.MockResponse
		expectedError bool
		errorContains string
	}{
		{
			name:          "nil options",
			action:        LinkActionSignUp,
			options:       nil,
			expectedError: true,
			errorContains: "email is required",
		},
		{
			name:   "missing email",
			action: LinkActionSignUp,
			options: &GenerateLinkOptions{
				RedirectTo: "https://example.com",
			},
			expectedError: true,
			errorContains: "email is required",
		},
		{
			name:   "invalid email",
			action: LinkActionSignUp,
			options: &GenerateLinkOptions{
				Email: "not-an-email",
			},
			mockResponse: authtest.MockResponse{
				StatusCode: http.StatusBadRequest,
				Body: map[string]interface{}{
					"error":   "invalid_email",
					"message": "Invalid email format",
				},
			},
			expectedError: true,
			errorContains: "Invalid email format",
		},
		{
			name:   "rate limited",
			action: LinkActionRecovery,
			options: &GenerateLinkOptions{
				Email: "test@example.com",
			},
			mockResponse: authtest.MockResponse{
				StatusCode: http.StatusTooManyRequests,
				Body: map[string]interface{}{
					"error":   "rate_limited",
					"message": "Too many requests",
				},
			},
			expectedError: true,
			errorContains: "Too many requests",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock client
			var mockResponses map[string]authtest.MockResponse

			if tc.mockResponse.StatusCode > 0 {
				mockResponses = map[string]authtest.MockResponse{
					"/auth/v1/admin/generate_link": tc.mockResponse,
				}
			}

			httpClient := authtest.MockHTTPClient(t, mockResponses)
			client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
			ctx := context.Background()

			// Call the function
			_, err := client.GenerateLink(ctx, tc.action, tc.options)

			// Check expectations
			if tc.expectedError && err == nil {
				t.Fatal("Expected error, got nil")
			}

			if !tc.expectedError && err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			if tc.expectedError && err != nil {
				if !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("Expected error to contain '%s', got '%s'", tc.errorContains, err.Error())
				}
			}
		})
	}
}

// TestGetUserEdgeCases tests edge cases for the GetUser function
func TestGetUserEdgeCases(t *testing.T) {
	// Test with server error
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users/user123": {
			StatusCode: http.StatusInternalServerError,
			Body: map[string]interface{}{
				"error":   "internal_error",
				"message": "Server error",
			},
		},
	}

	httpClient := authtest.MockHTTPClient(t, mockResponses)
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	_, err := client.GetUser(ctx, "user123")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !strings.Contains(err.Error(), "Server error") {
		t.Errorf("Expected error message to contain 'Server error', got %v", err)
	}

	// Test with non-existent user
	mockResponses = map[string]authtest.MockResponse{
		"/auth/v1/admin/users/nonexistent": {
			StatusCode: http.StatusNotFound,
			Body: map[string]interface{}{
				"error":   "not_found",
				"message": "User not found",
			},
		},
	}

	httpClient = authtest.MockHTTPClient(t, mockResponses)
	client = client.WithHTTPClient(httpClient)

	_, err = client.GetUser(ctx, "nonexistent")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !strings.Contains(err.Error(), "User not found") {
		t.Errorf("Expected error message to contain 'User not found', got %v", err)
	}

	// Test with invalid JSON response
	mockResponses = map[string]authtest.MockResponse{
		"/auth/v1/admin/users/user123": {
			StatusCode: http.StatusOK,
			Body:       "invalid json", // Not a map, will cause JSON parsing error
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		},
	}

	httpClient = authtest.MockHTTPClient(t, mockResponses)
	client = client.WithHTTPClient(httpClient)

	_, err = client.GetUser(ctx, "user123")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !strings.Contains(err.Error(), "failed") {
		t.Errorf("Expected error message to contain 'failed', got %v", err)
	}
}
