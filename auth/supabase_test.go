package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	authtest "github.com/vndee/go-supabase-auth/auth/mock"
)

const (
	testProjectURL = "https://example.supabase.co"
	testAPIKey     = "test-api-key"
)

// TestNewClient tests the client creation
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

// TestClientWithConfig tests the client configuration
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

// TestClientWithHTTPClient tests setting a custom HTTP client
func TestClientWithHTTPClient(t *testing.T) {
	client := NewClient(testProjectURL, testAPIKey)
	customHTTPClient := &http.Client{
		Timeout: 30,
	}

	updatedClient := client.WithHTTPClient(customHTTPClient)

	if updatedClient.httpClient != customHTTPClient {
		t.Error("Expected HTTPClient to be updated with custom client")
	}
}

// TestGetUser tests getting a user by ID
func TestGetUser(t *testing.T) {
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
	ctx := context.Background()

	// Test getting a user
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

	if user.Role != "user" {
		t.Errorf("Expected role to be 'user', got %s", user.Role)
	}
}

// TestListUsers tests listing users
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

// TestCreateUser tests creating a user
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

// TestUpdateUser tests updating a user
func TestUpdateUser(t *testing.T) {
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

	// Test updating a user
	role := "admin"
	options := &UpdateUserOptions{
		Role: &role,
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

// TestDeleteUser tests deleting a user
func TestDeleteUser(t *testing.T) {
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
	ctx := context.Background()

	// Test deleting a user
	err := client.DeleteUser(ctx, "user123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

// TestVerifyToken tests token verification
func TestVerifyTokenWithAPI(t *testing.T) {
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
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test verifying a token
	user, err := client.VerifyTokenWithAPI(ctx, "valid-token")
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

// TestSignUpAndSignIn tests user signup and signin
func TestSignUpAndSignIn(t *testing.T) {
	// Setup mock HTTP client with responses for signup and signin
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/signup": {
			StatusCode: http.StatusOK,
			Body: map[string]interface{}{
				"access_token":  "signup-access-token",
				"refresh_token": "signup-refresh-token",
				"expires_in":    3600,
				"token_type":    "bearer",
				"user": map[string]interface{}{
					"id":    "new-user-id",
					"email": "new@example.com",
					"role":  "user",
				},
			},
		},
		"/auth/v1/token?grant_type=password": {
			StatusCode: http.StatusOK,
			Body: map[string]interface{}{
				"access_token":  "signin-access-token",
				"refresh_token": "signin-refresh-token",
				"expires_in":    3600,
				"token_type":    "bearer",
				"user": map[string]interface{}{
					"id":    "user123",
					"email": "test@example.com",
					"role":  "user",
				},
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test signup
	userData := map[string]interface{}{
		"name": "New User",
	}

	signupUser, err := client.SignUp(ctx, "new@example.com", "password123", userData)
	if err != nil {
		t.Fatalf("Expected no error for signup, got %v", err)
	}

	if signupUser.Email != "new@example.com" {
		t.Errorf("Expected signup email to be 'new@example.com', got %s", signupUser.Email)
	}

	if signupUser.ID != "new-user-id" {
		t.Errorf("Expected signup user ID to be 'new-user-id', got %s", signupUser.ID)
	}

	// Check if tokens were set
	accessToken, refreshToken, _ := client.GetSession()
	if accessToken != "signup-access-token" {
		t.Errorf("Expected access token to be 'signup-access-token', got %s", accessToken)
	}

	if refreshToken != "signup-refresh-token" {
		t.Errorf("Expected refresh token to be 'signup-refresh-token', got %s", refreshToken)
	}

	// Test signin
	signinUser, err := client.SignIn(ctx, "test@example.com", "password123")
	if err != nil {
		t.Fatalf("Expected no error for signin, got %v", err)
	}

	if signinUser.Email != "test@example.com" {
		t.Errorf("Expected signin email to be 'test@example.com', got %s", signinUser.Email)
	}

	if signinUser.ID != "user123" {
		t.Errorf("Expected signin user ID to be 'user123', got %s", signinUser.ID)
	}

	// Check if tokens were updated
	accessToken, refreshToken, _ = client.GetSession()
	if accessToken != "signin-access-token" {
		t.Errorf("Expected access token to be 'signin-access-token', got %s", accessToken)
	}

	if refreshToken != "signin-refresh-token" {
		t.Errorf("Expected refresh token to be 'signin-refresh-token', got %s", refreshToken)
	}
}

// TestSignOut tests signing out
func TestSignOut(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/logout": {
			StatusCode: http.StatusNoContent,
			Body:       map[string]interface{}{},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Set a mock session
	client.SetSession("test-access-token", "test-refresh-token", 3600)

	// Test signing out
	err := client.SignOut(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify session was cleared
	accessToken, refreshToken, _ := client.GetSession()
	if accessToken != "" || refreshToken != "" {
		t.Error("Expected tokens to be cleared after sign out")
	}
}

// TestRefreshSession tests refreshing a session
func TestRefreshSession(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/token?grant_type=refresh_token": {
			StatusCode: http.StatusOK,
			Body: map[string]interface{}{
				"access_token":  "new-access-token",
				"refresh_token": "new-refresh-token",
				"expires_in":    3600,
				"token_type":    "bearer",
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Set a mock session
	client.SetSession("old-access-token", "old-refresh-token", 3600)

	// Test refreshing session
	err := client.RefreshSession(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check if tokens were updated
	accessToken, refreshToken, _ := client.GetSession()
	if accessToken != "new-access-token" {
		t.Errorf("Expected access token to be 'new-access-token', got %s", accessToken)
	}

	if refreshToken != "new-refresh-token" {
		t.Errorf("Expected refresh token to be 'new-refresh-token', got %s", refreshToken)
	}
}

// TestCreateAuthProvider tests creating an auth provider
func TestCreateAuthProvider(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/providers": {
			StatusCode: http.StatusCreated,
			Body:       map[string]interface{}{},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test creating an auth provider
	options := map[string]interface{}{
		"client_id":     "test-client-id",
		"client_secret": "test-client-secret",
		"redirect_uri":  "https://example.com/callback",
	}

	err := client.CreateAuthProvider(ctx, "github", options)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

// TestUpdateAuthProvider tests updating an auth provider
func TestUpdateAuthProvider(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/providers/github": {
			StatusCode: http.StatusOK,
			Body:       map[string]interface{}{},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test updating an auth provider
	options := map[string]interface{}{
		"client_id":     "updated-client-id",
		"client_secret": "updated-client-secret",
	}

	err := client.UpdateAuthProvider(ctx, "github", options)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

// TestDeleteAuthProvider tests deleting an auth provider
func TestDeleteAuthProvider(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/providers/github": {
			StatusCode: http.StatusNoContent,
			Body:       map[string]interface{}{},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test deleting an auth provider
	err := client.DeleteAuthProvider(ctx, "github")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

// TestGetAuthSettings tests getting auth settings
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

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test getting auth settings
	settings, err := client.GetAuthSettings(ctx)
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

// TestUpdateAuthSettings tests updating auth settings
func TestUpdateAuthSettings(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/config": {
			StatusCode: http.StatusOK,
			Body:       map[string]interface{}{},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test updating auth settings
	settings := map[string]interface{}{
		"site_url":            "https://updated.example.com",
		"jwt_expiry":          7200,
		"enable_email_signup": false,
		"enable_phone_signup": true,
	}

	err := client.UpdateAuthSettings(ctx, settings)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

// TestListAuditLogs tests listing audit logs
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

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test listing audit logs
	options := map[string]string{
		"page":     "1",
		"per_page": "10",
	}

	logs, err := client.ListAuditLogs(ctx, options)
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

// TestGenerateLink tests generating an authentication link
func TestGenerateLink(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/generate_link": {
			StatusCode: http.StatusOK,
			Body: map[string]interface{}{
				"link":         "https://example.supabase.co/auth/v1/verify?token=test-token",
				"email":        "test@example.com",
				"user_id":      "user123",
				"generated_at": "2023-01-01T00:00:00Z",
				"expires_at":   "2023-01-01T01:00:00Z",
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

	if !strings.Contains(link.Link, "test-token") {
		t.Errorf("Expected link to contain 'test-token', got %s", link.Link)
	}
}

// TestInviteUserByEmail tests inviting a user by email
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

// TestListFactors tests listing MFA factors
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
}

// TestListUserSessions tests listing user sessions
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
}

// TestDeleteUserSessions tests deleting user sessions
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

// TestResetPasswordForEmail tests sending password reset emails
func TestResetPasswordForEmail(t *testing.T) {
	// Setup mock HTTP client
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/recover": {
			StatusCode: http.StatusOK,
			Body:       map[string]interface{}{},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test resetting password
	err := client.ResetPasswordForEmail(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

// TestSetUserRole tests setting a user's role
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

// TestBanUser tests banning a user
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

// TestUnbanUser tests unbanning a user
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

// TestCreateManyUsers tests creating multiple users in a batch
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

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
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

	results, err := client.CreateManyUsers(ctx, users)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}
}

// TestGenerateUserMigration tests generating a user migration token
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

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test generating a user migration token
	options := map[string]interface{}{
		"target_host": "https://new-project.supabase.co",
	}

	result, err := client.GenerateUserMigration(ctx, "user123", options)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result["token"] != "migration-token" {
		t.Errorf("Expected token to be 'migration-token', got %v", result["token"])
	}
}

// TestSignUpOrInError tests error cases for the signUpOrIn function
func TestSignUpOrInError(t *testing.T) {
	// Setup mock HTTP client for error response
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/signup": {
			StatusCode: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":   "invalid_credentials",
				"message": "Invalid email format",
			},
		},
		"/auth/v1/token?grant_type=password": {
			StatusCode: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":   "invalid_credentials",
				"message": "Invalid email format",
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test error from signUpOrIn - parsing error response
	_, err := client.SignUp(ctx, "invalid-email", "password", nil)
	if err == nil {
		t.Error("Expected error, got nil")
	}

	// Setup mock HTTP client for non-JSON response
	mockResponsesNonJSON := map[string]authtest.MockResponse{
		"/auth/v1/signup": {
			StatusCode: http.StatusBadRequest,
			Body:       "non-json error response",
		},
	}
	httpClientNonJSON := authtest.MockHTTPClient(t, mockResponsesNonJSON)

	// Create client with non-JSON mock HTTP client
	clientNonJSON := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClientNonJSON)

	// Test error from signUpOrIn - non-JSON error response
	_, err = clientNonJSON.SignUp(ctx, "test@example.com", "password", nil)
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if !strings.Contains(err.Error(), "error code") {
		t.Errorf("Expected error containing 'error code', got: %v", err)
	}
}

// TestRefreshSessionDetailedErrors tests specific error cases for RefreshSession
func TestRefreshSessionDetailedErrors(t *testing.T) {
	client := NewClient(testProjectURL, testAPIKey)

	// Test with no refresh token
	err := client.RefreshSession(context.Background())
	if err == nil || err.Error() != "no refresh token available" {
		t.Errorf("Expected 'no refresh token available' error, got: %v", err)
	}

	// Setup mock HTTP client for error response
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/token?grant_type=refresh_token": {
			StatusCode: http.StatusUnauthorized,
			Body: map[string]interface{}{
				"error":   "invalid_grant",
				"message": "Invalid refresh token",
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client and set refresh token
	client = NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	client.refreshToken = "invalid-refresh-token"

	// Test with invalid refresh token
	err = client.RefreshSession(context.Background())
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if !strings.Contains(err.Error(), "Invalid refresh token") {
		t.Errorf("Expected error containing 'Invalid refresh token', got: %v", err)
	}
}

// TestResetPasswordForEmailDetailedCases tests edge cases for ResetPasswordForEmail
func TestResetPasswordForEmailDetailedCases(t *testing.T) {
	// Setup mock HTTP client for success response
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/recover": {
			StatusCode: http.StatusOK,
			Body:       map[string]interface{}{},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test successful password reset
	err := client.ResetPasswordForEmail(ctx, "test@example.com")
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Setup mock HTTP client for error response
	mockErrorResponses := map[string]authtest.MockResponse{
		"/auth/v1/recover": {
			StatusCode: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":   "invalid_email",
				"message": "Email address not found",
			},
		},
	}
	httpErrorClient := authtest.MockHTTPClient(t, mockErrorResponses)

	// Create client with error mock HTTP client
	clientError := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpErrorClient)

	// Test error case
	err = clientError.ResetPasswordForEmail(ctx, "nonexistent@example.com")
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if !strings.Contains(err.Error(), "Email address not found") {
		t.Errorf("Expected error containing 'Email address not found', got: %v", err)
	}
}

// TestCreateUserErrorCases tests error cases for the CreateUser function
func TestCreateUserErrorCases(t *testing.T) {
	// Test with nil options
	client := NewClient(testProjectURL, testAPIKey)
	_, err := client.CreateUser(context.Background(), nil)
	if err == nil {
		t.Error("Expected error for nil options, got nil")
	}

	// Test with neither email nor phone
	_, err = client.CreateUser(context.Background(), &CreateUserOptions{})
	if err == nil {
		t.Error("Expected error for missing email and phone, got nil")
	}

	// Setup mock HTTP client for error response
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users": {
			StatusCode: http.StatusConflict,
			Body: map[string]interface{}{
				"error":   "email_taken",
				"message": "Email address is already taken",
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client = NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)

	// Test error case - email already taken
	options := &CreateUserOptions{
		Email:    "existing@example.com",
		Password: "password123",
	}

	_, err = client.CreateUser(context.Background(), options)
	if err == nil {
		t.Error("Expected error for email taken, got nil")
	}
	if !strings.Contains(err.Error(), "Email address is already taken") {
		t.Errorf("Expected error containing 'Email address is already taken', got: %v", err)
	}
}

// TestUpdateUserErrorCases tests error cases for the UpdateUser function
func TestUpdateUserErrorCases(t *testing.T) {
	// Test with nil options
	client := NewClient(testProjectURL, testAPIKey)
	_, err := client.UpdateUser(context.Background(), "user123", nil)
	if err == nil {
		t.Error("Expected error for nil options, got nil")
	}

	// Setup mock HTTP client for error response
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users/user123": {
			StatusCode: http.StatusNotFound,
			Body: map[string]interface{}{
				"error":   "user_not_found",
				"message": "User not found",
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client = NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)

	// Test error case - user not found
	email := "new@example.com"
	options := &UpdateUserOptions{
		Email: &email,
	}

	_, err = client.UpdateUser(context.Background(), "user123", options)
	if err == nil {
		t.Error("Expected error for user not found, got nil")
	}
	if !strings.Contains(err.Error(), "User not found") {
		t.Errorf("Expected error containing 'User not found', got: %v", err)
	}

	// Test error during JSON marshaling
	// This is hard to simulate directly, so we'll skip it for now
}

// TestCreateManyUsersDetailedCases tests error and edge cases for the CreateManyUsers function
func TestCreateManyUsersDetailedCases(t *testing.T) {
	// Setup mock HTTP client for success response
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users/batch": {
			StatusCode: http.StatusCreated,
			Body: []map[string]interface{}{
				{
					"id":    "user1",
					"email": "user1@example.com",
				},
				{
					"id":    "user2",
					"email": "user2@example.com",
				},
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test successful batch user creation with direct array response
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

	result, err := client.CreateManyUsers(ctx, users)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected 2 users, got %d", len(result))
	}

	// Setup mock HTTP client for error response
	mockErrorResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users/batch": {
			StatusCode: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":   "invalid_request",
				"message": "Invalid user data",
			},
		},
	}
	httpErrorClient := authtest.MockHTTPClient(t, mockErrorResponses)

	// Create client with error mock HTTP client
	clientError := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpErrorClient)

	// Test error case
	_, err = clientError.CreateManyUsers(ctx, users)
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if !strings.Contains(err.Error(), "Invalid user data") {
		t.Errorf("Expected error containing 'Invalid user data', got: %v", err)
	}

	// Setup mock HTTP client for wrapped response format
	mockWrappedResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users/batch": {
			StatusCode: http.StatusCreated,
			Body: map[string]interface{}{
				"results": []map[string]interface{}{
					{
						"id":    "user1",
						"email": "user1@example.com",
					},
					{
						"id":    "user2",
						"email": "user2@example.com",
					},
				},
			},
		},
	}
	httpWrappedClient := authtest.MockHTTPClient(t, mockWrappedResponses)

	// Create client with wrapped response mock HTTP client
	clientWrapped := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpWrappedClient)

	// Test success with wrapped response format
	result, err = clientWrapped.CreateManyUsers(ctx, users)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected 2 users, got %d", len(result))
	}
}

// TestGenerateLinkDetailedCases tests various cases for the GenerateLink function
func TestGenerateLinkDetailedCases(t *testing.T) {
	// Test with nil options
	client := NewClient(testProjectURL, testAPIKey)
	_, err := client.GenerateLink(context.Background(), LinkActionSignUp, nil)
	if err == nil {
		t.Error("Expected error for nil options, got nil")
	}

	// Test with empty email
	_, err = client.GenerateLink(context.Background(), LinkActionSignUp, &GenerateLinkOptions{})
	if err == nil {
		t.Error("Expected error for empty email, got nil")
	}

	// Setup mock HTTP client for success response
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/generate_link": {
			StatusCode: http.StatusOK,
			Body: map[string]interface{}{
				"link":         "https://example.com/auth/v1/verify?token=abc123",
				"email":        "test@example.com",
				"user_id":      "user123",
				"generated_at": "2023-01-01T00:00:00Z",
				"expires_at":   "2023-01-02T00:00:00Z",
			},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client = NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test successful link generation with all options
	options := &GenerateLinkOptions{
		Email:      "test@example.com",
		RedirectTo: "https://example.com/app",
		Data: map[string]interface{}{
			"key": "value",
		},
	}

	response, err := client.GenerateLink(ctx, LinkActionSignUp, options)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if response.Email != "test@example.com" {
		t.Errorf("Expected email to be 'test@example.com', got %s", response.Email)
	}

	if response.Link != "https://example.com/auth/v1/verify?token=abc123" {
		t.Errorf("Expected link to be 'https://example.com/auth/v1/verify?token=abc123', got %s", response.Link)
	}

	// Setup mock HTTP client for error response
	mockErrorResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/generate_link": {
			StatusCode: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":   "invalid_request",
				"message": "Invalid email format",
			},
		},
	}
	httpErrorClient := authtest.MockHTTPClient(t, mockErrorResponses)

	// Create client with error mock HTTP client
	clientError := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpErrorClient)

	// Test error case
	_, err = clientError.GenerateLink(ctx, LinkActionSignUp, options)
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if !strings.Contains(err.Error(), "Invalid email format") {
		t.Errorf("Expected error containing 'Invalid email format', got: %v", err)
	}
}

// TestSignOutDetailedErrors tests error cases for SignOut
func TestSignOutDetailedErrors(t *testing.T) {
	// Test signing out when not logged in
	client := NewClient(testProjectURL, testAPIKey)
	err := client.SignOut(context.Background())
	if err == nil || err.Error() != "not logged in" {
		t.Errorf("Expected 'not logged in' error, got: %v", err)
	}

	// Test with HTTP error during signout
	mockErrorResponses := map[string]authtest.MockResponse{
		"/auth/v1/logout": {
			StatusCode: http.StatusInternalServerError,
			Body:       "Server error during logout",
		},
	}
	httpErrorClient := authtest.MockHTTPClient(t, mockErrorResponses)

	// Create client with mock HTTP client and set access token
	clientError := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpErrorClient)
	clientError.accessToken = "test-access-token"

	// Test server error during signout
	err = clientError.SignOut(context.Background())
	if err == nil {
		t.Error("Expected error for server error during signout, got nil")
	}
	if !strings.Contains(err.Error(), "error signing out") {
		t.Errorf("Expected error containing 'error signing out', got: %v", err)
	}
}

// TestGenerateUserMigrationDetailedCases tests detailed cases for GenerateUserMigration
func TestGenerateUserMigrationDetailedCases(t *testing.T) {
	// Setup mock HTTP client for success response
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

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test with empty options
	result, err := client.GenerateUserMigration(ctx, "user123", nil)
	if err != nil {
		t.Fatalf("Expected no error for empty options, got %v", err)
	}
	if result["token"] != "migration-token" {
		t.Errorf("Expected token to be 'migration-token', got %v", result["token"])
	}

	// Setup mock HTTP client for error response
	mockErrorResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/users/invalid-user/migrate": {
			StatusCode: http.StatusNotFound,
			Body: map[string]interface{}{
				"error":   "user_not_found",
				"message": "User not found",
			},
		},
	}
	httpErrorClient := authtest.MockHTTPClient(t, mockErrorResponses)

	// Create client with error mock HTTP client
	clientError := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpErrorClient)

	// Test with invalid user
	_, err = clientError.GenerateUserMigration(ctx, "invalid-user", map[string]interface{}{})
	if err == nil {
		t.Error("Expected error for invalid user, got nil")
	}
	if !strings.Contains(err.Error(), "User not found") {
		t.Errorf("Expected error containing 'User not found', got: %v", err)
	}

	// Test JSON marshaling error - this is hard to test directly
	// but we could test with an invalid JSON input if needed
}

// TestUpdateAuthProviderDetailedCases tests detailed cases for UpdateAuthProvider
func TestUpdateAuthProviderDetailedCases(t *testing.T) {
	// Setup mock HTTP client for success response
	mockResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/providers/github": {
			StatusCode: http.StatusOK,
			Body:       map[string]interface{}{},
		},
	}
	httpClient := authtest.MockHTTPClient(t, mockResponses)

	// Create client with mock HTTP client
	client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
	ctx := context.Background()

	// Test with empty options
	err := client.UpdateAuthProvider(ctx, "github", nil)
	if err != nil {
		t.Fatalf("Expected no error for empty options, got %v", err)
	}

	// Setup mock HTTP client for error response
	mockErrorResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/providers/invalid-provider": {
			StatusCode: http.StatusNotFound,
			Body: map[string]interface{}{
				"error":   "provider_not_found",
				"message": "Provider not found",
			},
		},
	}
	httpErrorClient := authtest.MockHTTPClient(t, mockErrorResponses)

	// Create client with error mock HTTP client
	clientError := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpErrorClient)

	// Test with invalid provider
	err = clientError.UpdateAuthProvider(ctx, "invalid-provider", map[string]interface{}{})
	if err == nil {
		t.Error("Expected error for invalid provider, got nil")
	}
	if !strings.Contains(err.Error(), "Provider not found") {
		t.Errorf("Expected error containing 'Provider not found', got: %v", err)
	}
}

// TestGetAuthSettingsDetailedCases tests detailed cases for GetAuthSettings
func TestGetAuthSettingsDetailedCases(t *testing.T) {
	// Setup mock HTTP client for an error response
	mockErrorResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/config": {
			StatusCode: http.StatusUnauthorized,
			Body: map[string]interface{}{
				"error":   "unauthorized",
				"message": "Invalid API key",
			},
		},
	}
	httpErrorClient := authtest.MockHTTPClient(t, mockErrorResponses)

	// Create client with error mock HTTP client
	clientError := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpErrorClient)
	ctx := context.Background()

	// Test with unauthorized access
	_, err := clientError.GetAuthSettings(ctx)
	if err == nil {
		t.Error("Expected error for unauthorized access, got nil")
	}
	if !strings.Contains(err.Error(), "Invalid API key") {
		t.Errorf("Expected error containing 'Invalid API key', got: %v", err)
	}

	// Setup mock HTTP client for malformed JSON response
	mockMalformedResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/config": {
			StatusCode: http.StatusOK,
			Body:       "This is not valid JSON",
		},
	}
	httpMalformedClient := authtest.MockHTTPClient(t, mockMalformedResponses)

	// Create client with malformed response mock HTTP client
	clientMalformed := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpMalformedClient)

	// Test with malformed response
	_, err = clientMalformed.GetAuthSettings(ctx)
	if err == nil {
		t.Error("Expected error for malformed response, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse") {
		t.Errorf("Expected error containing 'failed to parse', got: %v", err)
	}
}

// TestUpdateAuthSettingsDetailedCases tests detailed cases for UpdateAuthSettings
func TestUpdateAuthSettingsDetailedCases(t *testing.T) {
	// Setup mock HTTP client for an error response
	mockErrorResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/config": {
			StatusCode: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":   "invalid_settings",
				"message": "Invalid auth settings",
			},
		},
	}
	httpErrorClient := authtest.MockHTTPClient(t, mockErrorResponses)

	// Create client with error mock HTTP client
	clientError := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpErrorClient)
	ctx := context.Background()

	// Test with invalid settings
	settings := map[string]interface{}{
		"invalid_setting": "value",
	}
	err := clientError.UpdateAuthSettings(ctx, settings)
	if err == nil {
		t.Error("Expected error for invalid settings, got nil")
	}
	if !strings.Contains(err.Error(), "Invalid auth settings") {
		t.Errorf("Expected error containing 'Invalid auth settings', got: %v", err)
	}

	// Setup mock HTTP client for non-JSON body error
	mockNonJSONResponses := map[string]authtest.MockResponse{
		"/auth/v1/admin/config": {
			StatusCode: http.StatusBadRequest,
			Body:       "This is not JSON",
		},
	}
	httpNonJSONClient := authtest.MockHTTPClient(t, mockNonJSONResponses)

	// Create client with non-JSON error mock HTTP client
	clientNonJSON := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpNonJSONClient)

	// Test with non-JSON error response
	err = clientNonJSON.UpdateAuthSettings(ctx, settings)
	if err == nil {
		t.Error("Expected error for non-JSON error response, got nil")
	}
	if !strings.Contains(err.Error(), "This is not JSON") {
		t.Errorf("Expected error containing 'This is not JSON', got: %v", err)
	}
}

// TestVerifyJWT tests the local token verification function
func TestVerifyJWT(t *testing.T) {
	// This is a test JWT with the following claims:
	// {
	//   "sub": "test-user-id",
	//   "role": "authenticated",
	//   "email": "test@example.com",
	//   "exp": <future timestamp>,
	//   "iat": <past timestamp>,
	//   "iss": "test-issuer"
	// }
	// Secret used: "test-jwt-secret"

	// Create a real token for testing
	claims := jwt.MapClaims{
		"sub":   "test-user-id",
		"role":  "authenticated",
		"email": "test@example.com",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Add(-5 * time.Minute).Unix(),
		"iss":   "test-issuer",
		"app_metadata": map[string]interface{}{
			"provider": "email",
		},
		"user_metadata": map[string]interface{}{
			"name": "Test User",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	validToken, err := token.SignedString([]byte("test-jwt-secret"))
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Create an expired token
	expiredClaims := jwt.MapClaims{
		"sub":   "test-user-id",
		"role":  "authenticated",
		"email": "test@example.com",
		"exp":   time.Now().Add(-1 * time.Hour).Unix(),
		"iat":   time.Now().Add(-2 * time.Hour).Unix(),
		"iss":   "test-issuer",
	}

	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	invalidToken, err := expiredToken.SignedString([]byte("test-jwt-secret"))
	if err != nil {
		t.Fatalf("Failed to create expired test token: %v", err)
	}

	// Create token with wrong issuer
	wrongIssuerClaims := jwt.MapClaims{
		"sub":   "test-user-id",
		"role":  "authenticated",
		"email": "test@example.com",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iss":   "wrong-issuer",
	}

	wrongIssuerToken := jwt.NewWithClaims(jwt.SigningMethodHS256, wrongIssuerClaims)
	issuerToken, err := wrongIssuerToken.SignedString([]byte("test-jwt-secret"))
	if err != nil {
		t.Fatalf("Failed to create wrong issuer test token: %v", err)
	}

	// Test cases
	tests := []struct {
		name        string
		token       string
		secret      string
		issuer      string
		wantErr     bool
		expectedErr error
	}{
		{
			name:    "Valid token",
			token:   validToken,
			secret:  "test-jwt-secret",
			issuer:  "test-issuer",
			wantErr: false,
		},
		{
			name:        "Expired token",
			token:       invalidToken,
			secret:      "test-jwt-secret",
			issuer:      "test-issuer",
			wantErr:     true,
			expectedErr: ErrExpiredToken,
		},
		{
			name:        "Invalid signature",
			token:       validToken,
			secret:      "wrong-secret",
			issuer:      "test-issuer",
			wantErr:     true,
			expectedErr: ErrInvalidToken,
		},
		{
			name:        "Wrong issuer",
			token:       issuerToken,
			secret:      "test-jwt-secret",
			issuer:      "test-issuer",
			wantErr:     true,
			expectedErr: ErrInvalidToken,
		},
		{
			name:    "No issuer check",
			token:   issuerToken,
			secret:  "test-jwt-secret",
			issuer:  "", // Empty means don't check issuer
			wantErr: false,
		},
		{
			name:        "Invalid token format",
			token:       "not.a.validtoken",
			secret:      "test-jwt-secret",
			issuer:      "test-issuer",
			wantErr:     true,
			expectedErr: ErrInvalidToken,
		},
	}

	client := NewClient(testProjectURL, testAPIKey)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := client.VerifyJWT(tt.token, tt.secret, tt.issuer)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got nil")
					return
				}

				if tt.expectedErr != nil && !errors.Is(err, tt.expectedErr) {
					t.Errorf("Expected error %v, got %v", tt.expectedErr, err)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Verify payload for valid token
			if payload.Sub != "test-user-id" {
				t.Errorf("Expected subject 'test-user-id', got '%s'", payload.Sub)
			}

			if payload.Email != "test@example.com" {
				t.Errorf("Expected email 'test@example.com', got '%s'", payload.Email)
			}

			if payload.Role != "authenticated" {
				t.Errorf("Expected role 'authenticated', got '%s'", payload.Role)
			}
		})
	}
}
