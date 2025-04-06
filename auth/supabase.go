// Package auth provides a comprehensive SDK for Supabase Authentication.
package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client represents a Supabase client that handles both user and admin operations
type Client struct {
	config     *Config
	httpClient *http.Client

	// Session information
	accessToken  string
	refreshToken string
	tokenExpiry  time.Time
}

// NewClient creates a new Supabase client with default configuration
func NewClient(projectURL, apiKey string) *Client {
	return &Client{
		config: &Config{
			ProjectURL:        projectURL,
			APIKey:            apiKey,
			AutoRefreshTokens: true,
			PersistSession:    true,
		},
		httpClient: &http.Client{
			Timeout: time.Second * 10,
		},
	}
}

// WithConfig returns a client with a custom configuration
func (c *Client) WithConfig(config *Config) *Client {
	c.config = config
	return c
}

// WithHTTPClient returns a client with a custom HTTP client
func (c *Client) WithHTTPClient(httpClient *http.Client) *Client {
	c.httpClient = httpClient
	return c
}

// GetUser retrieves a user by their ID
func (c *Client) GetUser(ctx context.Context, userID string) (*User, error) {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/users/%s", c.config.ProjectURL, userID)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(resp)
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedParsing, err.Error())
	}

	return &user, nil
}

// ListUsers returns a list of users with pagination
func (c *Client) ListUsers(ctx context.Context, options *ListUsersOptions) (*UserList, error) {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/users", c.config.ProjectURL)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	q := req.URL.Query()
	if options != nil {
		if options.Page > 0 {
			q.Add("page", fmt.Sprintf("%d", options.Page))
		}
		if options.PerPage > 0 {
			q.Add("per_page", fmt.Sprintf("%d", options.PerPage))
		}
		if options.Filter != "" {
			q.Add("filter", options.Filter)
		}
		if options.SortBy != "" {
			q.Add("sort_by", options.SortBy)
		}
		if options.SortOrder != "" {
			q.Add("sort_order", options.SortOrder)
		}
	}
	req.URL.RawQuery = q.Encode()

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(resp)
	}

	var userList UserList
	if err := json.NewDecoder(resp.Body).Decode(&userList); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedParsing, err.Error())
	}

	return &userList, nil
}

// CreateUser creates a new user with the specified properties
func (c *Client) CreateUser(ctx context.Context, options *CreateUserOptions) (*User, error) {
	if options == nil {
		return nil, fmt.Errorf("%w: options cannot be nil", ErrInvalidArgument)
	}

	if options.Email == "" && options.Phone == "" {
		return nil, fmt.Errorf("%w: either email or phone must be provided", ErrInvalidArgument)
	}

	endpoint := fmt.Sprintf("%s/auth/v1/admin/users", c.config.ProjectURL)

	jsonData, err := json.Marshal(options)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedEncoding, err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, handleErrorResponse(resp)
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedParsing, err.Error())
	}

	return &user, nil
}

// UpdateUser updates an existing user with new properties
func (c *Client) UpdateUser(ctx context.Context, userID string, options *UpdateUserOptions) (*User, error) {
	if options == nil {
		return nil, fmt.Errorf("%w: options cannot be nil", ErrInvalidArgument)
	}

	endpoint := fmt.Sprintf("%s/auth/v1/admin/users/%s", c.config.ProjectURL, userID)

	jsonData, err := json.Marshal(options)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedEncoding, err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(resp)
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedParsing, err.Error())
	}

	return &user, nil
}

// DeleteUser deletes a user by their ID
func (c *Client) DeleteUser(ctx context.Context, userID string) error {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/users/%s", c.config.ProjectURL, userID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return handleErrorResponse(resp)
	}

	return nil
}

// VerifyToken validates a JWT token and returns the user information
func (c *Client) VerifyToken(ctx context.Context, token string) (*User, error) {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/verify-token", c.config.ProjectURL)

	data := map[string]string{
		"token": token,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedEncoding, err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(resp)
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedParsing, err.Error())
	}

	return &user, nil
}

// SignUp registers a new user with email and password
func (c *Client) SignUp(ctx context.Context, email, password string, userData map[string]interface{}) (*User, error) {
	data := map[string]interface{}{
		"email":    email,
		"password": password,
		"data":     userData,
	}

	return c.signUpOrIn(ctx, "/auth/v1/signup", data)
}

// SignIn authenticates a user with email and password
func (c *Client) SignIn(ctx context.Context, email, password string) (*User, error) {
	data := map[string]interface{}{
		"email":    email,
		"password": password,
	}

	return c.signUpOrIn(ctx, "/auth/v1/token?grant_type=password", data)
}

// SignOut invalidates all session tokens for a user
func (c *Client) SignOut(ctx context.Context) error {
	if c.accessToken == "" {
		return errors.New("not logged in")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/auth/v1/logout", c.config.ProjectURL), nil)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", c.config.APIKey)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error signing out: %s", string(bodyBytes))
	}

	c.accessToken = ""
	c.refreshToken = ""

	return nil
}

// RefreshSession refreshes the access token using the refresh token
func (c *Client) RefreshSession(ctx context.Context) error {
	if c.refreshToken == "" {
		return errors.New("no refresh token available")
	}

	data := map[string]interface{}{
		"refresh_token": c.refreshToken,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedEncoding, err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/auth/v1/token?grant_type=refresh_token", c.config.ProjectURL), bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", c.config.APIKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return err
		}
		return fmt.Errorf("error refreshing token: %s", errResp.Message)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("%w: %s", ErrFailedParsing, err.Error())
	}

	c.accessToken = tokenResp.AccessToken
	c.refreshToken = tokenResp.RefreshToken
	c.tokenExpiry = time.Now().Add(time.Second * time.Duration(tokenResp.ExpiresIn))

	if c.config.TokenCallback != nil {
		c.config.TokenCallback(c.accessToken, c.refreshToken)
	}

	return nil
}

// CreateAuthProvider enables a new auth provider
func (c *Client) CreateAuthProvider(ctx context.Context, provider string, options map[string]interface{}) error {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/providers", c.config.ProjectURL)

	data := map[string]interface{}{
		"provider": provider,
	}

	for k, v := range options {
		data[k] = v
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedEncoding, err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return handleErrorResponse(resp)
	}

	return nil
}

// UpdateAuthProvider updates an existing auth provider
func (c *Client) UpdateAuthProvider(ctx context.Context, provider string, options map[string]interface{}) error {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/providers/%s", c.config.ProjectURL, provider)

	jsonData, err := json.Marshal(options)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedEncoding, err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return handleErrorResponse(resp)
	}

	return nil
}

// DeleteAuthProvider disables an auth provider
func (c *Client) DeleteAuthProvider(ctx context.Context, provider string) error {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/providers/%s", c.config.ProjectURL, provider)

	req, err := http.NewRequestWithContext(ctx, "DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return handleErrorResponse(resp)
	}

	return nil
}

// GetAuthSettings gets the auth settings for the project
func (c *Client) GetAuthSettings(ctx context.Context) (map[string]interface{}, error) {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/config", c.config.ProjectURL)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(resp)
	}

	var settings map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&settings); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedParsing, err.Error())
	}

	return settings, nil
}

// UpdateAuthSettings updates the auth settings for the project
func (c *Client) UpdateAuthSettings(ctx context.Context, settings map[string]interface{}) error {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/config", c.config.ProjectURL)

	jsonData, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedEncoding, err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return handleErrorResponse(resp)
	}

	return nil
}

// ListAuditLogs retrieves the audit logs for the project
func (c *Client) ListAuditLogs(ctx context.Context, options map[string]string) ([]map[string]interface{}, error) {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/audit", c.config.ProjectURL)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	q := req.URL.Query()
	for k, v := range options {
		q.Add(k, v)
	}
	req.URL.RawQuery = q.Encode()

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(resp)
	}

	var logs []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedParsing, err.Error())
	}

	return logs, nil
}

// GenerateLink generates an email link for a specific action
func (c *Client) GenerateLink(ctx context.Context, action LinkAction, options *GenerateLinkOptions) (*LinkResponse, error) {
	if options == nil || options.Email == "" {
		return nil, fmt.Errorf("%w: email is required", ErrInvalidArgument)
	}

	endpoint := fmt.Sprintf("%s/auth/v1/admin/generate_link", c.config.ProjectURL)

	data := map[string]interface{}{
		"type":  string(action),
		"email": options.Email,
	}

	if options.RedirectTo != "" {
		data["redirect_to"] = options.RedirectTo
	}

	if options.Data != nil {
		data["data"] = options.Data
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedEncoding, err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(resp)
	}

	var linkResp LinkResponse
	if err := json.NewDecoder(resp.Body).Decode(&linkResp); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedParsing, err.Error())
	}

	return &linkResp, nil
}

// InviteUserByEmail creates a user and sends an invite link
func (c *Client) InviteUserByEmail(ctx context.Context, email string, options *InviteOptions) (*User, error) {
	if email == "" {
		return nil, fmt.Errorf("%w: email is required", ErrInvalidArgument)
	}

	endpoint := fmt.Sprintf("%s/auth/v1/admin/invite", c.config.ProjectURL)

	data := map[string]interface{}{
		"email": email,
	}

	if options != nil {
		if options.RedirectTo != "" {
			data["redirect_to"] = options.RedirectTo
		}

		if options.Data != nil {
			data["data"] = options.Data
		}

		if options.UserMetadata != nil {
			data["user_metadata"] = options.UserMetadata
		}
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedEncoding, err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(resp)
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedParsing, err.Error())
	}

	return &user, nil
}

// ListFactors lists all MFA factors for a user
func (c *Client) ListFactors(ctx context.Context, userID string) ([]Factor, error) {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/users/%s/factors", c.config.ProjectURL, userID)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(resp)
	}

	var factors []Factor
	if err := json.NewDecoder(resp.Body).Decode(&factors); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedParsing, err.Error())
	}

	return factors, nil
}

// ListUserSessions lists all active sessions for a user
func (c *Client) ListUserSessions(ctx context.Context, userID string) ([]Session, error) {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/users/%s/sessions", c.config.ProjectURL, userID)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(resp)
	}

	var sessions []Session
	if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedParsing, err.Error())
	}

	return sessions, nil
}

// DeleteUserSessions invalidates all sessions for a user
func (c *Client) DeleteUserSessions(ctx context.Context, userID string) error {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/users/%s/sessions", c.config.ProjectURL, userID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return handleErrorResponse(resp)
	}

	return nil
}

// ResetPasswordForEmail sends a password reset email
func (c *Client) ResetPasswordForEmail(ctx context.Context, email string) error {
	data := map[string]interface{}{
		"email": email,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedEncoding, err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/auth/v1/recover", c.config.ProjectURL), bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", c.config.APIKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return err
		}
		return fmt.Errorf("error sending password reset: %s", errResp.Message)
	}

	return nil
}

// SetUserRole updates a user's role
func (c *Client) SetUserRole(ctx context.Context, userID, role string) (*User, error) {
	return c.UpdateUser(ctx, userID, &UpdateUserOptions{
		Role: &role,
	})
}

// BanUser sets a user's banned status
func (c *Client) BanUser(ctx context.Context, userID string) (*User, error) {
	banned := true
	return c.UpdateUser(ctx, userID, &UpdateUserOptions{
		Banned: &banned,
	})
}

// UnbanUser removes a user's banned status
func (c *Client) UnbanUser(ctx context.Context, userID string) (*User, error) {
	banned := false
	return c.UpdateUser(ctx, userID, &UpdateUserOptions{
		Banned: &banned,
	})
}

// CreateManyUsers creates multiple users in a batch operation
func (c *Client) CreateManyUsers(ctx context.Context, users []*CreateUserOptions) ([]interface{}, error) {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/users/batch", c.config.ProjectURL)

	jsonData, err := json.Marshal(map[string]interface{}{
		"users": users,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedEncoding, err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, handleErrorResponse(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedParsing, err.Error())
	}

	var result struct {
		Results []interface{} `json:"results"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		// Try to unmarshal as a direct array
		var directResults []interface{}
		if jsonErr := json.Unmarshal(body, &directResults); jsonErr != nil {
			return nil, fmt.Errorf("%w: %s", ErrFailedParsing, err.Error())
		}
		return directResults, nil
	}

	return result.Results, nil
}

// GenerateUserMigration generates a migration token for a user
func (c *Client) GenerateUserMigration(ctx context.Context, userID string, options map[string]interface{}) (map[string]interface{}, error) {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/users/%s/migrate", c.config.ProjectURL, userID)

	jsonData, err := json.Marshal(options)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedEncoding, err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	c.setAdminHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(resp)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedParsing, err.Error())
	}

	return result, nil
}

// SetSession sets the current session tokens
func (c *Client) SetSession(accessToken, refreshToken string, expiresIn int) {
	c.accessToken = accessToken
	c.refreshToken = refreshToken
	c.tokenExpiry = time.Now().Add(time.Second * time.Duration(expiresIn))
}

// GetSession returns the current session tokens
func (c *Client) GetSession() (accessToken, refreshToken string, expiry time.Time) {
	return c.accessToken, c.refreshToken, c.tokenExpiry
}

// signUpOrIn is an internal method to handle sign up and sign in
func (c *Client) signUpOrIn(ctx context.Context, endpoint string, data map[string]interface{}) (*User, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedEncoding, err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s%s", c.config.ProjectURL, endpoint), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", c.config.APIKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("error code %d: %s", resp.StatusCode, string(bodyBytes))
		}
		return nil, fmt.Errorf("error: %s - %s", errResp.Error, errResp.Message)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedParsing, err.Error())
	}

	c.accessToken = tokenResp.AccessToken
	c.refreshToken = tokenResp.RefreshToken
	c.tokenExpiry = time.Now().Add(time.Second * time.Duration(tokenResp.ExpiresIn))

	if c.config.TokenCallback != nil {
		c.config.TokenCallback(c.accessToken, c.refreshToken)
	}

	return &tokenResp.User, nil
}

// setAdminHeaders sets the headers required for admin API requests
func (c *Client) setAdminHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", c.config.APIKey)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.config.APIKey))
}

// handleErrorResponse handles error responses from the Supabase API
func handleErrorResponse(resp *http.Response) error {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%w: status code %d, failed to read error response: %s",
			ErrAPIError, resp.StatusCode, err.Error())
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
		// If can't parse as JSON, return raw error string
		return fmt.Errorf("%w: status code %d, response: %s",
			ErrAPIError, resp.StatusCode, string(bodyBytes))
	}

	return NewAPIError(resp.StatusCode, errResp.Error, errResp.Message, errResp.Code)
}
