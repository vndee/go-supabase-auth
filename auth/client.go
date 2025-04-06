// Package auth provides a comprehensive admin SDK for Supabase Authentication.
package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client represents a Supabase authentication client
type Client struct {
	config     *Config
	httpClient *http.Client
}

// NewClient creates a new Supabase authentication client with default configuration
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
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(resp)
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedParsing, err.Error())
	}

	return &user, nil
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
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return handleErrorResponse(resp)
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

func (c *Client) setAdminHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", c.config.APIKey)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.config.APIKey))
}

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
