package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Admin provides administrative functions for Supabase Auth
type Admin struct {
	client *Client
}

// NewAdmin creates a new Admin instance
func NewAdmin(projectURL, apiKey string) *Admin {
	return &Admin{
		client: NewClient(projectURL, apiKey),
	}
}

// WithClient sets a custom client for the Admin
func (a *Admin) WithClient(client *Client) *Admin {
	a.client = client
	return a
}

// Client returns the underlying client
func (a *Admin) Client() *Client {
	return a.client
}

// CreateAuthProvider enables a new auth provider
func (a *Admin) CreateAuthProvider(ctx context.Context, provider string, options map[string]interface{}) error {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/providers", a.client.config.ProjectURL)

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

	a.client.setAdminHeaders(req)

	resp, err := a.client.httpClient.Do(req)
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
func (a *Admin) UpdateAuthProvider(ctx context.Context, provider string, options map[string]interface{}) error {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/providers/%s", a.client.config.ProjectURL, provider)

	jsonData, err := json.Marshal(options)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedEncoding, err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	a.client.setAdminHeaders(req)

	resp, err := a.client.httpClient.Do(req)
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
func (a *Admin) DeleteAuthProvider(ctx context.Context, provider string) error {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/providers/%s", a.client.config.ProjectURL, provider)

	req, err := http.NewRequestWithContext(ctx, "DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	a.client.setAdminHeaders(req)

	resp, err := a.client.httpClient.Do(req)
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
func (a *Admin) GetAuthSettings(ctx context.Context) (map[string]interface{}, error) {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/config", a.client.config.ProjectURL)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	a.client.setAdminHeaders(req)

	resp, err := a.client.httpClient.Do(req)
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
func (a *Admin) UpdateAuthSettings(ctx context.Context, settings map[string]interface{}) error {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/config", a.client.config.ProjectURL)

	jsonData, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedEncoding, err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	a.client.setAdminHeaders(req)

	resp, err := a.client.httpClient.Do(req)
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
func (a *Admin) ListAuditLogs(ctx context.Context, options map[string]string) ([]map[string]interface{}, error) {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/audit", a.client.config.ProjectURL)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	q := req.URL.Query()
	for k, v := range options {
		q.Add(k, v)
	}
	req.URL.RawQuery = q.Encode()

	a.client.setAdminHeaders(req)

	resp, err := a.client.httpClient.Do(req)
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

// GetUser is a convenience method for client.GetUser
func (a *Admin) GetUser(ctx context.Context, userID string) (*User, error) {
	return a.client.GetUser(ctx, userID)
}

// ListUsers is a convenience method for client.ListUsers
func (a *Admin) ListUsers(ctx context.Context, options *ListUsersOptions) (*UserList, error) {
	return a.client.ListUsers(ctx, options)
}

// CreateUser is a convenience method for client.CreateUser
func (a *Admin) CreateUser(ctx context.Context, options *CreateUserOptions) (*User, error) {
	return a.client.CreateUser(ctx, options)
}

// UpdateUser is a convenience method for client.UpdateUser
func (a *Admin) UpdateUser(ctx context.Context, userID string, options *UpdateUserOptions) (*User, error) {
	return a.client.UpdateUser(ctx, userID, options)
}

// DeleteUser is a convenience method for client.DeleteUser
func (a *Admin) DeleteUser(ctx context.Context, userID string) error {
	return a.client.DeleteUser(ctx, userID)
}

// GenerateUserMigration generates a migration token for a user
func (a *Admin) GenerateUserMigration(ctx context.Context, userID string, options map[string]interface{}) (map[string]interface{}, error) {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/users/%s/migrate", a.client.config.ProjectURL, userID)

	jsonData, err := json.Marshal(options)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedEncoding, err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFailedRequest, err.Error())
	}

	a.client.setAdminHeaders(req)

	resp, err := a.client.httpClient.Do(req)
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

// CreateManyUsers creates multiple users in a batch operation
func (a *Admin) CreateManyUsers(ctx context.Context, users []*CreateUserOptions) ([]interface{}, error) {
	endpoint := fmt.Sprintf("%s/auth/v1/admin/users/batch", a.client.config.ProjectURL)

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

	a.client.setAdminHeaders(req)

	resp, err := a.client.httpClient.Do(req)
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
