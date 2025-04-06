package auth

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAPIError(t *testing.T) {
	err := &APIError{
		StatusCode: 400,
		ErrorType:  "invalid_request",
		Message:    "Invalid request",
		ErrorCode:  "400100",
	}

	expectedMsg := "supabase API error: status 400, type: invalid_request, code: 400100, message: Invalid request"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message to be '%s', got '%s'", expectedMsg, err.Error())
	}

	// Test without error code
	err = &APIError{
		StatusCode: 400,
		ErrorType:  "invalid_request",
		Message:    "Invalid request",
	}

	expectedMsg = "supabase API error: status 400, type: invalid_request, message: Invalid request"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message to be '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestNewAPIError(t *testing.T) {
	err := NewAPIError(400, "invalid_request", "Invalid request", "400100")

	if err.StatusCode != 400 {
		t.Errorf("Expected StatusCode to be 400, got %d", err.StatusCode)
	}

	if err.ErrorType != "invalid_request" {
		t.Errorf("Expected ErrorType to be 'invalid_request', got '%s'", err.ErrorType)
	}

	if err.Message != "Invalid request" {
		t.Errorf("Expected Message to be 'Invalid request', got '%s'", err.Message)
	}

	if err.ErrorCode != "400100" {
		t.Errorf("Expected ErrorCode to be '400100', got '%s'", err.ErrorCode)
	}
}

func TestIsNotFoundError(t *testing.T) {
	// Test with APIError
	err := NewAPIError(404, "not_found", "User not found", "404100")
	if !IsNotFoundError(err) {
		t.Error("Expected IsNotFoundError to return true for 404 error")
	}

	// Test with ErrUserNotFound
	if !IsNotFoundError(ErrUserNotFound) {
		t.Error("Expected IsNotFoundError to return true for ErrUserNotFound")
	}

	// Test with other error
	otherErr := errors.New("some other error")
	if IsNotFoundError(otherErr) {
		t.Error("Expected IsNotFoundError to return false for other error")
	}
}

func TestIsAuthenticationError(t *testing.T) {
	// Test with APIError
	err := NewAPIError(401, "unauthorized", "Unauthorized", "401100")
	if !IsAuthenticationError(err) {
		t.Error("Expected IsAuthenticationError to return true for 401 error")
	}

	// Test with ErrInvalidToken
	if !IsAuthenticationError(ErrInvalidToken) {
		t.Error("Expected IsAuthenticationError to return true for ErrInvalidToken")
	}

	// Test with ErrNotAuthenticated
	if !IsAuthenticationError(ErrNotAuthenticated) {
		t.Error("Expected IsAuthenticationError to return true for ErrNotAuthenticated")
	}

	// Test with other error
	otherErr := errors.New("some other error")
	if IsAuthenticationError(otherErr) {
		t.Error("Expected IsAuthenticationError to return false for other error")
	}
}

func TestIsAuthorizationError(t *testing.T) {
	// Test with APIError
	err := NewAPIError(403, "forbidden", "Forbidden", "403100")
	if !IsAuthorizationError(err) {
		t.Error("Expected IsAuthorizationError to return true for 403 error")
	}

	// Test with other error
	otherErr := errors.New("some other error")
	if IsAuthorizationError(otherErr) {
		t.Error("Expected IsAuthorizationError to return false for other error")
	}
}

func TestIsConflictError(t *testing.T) {
	// Test with APIError
	err := NewAPIError(409, "conflict", "Email already taken", "409100")
	if !IsConflictError(err) {
		t.Error("Expected IsConflictError to return true for 409 error")
	}

	// Test with ErrEmailTaken
	if !IsConflictError(ErrEmailTaken) {
		t.Error("Expected IsConflictError to return true for ErrEmailTaken")
	}

	// Test with ErrPhoneTaken
	if !IsConflictError(ErrPhoneTaken) {
		t.Error("Expected IsConflictError to return true for ErrPhoneTaken")
	}

	// Test with other error
	otherErr := errors.New("some other error")
	if IsConflictError(otherErr) {
		t.Error("Expected IsConflictError to return false for other error")
	}
}

func TestIsRateLimitError(t *testing.T) {
	// Test with APIError
	err := NewAPIError(429, "too_many_requests", "Too many requests", "429100")
	if !IsRateLimitError(err) {
		t.Error("Expected IsRateLimitError to return true for 429 error")
	}

	// Test with other error
	otherErr := errors.New("some other error")
	if IsRateLimitError(otherErr) {
		t.Error("Expected IsRateLimitError to return false for other error")
	}
}

func TestIsServerError(t *testing.T) {
	// Test with APIError (500)
	err := NewAPIError(500, "internal_server_error", "Internal server error", "500100")
	if !IsServerError(err) {
		t.Error("Expected IsServerError to return true for 500 error")
	}

	// Test with APIError (503)
	err = NewAPIError(503, "service_unavailable", "Service unavailable", "503100")
	if !IsServerError(err) {
		t.Error("Expected IsServerError to return true for 503 error")
	}

	// Test with other error
	otherErr := errors.New("some other error")
	if IsServerError(otherErr) {
		t.Error("Expected IsServerError to return false for other error")
	}
}

func TestErrorWrapping(t *testing.T) {
	// Test wrapping and unwrapping errors
	baseErr := ErrInvalidToken
	wrappedErr := fmt.Errorf("%w: token has expired", baseErr)

	if !errors.Is(wrappedErr, ErrInvalidToken) {
		t.Error("Expected errors.Is to return true for wrapped error")
	}

	var apiErr *APIError
	if errors.As(wrappedErr, &apiErr) {
		t.Error("Expected errors.As to return false for non-APIError")
	}

	// Test with APIError
	apiBaseErr := NewAPIError(401, "invalid_token", "Invalid token", "401100")
	apiWrappedErr := fmt.Errorf("custom wrapper: %w", apiBaseErr)

	var extractedAPIErr *APIError
	if !errors.As(apiWrappedErr, &extractedAPIErr) {
		t.Error("Expected errors.As to return true for wrapped APIError")
	}

	if extractedAPIErr.StatusCode != 401 {
		t.Errorf("Expected extracted APIError StatusCode to be 401, got %d", extractedAPIErr.StatusCode)
	}
}

// TestHandleErrorResponse tests the error response handling
func TestHandleErrorResponse(t *testing.T) {
	// Test cases
	testCases := []struct {
		name           string
		statusCode     int
		responseBody   string
		contentType    string
		expectedError  bool
		expectedErrMsg string
	}{
		{
			name:           "valid error response",
			statusCode:     400,
			responseBody:   `{"error":"invalid_request","message":"Invalid request","code":"400.100"}`,
			contentType:    "application/json",
			expectedError:  true,
			expectedErrMsg: "invalid_request",
		},
		{
			name:           "error response without code",
			statusCode:     401,
			responseBody:   `{"error":"unauthorized","message":"Unauthorized"}`,
			contentType:    "application/json",
			expectedError:  true,
			expectedErrMsg: "unauthorized",
		},
		{
			name:           "non-JSON error response",
			statusCode:     500,
			responseBody:   "Internal Server Error",
			contentType:    "text/plain",
			expectedError:  true,
			expectedErrMsg: "Internal Server Error",
		},
		{
			name:           "empty error response",
			statusCode:     503,
			responseBody:   "",
			contentType:    "application/json",
			expectedError:  true,
			expectedErrMsg: "503",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock response
			resp := &http.Response{
				StatusCode: tc.statusCode,
				Body:       io.NopCloser(strings.NewReader(tc.responseBody)),
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", tc.contentType)

			// Handle the error response
			err := handleErrorResponse(resp)

			// Check if we expected an error
			if tc.expectedError && err == nil {
				t.Fatalf("Expected an error, got nil")
			}

			if !tc.expectedError && err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			// Check the error message
			if tc.expectedError {
				if !strings.Contains(err.Error(), tc.expectedErrMsg) {
					t.Errorf("Expected error message to contain '%s', got '%s'", tc.expectedErrMsg, err.Error())
				}

				// Check if it's an APIError
				var apiErr *APIError
				if ok := IsAPIError(err, &apiErr); ok {
					if apiErr.StatusCode != tc.statusCode {
						t.Errorf("Expected status code %d, got %d", tc.statusCode, apiErr.StatusCode)
					}
				} else if !strings.Contains(tc.name, "non-JSON") && !strings.Contains(tc.name, "empty") {
					t.Errorf("Expected APIError, got different error type: %T", err)
				}
			}
		})
	}
}

// IsAPIError is a helper function to check if an error is an APIError
func IsAPIError(err error, apiErr **APIError) bool {
	return errors.As(err, apiErr)
}

// TestDefaultConfig tests the DefaultConfig function
func TestDefaultConfig(t *testing.T) {
	projectURL := "https://test.supabase.co"
	apiKey := "test-api-key"

	config := DefaultConfig(projectURL, apiKey)

	if config.ProjectURL != projectURL {
		t.Errorf("Expected ProjectURL to be %s, got %s", projectURL, config.ProjectURL)
	}

	if config.APIKey != apiKey {
		t.Errorf("Expected APIKey to be %s, got %s", apiKey, config.APIKey)
	}

	if !config.AutoRefreshTokens {
		t.Error("Expected AutoRefreshTokens to be true")
	}

	if !config.PersistSession {
		t.Error("Expected PersistSession to be true")
	}

	if config.Debug {
		t.Error("Expected Debug to be false")
	}
}
