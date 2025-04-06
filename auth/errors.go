package auth

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidArgument is returned when an argument is invalid
	ErrInvalidArgument = errors.New("invalid argument")

	// ErrNotAuthenticated is returned when the client is not authenticated
	ErrNotAuthenticated = errors.New("not authenticated")

	// ErrFailedRequest is returned when a request fails
	ErrFailedRequest = errors.New("failed to make request")

	// ErrFailedParsing is returned when parsing a response fails
	ErrFailedParsing = errors.New("failed to parse response")

	// ErrFailedEncoding is returned when encoding a request fails
	ErrFailedEncoding = errors.New("failed to encode request")

	// ErrAPIError is returned when the Supabase API returns an error
	ErrAPIError = errors.New("supabase API error")

	// ErrInvalidToken is returned when a token is invalid
	ErrInvalidToken = errors.New("invalid token")

	// ErrExpiredToken is returned when a token has expired
	ErrExpiredToken = errors.New("token has expired")

	// ErrUserNotFound is returned when a user is not found
	ErrUserNotFound = errors.New("user not found")

	// ErrEmailTaken is returned when an email is already taken
	ErrEmailTaken = errors.New("email already taken")

	// ErrPhoneTaken is returned when a phone number is already taken
	ErrPhoneTaken = errors.New("phone number already taken")

	// ErrNotImplemented is returned when a feature is not implemented
	ErrNotImplemented = errors.New("not implemented")
)

// APIError represents an error returned by the Supabase API
type APIError struct {
	StatusCode int
	Message    string
	ErrorType  string
	ErrorCode  string
}

// Error implements the error interface for APIError
func (e *APIError) Error() string {
	if e.ErrorCode != "" {
		return fmt.Sprintf("supabase API error: status %d, type: %s, code: %s, message: %s",
			e.StatusCode, e.ErrorType, e.ErrorCode, e.Message)
	}
	return fmt.Sprintf("supabase API error: status %d, type: %s, message: %s",
		e.StatusCode, e.ErrorType, e.Message)
}

// NewAPIError creates a new APIError
func NewAPIError(statusCode int, errorType string, message string, errorCode string) *APIError {
	return &APIError{
		StatusCode: statusCode,
		Message:    message,
		ErrorType:  errorType,
		ErrorCode:  errorCode,
	}
}

// IsNotFoundError checks if an error is a not found error
func IsNotFoundError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == 404
	}
	return errors.Is(err, ErrUserNotFound)
}

// IsAuthenticationError checks if an error is an authentication error
func IsAuthenticationError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == 401
	}
	return errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrNotAuthenticated)
}

// IsAuthorizationError checks if an error is an authorization error
func IsAuthorizationError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == 403
	}
	return false
}

// IsConflictError checks if an error is a conflict error (e.g., email already taken)
func IsConflictError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == 409
	}
	return errors.Is(err, ErrEmailTaken) || errors.Is(err, ErrPhoneTaken)
}

// IsRateLimitError checks if an error is a rate limit error
func IsRateLimitError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == 429
	}
	return false
}

// IsServerError checks if an error is a server error
func IsServerError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode >= 500
	}
	return false
}
