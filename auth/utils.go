package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JWTPayload represents the decoded JWT payload
type JWTPayload struct {
	Sub          string                 `json:"sub"`
	Role         string                 `json:"role"`
	Email        string                 `json:"email"`
	Exp          int64                  `json:"exp"`
	Iat          int64                  `json:"iat"`
	Aud          string                 `json:"aud"`
	Iss          string                 `json:"iss"`
	AppMetadata  map[string]interface{} `json:"app_metadata"`
	UserMetadata map[string]interface{} `json:"user_metadata"`
}

// DecodeJWT decodes a JWT token without verification
func DecodeJWT(token string) (*JWTPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: token must have 3 parts", ErrInvalidToken)
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode token payload", ErrInvalidToken)
	}

	var jwtPayload JWTPayload
	if err := json.Unmarshal(payload, &jwtPayload); err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal token payload", ErrInvalidToken)
	}

	return &jwtPayload, nil
}

// IsTokenExpired checks if a JWT token has expired
func IsTokenExpired(token string) (bool, error) {
	payload, err := DecodeJWT(token)
	if err != nil {
		return true, err
	}

	// Check if token has expired
	now := time.Now().Unix()
	return payload.Exp < now, nil
}

// GetUserIDFromToken extracts the user ID from a JWT token
func GetUserIDFromToken(token string) (string, error) {
	payload, err := DecodeJWT(token)
	if err != nil {
		return "", err
	}

	return payload.Sub, nil
}

// GetRoleFromToken extracts the role from a JWT token
func GetRoleFromToken(token string) (string, error) {
	payload, err := DecodeJWT(token)
	if err != nil {
		return "", err
	}

	return payload.Role, nil
}

// BuildFilter creates a filter string for user queries
func BuildFilter(field, operator, value string) string {
	return fmt.Sprintf("%s.%s.%s", field, operator, value)
}
