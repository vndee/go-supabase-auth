package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

// VerifyJWTWithSecret verifies a JWT token locally without making an API call to Supabase
// It checks the token signature, issuer (if provided), and expiration
// Returns the decoded claims and an error if verification fails
func VerifyJWTWithSecret(token string, jwtSecret string, issuer string) (*JWTPayload, error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Validate the alg is what we expect
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%w: unexpected signing method: %v", ErrInvalidToken, token.Header["alg"])
		}
		// Return the key for verification
		return []byte(jwtSecret), nil
	}, jwt.WithLeeway(5*time.Second)) // Allow 5 seconds leeway for clock skew

	if err != nil {
		if strings.Contains(err.Error(), "token is expired") {
			return nil, ErrExpiredToken
		}
		return nil, fmt.Errorf("%w: %s", ErrInvalidToken, err.Error())
	}

	if !parsedToken.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: failed to parse token claims", ErrInvalidToken)
	}

	// Check issuer if provided
	if issuer != "" {
		tokenIssuer, ok := claims["iss"].(string)
		if !ok || tokenIssuer != issuer {
			return nil, fmt.Errorf("%w: invalid issuer", ErrInvalidToken)
		}
	}

	// Map to our JWTPayload struct
	var jwtPayload JWTPayload
	jwtPayload.Sub, _ = claims["sub"].(string)
	jwtPayload.Role, _ = claims["role"].(string)
	jwtPayload.Email, _ = claims["email"].(string)
	jwtPayload.Aud, _ = claims["aud"].(string)
	jwtPayload.Iss, _ = claims["iss"].(string)

	// Handle exp and iat as float64 coming from JSON
	if exp, ok := claims["exp"].(float64); ok {
		jwtPayload.Exp = int64(exp)
	}
	if iat, ok := claims["iat"].(float64); ok {
		jwtPayload.Iat = int64(iat)
	}

	// Handle nested maps for metadata
	if appMetadata, ok := claims["app_metadata"].(map[string]interface{}); ok {
		jwtPayload.AppMetadata = appMetadata
	}
	if userMetadata, ok := claims["user_metadata"].(map[string]interface{}); ok {
		jwtPayload.UserMetadata = userMetadata
	}

	return &jwtPayload, nil
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
