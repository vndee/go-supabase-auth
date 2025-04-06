package auth

import (
	"testing"

	authtest "github.com/vndee/go-supabase-auth/auth/mock"
)

func TestDecodeJWT(t *testing.T) {
	// Test with valid token
	token := authtest.GenerateFakeJWT()
	payload, err := DecodeJWT(token)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if payload.Sub != "user123" {
		t.Errorf("Expected user ID to be 'user123', got %s", payload.Sub)
	}

	if payload.Role != "user" {
		t.Errorf("Expected role to be 'user', got %s", payload.Role)
	}

	if payload.Email != "test@example.com" {
		t.Errorf("Expected email to be 'test@example.com', got %s", payload.Email)
	}

	// Test with invalid token format
	_, err = DecodeJWT("invalid-token")
	if err == nil {
		t.Error("Expected error for invalid token, got nil")
	}

	// Test with invalid token parts
	_, err = DecodeJWT("part1.part2")
	if err == nil {
		t.Error("Expected error for token with wrong number of parts, got nil")
	}
}

func TestIsTokenExpired(t *testing.T) {
	// Test with valid non-expired token
	validToken := authtest.GenerateFakeJWT()
	expired, err := IsTokenExpired(validToken)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if expired {
		t.Error("Expected token to not be expired")
	}

	// Test with expired token
	expiredToken := authtest.GenerateExpiredJWT()
	expired, err = IsTokenExpired(expiredToken)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !expired {
		t.Error("Expected token to be expired")
	}

	// Test with invalid token
	_, err = IsTokenExpired("invalid-token")
	if err == nil {
		t.Error("Expected error for invalid token, got nil")
	}
}

func TestGetUserIDFromToken(t *testing.T) {
	// Test with valid token
	token := authtest.GenerateFakeJWT()
	userID, err := GetUserIDFromToken(token)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if userID != "user123" {
		t.Errorf("Expected user ID to be 'user123', got %s", userID)
	}

	// Test with invalid token
	_, err = GetUserIDFromToken("invalid-token")
	if err == nil {
		t.Error("Expected error for invalid token, got nil")
	}
}

func TestGetRoleFromToken(t *testing.T) {
	// Test with valid token
	token := authtest.GenerateFakeJWT()
	role, err := GetRoleFromToken(token)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if role != "user" {
		t.Errorf("Expected role to be 'user', got %s", role)
	}

	// Test with invalid token
	_, err = GetRoleFromToken("invalid-token")
	if err == nil {
		t.Error("Expected error for invalid token, got nil")
	}
}

func TestBuildFilter(t *testing.T) {
	filter := BuildFilter("email", "eq", "test@example.com")
	expected := "email.eq.test@example.com"

	if filter != expected {
		t.Errorf("Expected filter to be '%s', got '%s'", expected, filter)
	}
}
