package mock

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// MockResponse represents a predefined response for testing
type MockResponse struct {
	StatusCode int
	Body       interface{}
	Headers    map[string]string
}

// MockHTTPClient creates a mock HTTP client that returns predefined responses
func MockHTTPClient(t *testing.T, responses map[string]MockResponse) *http.Client {
	return &http.Client{
		Transport: &mockTransport{
			t:         t,
			responses: responses,
		},
	}
}

type mockTransport struct {
	t         *testing.T
	responses map[string]MockResponse
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Extract the path and method to find the corresponding mock response
	url := req.URL.String()
	mockResp, ok := m.responses[url]
	if !ok {
		// Try with just the path in case the full URL wasn't matched
		mockResp, ok = m.responses[req.URL.Path]
		if !ok {
			// If still not found, look for matches in partial paths
			for path, resp := range m.responses {
				if bytes.Contains([]byte(url), []byte(path)) {
					mockResp = resp
					ok = true
					break
				}
			}
		}
	}

	if !ok {
		m.t.Fatalf("No mock response for %s", url)
		return nil, nil
	}

	// Prepare the response
	responseBody, err := json.Marshal(mockResp.Body)
	if err != nil {
		m.t.Fatalf("Failed to marshal mock response: %v", err)
		return nil, err
	}

	// Create a mock response
	response := &http.Response{
		StatusCode: mockResp.StatusCode,
		Body:       io.NopCloser(bytes.NewBuffer(responseBody)),
		Header:     make(http.Header),
	}

	// Add headers
	for key, value := range mockResp.Headers {
		response.Header.Set(key, value)
	}

	return response, nil
}

// SetupTestServer creates a test HTTP server for more complex test scenarios
func SetupTestServer() (*httptest.Server, *[]http.Request) {
	var requests []http.Request

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Store received request for later inspection
		reqCopy := *r
		body, _ := io.ReadAll(r.Body)
		reqCopy.Body = io.NopCloser(bytes.NewBuffer(body))
		requests = append(requests, reqCopy)

		// Set default content type
		w.Header().Set("Content-Type", "application/json")

		// Handle different endpoints
		switch r.URL.Path {
		case "/auth/v1/admin/users":
			// Handle user listing or creation
			switch r.Method {
			case "GET":
				json.NewEncoder(w).Encode(map[string]interface{}{
					"users": []map[string]interface{}{
						{
							"id":    "user123",
							"email": "test@example.com",
							"role":  "user",
						},
					},
					"total_count": 1,
				})
			case "POST":
				// Parse request body to extract user data
				var userData map[string]interface{}
				if err := json.NewDecoder(io.NopCloser(bytes.NewBuffer(body))).Decode(&userData); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]string{
						"error":   "invalid_request",
						"message": "Invalid request body",
					})
					return
				}

				// Return mocked user creation response
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"id":    "new-user-id",
					"email": userData["email"],
					"role":  userData["role"],
				})
			}
		case "/auth/v1/admin/users/user123":
			// Handle specific user operations
			switch r.Method {
			case "GET":
				json.NewEncoder(w).Encode(map[string]interface{}{
					"id":    "user123",
					"email": "test@example.com",
					"role":  "user",
				})
			case "PUT":
				// Parse request body to extract update data
				var updateData map[string]interface{}
				if err := json.NewDecoder(io.NopCloser(bytes.NewBuffer(body))).Decode(&updateData); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]string{
						"error":   "invalid_request",
						"message": "Invalid request body",
					})
					return
				}

				// Return mocked user update response
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"id":    "user123",
					"email": "test@example.com",
					"role":  updateData["role"],
				})
			case "DELETE":
				w.WriteHeader(http.StatusNoContent)
			}
		case "/auth/v1/admin/verify-token":
			// Handle token verification
			var tokenData map[string]string
			if err := json.NewDecoder(io.NopCloser(bytes.NewBuffer(body))).Decode(&tokenData); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Simulate token verification
			if tokenData["token"] == "valid-token" {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"id":    "user123",
					"email": "test@example.com",
					"role":  "user",
				})
			} else {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "invalid_token",
					"message": "Invalid token",
				})
			}
		default:
			// Default handler for unimplemented paths
			w.WriteHeader(http.StatusNotImplemented)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "not_implemented",
				"message": "Endpoint not implemented in test server",
			})
		}
	}))

	return server, &requests
}

// GenerateFakeJWT generates a fake JWT token for testing
func GenerateFakeJWT() string {
	// This is a valid format JWT but with fake signature
	header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

	// Create payload with some test data including expiry
	payloadMap := map[string]interface{}{
		"sub":   "user123",
		"role":  "user",
		"email": "test@example.com",
		"exp":   4102444800, // 2100-01-01, far in the future
		"iat":   1609459200, // 2021-01-01
		"aud":   "test",
		"iss":   "supabase",
		"app_metadata": map[string]interface{}{
			"provider": "email",
		},
		"user_metadata": map[string]interface{}{
			"name": "Test User",
		},
	}

	payloadJSON, _ := json.Marshal(payloadMap)

	// Properly base64url encode the payload
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Add a fake signature (properly base64url encoded)
	signature := "fakesignaturefakesignaturefakesignaturefakesignature"
	signatureBase64 := base64.RawURLEncoding.EncodeToString([]byte(signature))

	return header + "." + payloadBase64 + "." + signatureBase64
}

// GenerateExpiredJWT generates a fake JWT token that is already expired
func GenerateExpiredJWT() string {
	// This is a valid format JWT but with fake signature
	header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

	// Create payload with expired timestamp
	payloadMap := map[string]interface{}{
		"sub":   "user123",
		"role":  "user",
		"email": "test@example.com",
		"exp":   1609459200, // 2021-01-01, already expired
		"iat":   1577836800, // 2020-01-01
		"aud":   "test",
		"iss":   "supabase",
	}

	payloadJSON, _ := json.Marshal(payloadMap)

	// Properly base64url encode the payload
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Add a fake signature (properly base64url encoded)
	signature := "fakesignaturefakesignaturefakesignaturefakesignature"
	signatureBase64 := base64.RawURLEncoding.EncodeToString([]byte(signature))

	return header + "." + payloadBase64 + "." + signatureBase64
}
