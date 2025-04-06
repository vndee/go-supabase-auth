# Testing Guide for go-supabase-auth

This guide explains how to run tests, analyze coverage, and improve test quality for the go-supabase-auth SDK.

## Running Tests

To run all tests:

```bash
make test
```

To run tests with verbose output:

```bash
go test -v ./...
```

To run tests for a specific package:

```bash
go test -v ./auth/...
```

## Test Coverage

### Generating Coverage Reports

To generate a coverage report for all core code (excluding examples and test utilities):

```bash
make coverage-core
```

This will:
1. Run tests and generate a coverage profile
2. Filter out test files, example code, and test utilities
3. Generate an HTML coverage report (`coverage.html`)
4. Display a function-by-function coverage summary

### Analyzing Coverage

To see a detailed analysis of which functions need more testing:

```bash
./scripts/check_coverage.sh
```

This script will:
1. Run tests with coverage
2. Filter the results to focus on core code
3. Sort functions by coverage percentage
4. Highlight functions with less than 50% coverage
5. Report overall coverage percentage

### Understanding Coverage Output

The coverage output shows three columns:
- Function name (with package)
- Set statements (covered/total)
- Coverage percentage

For example:
```
github.com/vndee/go-supabase-auth/auth/client.go:204:	SignOut			0.0%
github.com/vndee/go-supabase-auth/auth/client.go:318:	InviteUserByEmail	0.0%
github.com/vndee/go-supabase-auth/auth/client.go:375:	ResetPasswordForEmail	0.0%
```

This indicates that these functions have 0% test coverage and should be prioritized for testing.

## Improving Test Coverage

### Adding Tests for Untested Functions

1. Identify functions with low coverage using `./scripts/check_coverage.sh`
2. Add test cases for these functions in the appropriate test file
3. Use the testing utilities in `auth/testing` to mock HTTP responses

Example:

```go
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
```

### Testing Error Handling

Make sure to test both success and error paths:

```go
func TestResetPasswordForEmailError(t *testing.T) {
    // Setup mock HTTP client with error response
    mockResponses := map[string]authtest.MockResponse{
        "/auth/v1/recover": {
            StatusCode: http.StatusBadRequest,
            Body: map[string]interface{}{
                "error":   "invalid_request",
                "message": "Invalid email",
            },
        },
    }
    httpClient := authtest.MockHTTPClient(t, mockResponses)
    
    // Create client with mock HTTP client
    client := NewClient(testProjectURL, testAPIKey).WithHTTPClient(httpClient)
    ctx := context.Background()
    
    // Test with invalid email
    err := client.ResetPasswordForEmail(ctx, "invalid@example.com")
    if err == nil {
        t.Fatal("Expected error, got nil")
    }
    
    // Verify error type
    if !strings.Contains(err.Error(), "Invalid email") {
        t.Errorf("Expected error message to contain 'Invalid email', got %v", err)
    }
}
```

### Testing Edge Cases

Remember to test edge cases, including:

1. Empty/nil inputs
2. Boundary conditions
3. Invalid inputs
4. Rate limit responses
5. Unauthorized responses
6. Server errors

### Using Table-Driven Tests

For functions with many cases, use table-driven tests:

```go
func TestVerifyToken(t *testing.T) {
    testCases := []struct {
        name          string
        token         string
        mockResponse  authtest.MockResponse
        expectedError bool
        expectedUser  *User
    }{
        {
            name:  "valid token",
            token: "valid-token",
            mockResponse: authtest.MockResponse{
                StatusCode: http.StatusOK,
                Body: map[string]interface{}{
                    "id":    "user123",
                    "email": "test@example.com",
                },
            },
            expectedError: false,
            expectedUser: &User{
                ID:    "user123",
                Email: "test@example.com",
            },
        },
        {
            name:  "invalid token",
            token: "invalid-token",
            mockResponse: authtest.MockResponse{
                StatusCode: http.StatusUnauthorized,
                Body: map[string]interface{}{
                    "error":   "invalid_token",
                    "message": "Invalid token",
                },
            },
            expectedError: true,
            expectedUser:  nil,
        },
        // Add more test cases...
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            // Setup mock client...
            
            // Run test and verify results...
        })
    }
}
```

## Continuous Integration

The project is configured to:

1. Run all tests on each pull request and push
2. Generate and upload coverage reports
3. Report on test coverage metrics

## Tips for Effective Testing

1. **Test functionality, not implementation**: Focus on testing the behavior/API
2. **Keep tests isolated**: Each test should be independent
3. **Test both success and failure paths**: Don't just test the happy path
4. **Mock external dependencies**: Use the testing utilities to mock HTTP responses
5. **Aim for high coverage**: Try to achieve at least 80% overall test coverage

## Additional Resources

- [Go Testing Package Documentation](https://golang.org/pkg/testing/)
- [Go Cover Tool Documentation](https://golang.org/cmd/cover/)
- [Table Driven Tests in Go](https://dave.cheney.net/2019/05/07/prefer-table-driven-tests)