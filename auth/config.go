package auth

// Config represents the configuration for the Supabase Auth client
type Config struct {
	// ProjectURL is the URL of your Supabase project (required)
	ProjectURL string

	// APIKey is your Supabase project API key (service_role key for admin functions)
	APIKey string

	// AutoRefreshTokens determines whether to automatically refresh expired tokens
	AutoRefreshTokens bool

	// PersistSession determines whether to persist session information
	PersistSession bool

	// TokenCallback is called when tokens are refreshed
	TokenCallback func(accessToken, refreshToken string)

	// Debug enables debug logging
	Debug bool
}

// DefaultConfig returns a default configuration
func DefaultConfig(projectURL, apiKey string) *Config {
	return &Config{
		ProjectURL:        projectURL,
		APIKey:            apiKey,
		AutoRefreshTokens: true,
		PersistSession:    true,
		Debug:             false,
	}
}
