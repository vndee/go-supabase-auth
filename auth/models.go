package auth

import "time"

// User represents a Supabase user
type User struct {
	ID                 string                 `json:"id"`
	Aud                string                 `json:"aud"`
	Role               string                 `json:"role"`
	Email              string                 `json:"email"`
	Phone              string                 `json:"phone"`
	EmailConfirmed     *time.Time             `json:"email_confirmed_at,omitempty"`
	PhoneConfirmed     *time.Time             `json:"phone_confirmed_at,omitempty"`
	LastSignInAt       time.Time              `json:"last_sign_in_at,omitempty"`
	AppMetadata        map[string]interface{} `json:"app_metadata"`
	UserMetadata       map[string]interface{} `json:"user_metadata"`
	Identities         []Identity             `json:"identities"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
	IsAnonymous        bool                   `json:"is_anonymous,omitempty"`
	BannedUntil        *time.Time             `json:"banned_until,omitempty"`
	ConfirmedAt        *time.Time             `json:"confirmed_at,omitempty"`
	ConfirmationSentAt *time.Time             `json:"confirmation_sent_at,omitempty"`
	RecoverySentAt     *time.Time             `json:"recovery_sent_at,omitempty"`
	EmailChange        string                 `json:"email_change,omitempty"`
	EmailChangeSentAt  *time.Time             `json:"email_change_sent_at,omitempty"`
	PhoneChange        string                 `json:"phone_change,omitempty"`
	PhoneChangeSentAt  *time.Time             `json:"phone_change_sent_at,omitempty"`
	FactorsVerified    bool                   `json:"factors_confirmed,omitempty"`
}

// Identity represents a user's identity from an OAuth provider
type Identity struct {
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	IdentityData map[string]interface{} `json:"identity_data"`
	Provider     string                 `json:"provider"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	LastSignInAt time.Time              `json:"last_sign_in_at"`
}

// UserList represents a paginated list of users
type UserList struct {
	Users      []User `json:"users"`
	TotalCount int    `json:"total_count"`
	NextPage   int    `json:"next_page,omitempty"`
	PrevPage   int    `json:"prev_page,omitempty"`
}

// Session represents a user's active session
type Session struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Factor       string    `json:"factor"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	LastUsedAt   time.Time `json:"last_used_at"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Factor represents a multi-factor authentication factor
type Factor struct {
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	Type         string                 `json:"type"`
	Status       string                 `json:"status"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	FriendlyName string                 `json:"friendly_name"`
	FactorData   map[string]interface{} `json:"factor_data"`
}

// LinkAction represents the type of action for which to generate a link
type LinkAction string

const (
	// LinkActionSignUp generates a signup link
	LinkActionSignUp LinkAction = "signup"
	// LinkActionInvite generates an invite link
	LinkActionInvite LinkAction = "invite"
	// LinkActionMagicLink generates a magic link
	LinkActionMagicLink LinkAction = "magiclink"
	// LinkActionRecovery generates a password recovery link
	LinkActionRecovery LinkAction = "recovery"
	// LinkActionEmailChange generates an email change confirmation link
	LinkActionEmailChange LinkAction = "email_change"
)

// LinkResponse represents a response for a generated link
type LinkResponse struct {
	Link         string    `json:"link"`
	PKCE         bool      `json:"pkce"`
	UserID       string    `json:"user_id,omitempty"`
	Email        string    `json:"email"`
	GeneratedAt  time.Time `json:"generated_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	RedirectedTo string    `json:"redirected_to,omitempty"`
}

// ErrorResponse represents an error response from the Supabase API
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// ListUsersOptions contains options for listing users
type ListUsersOptions struct {
	Page      int    `json:"page,omitempty"`
	PerPage   int    `json:"per_page,omitempty"`
	Filter    string `json:"filter,omitempty"`
	SortBy    string `json:"sort_by,omitempty"`
	SortOrder string `json:"sort_order,omitempty"`
}

// CreateUserOptions contains options for creating a user
type CreateUserOptions struct {
	Email        string                 `json:"email,omitempty"`
	Phone        string                 `json:"phone,omitempty"`
	Password     string                 `json:"password,omitempty"`
	EmailConfirm bool                   `json:"email_confirm,omitempty"`
	PhoneConfirm bool                   `json:"phone_confirm,omitempty"`
	UserMetadata map[string]interface{} `json:"user_metadata,omitempty"`
	AppMetadata  map[string]interface{} `json:"app_metadata,omitempty"`
	BanDuration  string                 `json:"ban_duration,omitempty"`
	Data         map[string]interface{} `json:"data,omitempty"` // For custom claims
	Role         string                 `json:"role,omitempty"`
}

// UpdateUserOptions contains options for updating a user
type UpdateUserOptions struct {
	Email        *string                 `json:"email,omitempty"`
	Phone        *string                 `json:"phone,omitempty"`
	Password     *string                 `json:"password,omitempty"`
	UserMetadata map[string]interface{}  `json:"user_metadata,omitempty"`
	AppMetadata  map[string]interface{}  `json:"app_metadata,omitempty"`
	Banned       *bool                   `json:"banned,omitempty"`
	BanDuration  *string                 `json:"ban_duration,omitempty"`
	Role         *string                 `json:"role,omitempty"`
	Data         *map[string]interface{} `json:"data,omitempty"` // For custom claims
}

// GenerateLinkOptions contains options for generating authentication links
type GenerateLinkOptions struct {
	Email      string                 `json:"email"`
	RedirectTo string                 `json:"redirect_to,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`
}

// InviteOptions contains options for inviting users
type InviteOptions struct {
	RedirectTo   string                 `json:"redirect_to,omitempty"`
	Data         map[string]interface{} `json:"data,omitempty"`
	UserMetadata map[string]interface{} `json:"user_metadata,omitempty"`
}

// TokenResponse represents the response from authentication endpoints
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	User         User   `json:"user"`
}
