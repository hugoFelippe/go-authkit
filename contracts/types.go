package contracts

import (
	"time"
)

// Claims representa as informações contidas em um token de autenticação.
// É usado tanto para JWT quanto para outros tipos de tokens.
type Claims struct {
	// Standard JWT claims
	Subject   string    `json:"sub,omitempty"` // Subject (user ID)
	Issuer    string    `json:"iss,omitempty"` // Issuer
	Audience  []string  `json:"aud,omitempty"` // Audience
	ExpiresAt time.Time `json:"exp,omitempty"` // Expiration time
	NotBefore time.Time `json:"nbf,omitempty"` // Not before
	IssuedAt  time.Time `json:"iat,omitempty"` // Issued at
	ID        string    `json:"jti,omitempty"` // JWT ID

	// Custom claims
	Email       string                 `json:"email,omitempty"`
	Username    string                 `json:"username,omitempty"`
	Name        string                 `json:"name,omitempty"`
	Roles       []string               `json:"roles,omitempty"`
	Permissions []string               `json:"permissions,omitempty"`
	Scopes      []string               `json:"scopes,omitempty"`
	Groups      []string               `json:"groups,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`

	// ABAC attributes
	Department string `json:"department,omitempty"`
	Level      int    `json:"level,omitempty"`
	Region     string `json:"region,omitempty"`
}

// User representa um usuário no sistema.
type User struct {
	ID          string                 `json:"id"`
	Username    string                 `json:"username"`
	Email       string                 `json:"email"`
	Name        string                 `json:"name"`
	Roles       []string               `json:"roles,omitempty"`
	Permissions []string               `json:"permissions,omitempty"`
	Groups      []string               `json:"groups,omitempty"`
	Attributes  map[string]interface{} `json:"attributes,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Active      bool                   `json:"active"`
}

// TokenType define os tipos de token suportados.
type TokenType string

const (
	TokenTypeJWT     TokenType = "jwt"
	TokenTypeOpaque  TokenType = "opaque"
	TokenTypeAPIKey  TokenType = "apikey"
	TokenTypeBearer  TokenType = "bearer"
	TokenTypeRefresh TokenType = "refresh"
)

// TokenInfo contém informações sobre um token.
type TokenInfo struct {
	Type      TokenType              `json:"type"`
	Active    bool                   `json:"active"`
	ExpiresAt *time.Time             `json:"expires_at,omitempty"`
	IssuedAt  *time.Time             `json:"issued_at,omitempty"`
	Subject   string                 `json:"subject,omitempty"`
	Issuer    string                 `json:"issuer,omitempty"`
	Audience  []string               `json:"audience,omitempty"`
	Scopes    []string               `json:"scopes,omitempty"`
	Extra     map[string]interface{} `json:"extra,omitempty"`
}

// APIKey representa uma chave de API.
type APIKey struct {
	ID          string                 `json:"id"`
	Key         string                 `json:"key"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	UserID      string                 `json:"user_id"`
	Scopes      []string               `json:"scopes,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Active      bool                   `json:"active"`
	LastUsedAt  *time.Time             `json:"last_used_at,omitempty"`
}

// OAuth2Token representa um token OAuth2.
type OAuth2Token struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scopes       []string  `json:"scopes,omitempty"`
}

// Session representa uma sessão de usuário.
type Session struct {
	ID        string                 `json:"id"`
	UserID    string                 `json:"user_id"`
	Token     string                 `json:"token"`
	ExpiresAt time.Time              `json:"expires_at"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
	Active    bool                   `json:"active"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Permission representa uma permissão no sistema.
type Permission struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

// Role representa um papel/função no sistema.
type Role struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Permissions []Permission `json:"permissions,omitempty"`
}

// AuthContext contém informações de contexto para autenticação.
type AuthContext struct {
	User        *User                  `json:"user,omitempty"`
	Claims      *Claims                `json:"claims,omitempty"`
	Token       string                 `json:"token,omitempty"`
	TokenType   TokenType              `json:"token_type,omitempty"`
	Scopes      []string               `json:"scopes,omitempty"`
	Permissions []string               `json:"permissions,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// APIKeyData representa dados de uma API Key (movida de token/apikey.go)
type APIKeyData struct {
	ID         string                 `json:"id"`
	UserID     string                 `json:"user_id"`
	Name       string                 `json:"name"`
	HashedKey  string                 `json:"hashed_key"`
	Prefix     string                 `json:"prefix"`
	Scopes     []string               `json:"scopes"`
	ExpiresAt  *time.Time             `json:"expires_at"`
	CreatedAt  time.Time              `json:"created_at"`
	LastUsedAt *time.Time             `json:"last_used_at"`
	Active     bool                   `json:"active"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// APIKeyConfig configuração para API Keys (movida de token/apikey.go)
type APIKeyConfig struct {
	Prefix        string
	Length        int
	ExpiryDefault time.Duration
	HashKeys      bool
}

// GenerateOptions contém opções para geração de tokens (movida de token/manager.go)
type GenerateOptions struct {
	ExpiresAt    *time.Time
	Audience     []string
	Scopes       []string
	CustomClaims map[string]interface{}
	TokenType    string
}

// GenerateOption configura opções para geração de tokens (movida de token/manager.go)
type GenerateOption func(*GenerateOptions)
