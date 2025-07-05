package authkit

import (
	"context"
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

// TokenInfo contém informações sobre um token.
type TokenInfo struct {
	Token     string            `json:"token"`
	Type      TokenType         `json:"type"`
	ExpiresAt time.Time         `json:"expires_at"`
	IssuedAt  time.Time         `json:"issued_at"`
	Scopes    []string          `json:"scopes,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// TokenType define o tipo de token.
type TokenType string

const (
	TokenTypeJWT    TokenType = "jwt"
	TokenTypeAPIKey TokenType = "api_key"
	TokenTypeOpaque TokenType = "opaque"
	TokenTypeBearer TokenType = "bearer"
)

// AuthContext contém informações de contexto de autenticação.
type AuthContext struct {
	User        *User                  `json:"user,omitempty"`
	Claims      *Claims                `json:"claims,omitempty"`
	Token       *TokenInfo             `json:"token,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	ClientID    string                 `json:"client_id,omitempty"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	Scopes      []string               `json:"scopes,omitempty"`
	Permissions []string               `json:"permissions,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Scope representa um escopo de acesso.
type Scope struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Resource    string `json:"resource,omitempty"`
	Action      string `json:"action,omitempty"`
}

// Permission representa uma permissão específica.
type Permission struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

// Role representa um papel/função no sistema.
type Role struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
	Scopes      []string     `json:"scopes,omitempty"`
}

// APIKey representa uma chave de API.
type APIKey struct {
	ID          string            `json:"id"`
	Key         string            `json:"key"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	UserID      string            `json:"user_id"`
	Scopes      []string          `json:"scopes,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time        `json:"last_used_at,omitempty"`
	Active      bool              `json:"active"`
}

// SessionInfo contém informações sobre uma sessão de usuário.
type SessionInfo struct {
	ID         string            `json:"id"`
	UserID     string            `json:"user_id"`
	Token      string            `json:"token"`
	CreatedAt  time.Time         `json:"created_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	LastAccess time.Time         `json:"last_access"`
	IPAddress  string            `json:"ip_address,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Active     bool              `json:"active"`
}

// OAuth2Token representa um token OAuth2.
type OAuth2Token struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scopes       []string  `json:"scopes,omitempty"`
}

// OIDCToken representa um token OpenID Connect.
type OIDCToken struct {
	OAuth2Token
	IDToken   string                 `json:"id_token"`
	UserInfo  map[string]interface{} `json:"user_info,omitempty"`
	Subject   string                 `json:"subject"`
	Issuer    string                 `json:"issuer"`
	Audience  []string               `json:"audience"`
	ExpiresAt time.Time              `json:"expires_at"`
	IssuedAt  time.Time              `json:"issued_at"`
}

// ContextKey é usado para armazenar valores no context.Context.
type ContextKey string

const (
	// ContextKeyUser chave para armazenar o usuário no contexto
	ContextKeyUser ContextKey = "authkit:user"
	// ContextKeyClaims chave para armazenar as claims no contexto
	ContextKeyClaims ContextKey = "authkit:claims"
	// ContextKeyAuthContext chave para armazenar o contexto de auth no contexto
	ContextKeyAuthContext ContextKey = "authkit:auth_context"
	// ContextKeyToken chave para armazenar o token no contexto
	ContextKeyToken ContextKey = "authkit:token"
	// ContextKeyScopes chave para armazenar os scopes no contexto
	ContextKeyScopes ContextKey = "authkit:scopes"
)

// GetUserFromContext extrai o usuário do contexto.
func GetUserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(ContextKeyUser).(*User)
	return user, ok
}

// GetClaimsFromContext extrai as claims do contexto.
func GetClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(ContextKeyClaims).(*Claims)
	return claims, ok
}

// GetAuthContextFromContext extrai o contexto de autenticação do contexto.
func GetAuthContextFromContext(ctx context.Context) (*AuthContext, bool) {
	authCtx, ok := ctx.Value(ContextKeyAuthContext).(*AuthContext)
	return authCtx, ok
}

// GetTokenFromContext extrai o token do contexto.
func GetTokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(ContextKeyToken).(string)
	return token, ok
}

// GetScopesFromContext extrai os scopes do contexto.
func GetScopesFromContext(ctx context.Context) ([]string, bool) {
	scopes, ok := ctx.Value(ContextKeyScopes).([]string)
	return scopes, ok
}

// WithUser adiciona um usuário ao contexto.
func WithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, ContextKeyUser, user)
}

// WithClaims adiciona claims ao contexto.
func WithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, ContextKeyClaims, claims)
}

// WithAuthContext adiciona um contexto de autenticação ao contexto.
func WithAuthContext(ctx context.Context, authCtx *AuthContext) context.Context {
	return context.WithValue(ctx, ContextKeyAuthContext, authCtx)
}

// WithToken adiciona um token ao contexto.
func WithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, ContextKeyToken, token)
}

// WithScopes adiciona scopes ao contexto.
func WithScopes(ctx context.Context, scopes []string) context.Context {
	return context.WithValue(ctx, ContextKeyScopes, scopes)
}
