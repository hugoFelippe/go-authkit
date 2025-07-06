package contracts

import (
	"context"
	"time"
)

// TokenValidator define a interface para validação de tokens.
type TokenValidator interface {
	// ValidateToken valida um token e retorna as claims se válido
	ValidateToken(ctx context.Context, token string) (*Claims, error)

	// ValidateTokenWithType valida um token de um tipo específico
	ValidateTokenWithType(ctx context.Context, token string, tokenType TokenType) (*Claims, error)
}

// TokenGenerator define a interface para geração de tokens.
type TokenGenerator interface {
	// GenerateToken gera um novo token com as claims fornecidas
	GenerateToken(ctx context.Context, claims *Claims) (string, error)

	// GenerateTokenWithExpiry gera um token com tempo de expiração específico
	GenerateTokenWithExpiry(ctx context.Context, claims *Claims, expiry time.Duration) (string, error)

	// GenerateRefreshToken gera um refresh token para um usuário
	GenerateRefreshToken(ctx context.Context, user *User) (string, error)
}

// TokenManager combina validação e geração de tokens.
type TokenManager interface {
	TokenValidator
	TokenGenerator

	// RefreshToken renova um token usando um refresh token
	RefreshToken(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error)

	// RevokeToken revoga um token
	RevokeToken(ctx context.Context, token string) error

	// RevokeAllTokens revoga todos os tokens de um usuário
	RevokeAllTokens(ctx context.Context, userID string) error

	// IntrospectToken retorna informações sobre um token
	IntrospectToken(ctx context.Context, token string) (*TokenInfo, error)
}

// UserProvider define a interface para provedores de usuário.
type UserProvider interface {
	// GetUser busca um usuário por ID
	GetUser(ctx context.Context, userID string) (*User, error)

	// GetUserByEmail busca um usuário por email
	GetUserByEmail(ctx context.Context, email string) (*User, error)

	// GetUserByUsername busca um usuário por username
	GetUserByUsername(ctx context.Context, username string) (*User, error)

	// CreateUser cria um novo usuário
	CreateUser(ctx context.Context, user *User) error

	// UpdateUser atualiza um usuário existente
	UpdateUser(ctx context.Context, user *User) error

	// DeleteUser remove um usuário
	DeleteUser(ctx context.Context, userID string) error

	// ValidateCredentials valida credenciais de usuário
	ValidateCredentials(ctx context.Context, identifier, password string) (*User, error)
}

// PermissionProvider define a interface para provedores de permissão.
type PermissionProvider interface {
	// GetUserPermissions retorna as permissões de um usuário
	GetUserPermissions(ctx context.Context, userID string) ([]Permission, error)

	// GetUserRoles retorna os papéis de um usuário
	GetUserRoles(ctx context.Context, userID string) ([]Role, error)

	// HasPermission verifica se um usuário tem uma permissão específica
	HasPermission(ctx context.Context, userID, resource, action string) (bool, error)

	// HasRole verifica se um usuário tem um papel específico
	HasRole(ctx context.Context, userID, roleName string) (bool, error)

	// HasScope verifica se um usuário tem um escopo específico
	HasScope(ctx context.Context, userID, scope string) (bool, error)
}

// StorageProvider define a interface para armazenamento de dados de autenticação.
type StorageProvider interface {
	// Token storage
	StoreToken(ctx context.Context, token string, claims *Claims, expiry time.Duration) error
	GetToken(ctx context.Context, token string) (*Claims, error)
	DeleteToken(ctx context.Context, token string) error
	DeleteAllTokens(ctx context.Context, userID string) error

	// Session storage
	StoreSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	DeleteSession(ctx context.Context, sessionID string) error
	DeleteAllSessions(ctx context.Context, userID string) error

	// API Key storage
	StoreAPIKey(ctx context.Context, apiKey *APIKey) error
	GetAPIKey(ctx context.Context, key string) (*APIKey, error)
	DeleteAPIKey(ctx context.Context, keyID string) error
	GetUserAPIKeys(ctx context.Context, userID string) ([]*APIKey, error)

	// General key-value storage
	Set(ctx context.Context, key string, value interface{}, expiry time.Duration) error
	Get(ctx context.Context, key string) (interface{}, error)
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)

	// Health check
	Ping(ctx context.Context) error
	Close() error
}

// OAuth2Provider define a interface para provedores OAuth2.
type OAuth2Provider interface {
	// GetAuthorizationURL retorna a URL de autorização
	GetAuthorizationURL(state string, scopes []string) string

	// ExchangeCodeForToken troca um código de autorização por um token
	ExchangeCodeForToken(ctx context.Context, code string) (*OAuth2Token, error)

	// RefreshToken renova um token OAuth2
	RefreshToken(ctx context.Context, refreshToken string) (*OAuth2Token, error)

	// GetUserInfo obtém informações do usuário usando um token de acesso
	GetUserInfo(ctx context.Context, accessToken string) (*User, error)

	// RevokeToken revoga um token OAuth2
	RevokeToken(ctx context.Context, token string) error
}

// JWTProvider define a interface para provedores JWT.
type JWTProvider interface {
	// GenerateJWT gera um JWT com as claims fornecidas
	GenerateJWT(ctx context.Context, claims *Claims) (string, error)

	// ValidateJWT valida um JWT e retorna as claims
	ValidateJWT(ctx context.Context, token string) (*Claims, error)

	// ParseJWT faz parse de um JWT sem validar a assinatura
	ParseJWT(ctx context.Context, token string) (*Claims, error)

	// GetSigningMethod retorna o método de assinatura usado
	GetSigningMethod() string

	// GetIssuer retorna o emissor configurado
	GetIssuer() string
}

// APIKeyProvider define a interface para provedores de API Key.
type APIKeyProvider interface {
	// GenerateAPIKey gera uma nova API key
	GenerateAPIKey(ctx context.Context, userID, name string, scopes []string, expiry *time.Time) (*APIKey, error)

	// ValidateAPIKey valida uma API key e retorna as informações
	ValidateAPIKey(ctx context.Context, key string) (*APIKey, error)

	// RevokeAPIKey revoga uma API key
	RevokeAPIKey(ctx context.Context, keyID string) error

	// ListUserAPIKeys lista todas as API keys de um usuário
	ListUserAPIKeys(ctx context.Context, userID string) ([]*APIKey, error)

	// UpdateAPIKey atualiza uma API key existente
	UpdateAPIKey(ctx context.Context, apiKey *APIKey) error
}

// Middleware define a interface para middlewares de autenticação.
type Middleware interface {
	// Authenticate executa a autenticação
	Authenticate(ctx context.Context, token string) (*AuthContext, error)

	// Authorize executa a autorização
	Authorize(ctx context.Context, authCtx *AuthContext, resource, action string) error

	// RequireScopes verifica se o contexto possui os escopos necessários
	RequireScopes(ctx context.Context, authCtx *AuthContext, scopes []string) error

	// RequireRoles verifica se o contexto possui os papéis necessários
	RequireRoles(ctx context.Context, authCtx *AuthContext, roles []string) error

	// RequirePermissions verifica se o contexto possui as permissões necessárias
	RequirePermissions(ctx context.Context, authCtx *AuthContext, permissions []Permission) error
}

// EventHandler define a interface para manipulação de eventos de autenticação.
type EventHandler interface {
	// OnLogin é chamado quando um usuário faz login
	OnLogin(ctx context.Context, user *User, authCtx *AuthContext) error

	// OnLogout é chamado quando um usuário faz logout
	OnLogout(ctx context.Context, user *User, authCtx *AuthContext) error

	// OnTokenGenerated é chamado quando um token é gerado
	OnTokenGenerated(ctx context.Context, token string, claims *Claims) error

	// OnTokenValidated é chamado quando um token é validado
	OnTokenValidated(ctx context.Context, token string, claims *Claims) error

	// OnTokenRevoked é chamado quando um token é revogado
	OnTokenRevoked(ctx context.Context, token string) error

	// OnAuthenticationFailed é chamado quando a autenticação falha
	OnAuthenticationFailed(ctx context.Context, reason string, metadata map[string]interface{}) error

	// OnAuthorizationFailed é chamado quando a autorização falha
	OnAuthorizationFailed(ctx context.Context, user *User, resource, action, reason string) error
}

// ConfigProvider define a interface para provedores de configuração.
type ConfigProvider interface {
	// GetString retorna um valor de configuração como string
	GetString(key string) string

	// GetInt retorna um valor de configuração como int
	GetInt(key string) int

	// GetBool retorna um valor de configuração como bool
	GetBool(key string) bool

	// GetDuration retorna um valor de configuração como duration
	GetDuration(key string) time.Duration

	// Set define um valor de configuração
	Set(key string, value interface{}) error

	// IsSet verifica se uma chave de configuração está definida
	IsSet(key string) bool

	// GetAll retorna todas as configurações
	GetAll() map[string]interface{}
}

// Validator é a interface para validação de tokens (movida de token/validator.go)
type Validator interface {
	ValidateToken(ctx context.Context, tokenString string) (*Claims, error)
	GetTokenType() string
}

// ValidationCache interface para cache de validação (movida de token/validator.go)
type ValidationCache interface {
	Get(ctx context.Context, key string) (*Claims, bool)
	Set(ctx context.Context, key string, claims *Claims, ttl time.Duration)
	Delete(ctx context.Context, key string)
}

// APIKeyStorage interface para armazenamento de API Keys (movida de token/apikey.go)
type APIKeyStorage interface {
	Store(ctx context.Context, key string, data *APIKeyData) error
	Get(ctx context.Context, key string) (*APIKeyData, error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, userID string) ([]*APIKeyData, error)
	DeleteByUser(ctx context.Context, userID string) error
}
