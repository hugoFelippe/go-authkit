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

// TokenStorage interface para armazenamento específico de tokens
type TokenStorage interface {
	// StoreToken armazena um token com sua expiração
	StoreToken(ctx context.Context, token string, claims *Claims, expiry time.Duration) error

	// GetToken recupera as claims de um token
	GetToken(ctx context.Context, token string) (*Claims, error)

	// DeleteToken remove um token do armazenamento
	DeleteToken(ctx context.Context, token string) error

	// DeleteAllTokens remove todos os tokens de um usuário
	DeleteAllTokens(ctx context.Context, userID string) error

	// IsRevoked verifica se um token foi revogado
	IsRevoked(ctx context.Context, token string) (bool, error)

	// RevokeToken revoga um token específico
	RevokeToken(ctx context.Context, token string) error

	// RevokeAllTokens revoga todos os tokens de um usuário
	RevokeAllTokens(ctx context.Context, userID string) error

	// Cleanup remove tokens expirados
	Cleanup(ctx context.Context) error
}

// UserStorage interface para armazenamento específico de usuários
type UserStorage interface {
	// StoreUser armazena um usuário
	StoreUser(ctx context.Context, user *User) error

	// GetUser recupera um usuário por ID
	GetUser(ctx context.Context, userID string) (*User, error)

	// GetUserByEmail recupera um usuário por email
	GetUserByEmail(ctx context.Context, email string) (*User, error)

	// GetUserByUsername recupera um usuário por username
	GetUserByUsername(ctx context.Context, username string) (*User, error)

	// UpdateUser atualiza um usuário existente
	UpdateUser(ctx context.Context, user *User) error

	// DeleteUser remove um usuário
	DeleteUser(ctx context.Context, userID string) error

	// ListUsers lista usuários com paginação
	ListUsers(ctx context.Context, offset, limit int) ([]*User, error)

	// CountUsers conta o total de usuários
	CountUsers(ctx context.Context) (int64, error)
}

// SessionStorage interface para armazenamento específico de sessões
type SessionStorage interface {
	// StoreSession armazena uma sessão
	StoreSession(ctx context.Context, session *Session) error

	// GetSession recupera uma sessão por ID
	GetSession(ctx context.Context, sessionID string) (*Session, error)

	// DeleteSession remove uma sessão
	DeleteSession(ctx context.Context, sessionID string) error

	// DeleteAllSessions remove todas as sessões de um usuário
	DeleteAllSessions(ctx context.Context, userID string) error

	// GetUserSessions recupera todas as sessões ativas de um usuário
	GetUserSessions(ctx context.Context, userID string) ([]*Session, error)

	// Cleanup remove sessões expiradas
	Cleanup(ctx context.Context) error
}

// ConfigStorage interface para armazenamento de configurações
type ConfigStorage interface {
	// Set define um valor de configuração
	Set(ctx context.Context, key string, value interface{}, expiry time.Duration) error

	// Get recupera um valor de configuração
	Get(ctx context.Context, key string) (interface{}, error)

	// Delete remove uma configuração
	Delete(ctx context.Context, key string) error

	// Exists verifica se uma chave existe
	Exists(ctx context.Context, key string) (bool, error)

	// GetAll recupera todas as configurações
	GetAll(ctx context.Context) (map[string]interface{}, error)

	// Clear remove todas as configurações
	Clear(ctx context.Context) error
}

// CacheStorage interface para cache genérico com TTL
type CacheStorage interface {
	// SetCache armazena um valor com TTL opcional
	SetCache(ctx context.Context, key string, value interface{}, ttl time.Duration) error

	// GetCache recupera um valor
	GetCache(ctx context.Context, key string) (interface{}, error)

	// DeleteCache remove um valor
	DeleteCache(ctx context.Context, key string) error

	// ExistsCache verifica se uma chave existe
	ExistsCache(ctx context.Context, key string) (bool, error)

	// TTL retorna o tempo de vida restante de uma chave
	TTL(ctx context.Context, key string) (time.Duration, error)

	// Expire define um novo TTL para uma chave
	Expire(ctx context.Context, key string, ttl time.Duration) error

	// Keys lista todas as chaves com um padrão opcional
	Keys(ctx context.Context, pattern string) ([]string, error)

	// ClearCache remove todas as chaves
	ClearCache(ctx context.Context) error

	// Size retorna o número de chaves armazenadas
	Size(ctx context.Context) (int64, error)
}

// HealthChecker interface para verificação de saúde do storage
type HealthChecker interface {
	// Ping verifica se o storage está acessível
	Ping(ctx context.Context) error

	// Stats retorna estatísticas do storage
	Stats(ctx context.Context) (map[string]interface{}, error)
}

// StorageManager interface que combina todos os tipos de storage
type StorageManager interface {
	TokenStorage
	UserStorage
	SessionStorage
	ConfigStorage
	CacheStorage
	HealthChecker

	// Close fecha a conexão com o storage
	Close() error
}
