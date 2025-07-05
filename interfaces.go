package authkit

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

	// GenerateRefreshToken gera um refresh token
	GenerateRefreshToken(ctx context.Context, userID string) (string, error)
}

// TokenManager combina validação e geração de tokens.
type TokenManager interface {
	TokenValidator
	TokenGenerator

	// RefreshToken renova um token usando um refresh token
	RefreshToken(ctx context.Context, refreshToken string) (string, error)

	// RevokeToken revoga um token
	RevokeToken(ctx context.Context, token string) error

	// IntrospectToken retorna informações sobre um token
	IntrospectToken(ctx context.Context, token string) (*TokenInfo, error)
}

// UserProvider define a interface para provedores de usuário.
type UserProvider interface {
	// GetUser busca um usuário por ID
	GetUser(ctx context.Context, userID string) (*User, error)

	// GetUserByUsername busca um usuário por username
	GetUserByUsername(ctx context.Context, username string) (*User, error)

	// GetUserByEmail busca um usuário por email
	GetUserByEmail(ctx context.Context, email string) (*User, error)

	// ValidateCredentials valida credenciais de usuário
	ValidateCredentials(ctx context.Context, username, password string) (*User, error)

	// CreateUser cria um novo usuário
	CreateUser(ctx context.Context, user *User) error

	// UpdateUser atualiza um usuário existente
	UpdateUser(ctx context.Context, user *User) error

	// DeleteUser remove um usuário
	DeleteUser(ctx context.Context, userID string) error
}

// PermissionChecker define a interface para verificação de permissões.
type PermissionChecker interface {
	// HasPermission verifica se um usuário tem uma permissão específica
	HasPermission(ctx context.Context, userID string, permission string) (bool, error)

	// HasPermissions verifica se um usuário tem todas as permissões especificadas
	HasPermissions(ctx context.Context, userID string, permissions []string) (bool, error)

	// HasAnyPermission verifica se um usuário tem pelo menos uma das permissões
	HasAnyPermission(ctx context.Context, userID string, permissions []string) (bool, error)

	// GetUserPermissions retorna todas as permissões de um usuário
	GetUserPermissions(ctx context.Context, userID string) ([]string, error)
}

// RoleManager define a interface para gerenciamento de papéis.
type RoleManager interface {
	// HasRole verifica se um usuário tem um papel específico
	HasRole(ctx context.Context, userID string, role string) (bool, error)

	// HasRoles verifica se um usuário tem todos os papéis especificados
	HasRoles(ctx context.Context, userID string, roles []string) (bool, error)

	// HasAnyRole verifica se um usuário tem pelo menos um dos papéis
	HasAnyRole(ctx context.Context, userID string, roles []string) (bool, error)

	// GetUserRoles retorna todos os papéis de um usuário
	GetUserRoles(ctx context.Context, userID string) ([]string, error)

	// AssignRole atribui um papel a um usuário
	AssignRole(ctx context.Context, userID string, role string) error

	// RevokeRole remove um papel de um usuário
	RevokeRole(ctx context.Context, userID string, role string) error
}

// ScopeChecker define a interface para verificação de escopos.
type ScopeChecker interface {
	// HasScope verifica se um token tem um escopo específico
	HasScope(ctx context.Context, scopes []string, required string) bool

	// HasScopes verifica se um token tem todos os escopos especificados
	HasScopes(ctx context.Context, scopes []string, required []string) bool

	// HasAnyScope verifica se um token tem pelo menos um dos escopos
	HasAnyScope(ctx context.Context, scopes []string, required []string) bool

	// ParseScopes converte uma string de escopos em uma lista
	ParseScopes(scopeString string) []string

	// FormatScopes converte uma lista de escopos em uma string
	FormatScopes(scopes []string) string
}

// SessionManager define a interface para gerenciamento de sessões.
type SessionManager interface {
	// CreateSession cria uma nova sessão
	CreateSession(ctx context.Context, userID string, metadata map[string]string) (*SessionInfo, error)

	// GetSession busca uma sessão por ID
	GetSession(ctx context.Context, sessionID string) (*SessionInfo, error)

	// UpdateSession atualiza uma sessão existente
	UpdateSession(ctx context.Context, session *SessionInfo) error

	// DeleteSession remove uma sessão
	DeleteSession(ctx context.Context, sessionID string) error

	// GetUserSessions retorna todas as sessões de um usuário
	GetUserSessions(ctx context.Context, userID string) ([]*SessionInfo, error)

	// InvalidateUserSessions invalida todas as sessões de um usuário
	InvalidateUserSessions(ctx context.Context, userID string) error
}

// APIKeyManager define a interface para gerenciamento de API Keys.
type APIKeyManager interface {
	// GenerateAPIKey gera uma nova API Key
	GenerateAPIKey(ctx context.Context, userID, name string, scopes []string) (*APIKey, error)

	// ValidateAPIKey valida uma API Key e retorna as claims
	ValidateAPIKey(ctx context.Context, key string) (*Claims, error)

	// GetAPIKey busca uma API Key por ID
	GetAPIKey(ctx context.Context, keyID string) (*APIKey, error)

	// ListAPIKeys lista todas as API Keys de um usuário
	ListAPIKeys(ctx context.Context, userID string) ([]*APIKey, error)

	// RevokeAPIKey revoga uma API Key
	RevokeAPIKey(ctx context.Context, keyID string) error

	// UpdateAPIKey atualiza uma API Key
	UpdateAPIKey(ctx context.Context, apiKey *APIKey) error
}

// OAuth2Provider define a interface para provedores OAuth2.
type OAuth2Provider interface {
	// GetAuthorizationURL retorna a URL de autorização
	GetAuthorizationURL(state string, scopes []string) string

	// ExchangeCode troca um código de autorização por tokens
	ExchangeCode(ctx context.Context, code, state string) (*OAuth2Token, error)

	// RefreshToken renova um token usando refresh token
	RefreshToken(ctx context.Context, refreshToken string) (*OAuth2Token, error)

	// ValidateToken valida um token OAuth2
	ValidateToken(ctx context.Context, token string) (*Claims, error)

	// RevokeToken revoga um token OAuth2
	RevokeToken(ctx context.Context, token string) error
}

// OIDCProvider define a interface para provedores OpenID Connect.
type OIDCProvider interface {
	OAuth2Provider

	// GetUserInfo busca informações do usuário usando um token
	GetUserInfo(ctx context.Context, accessToken string) (map[string]interface{}, error)

	// ValidateIDToken valida um ID Token
	ValidateIDToken(ctx context.Context, idToken string) (*Claims, error)

	// GetJWKS retorna as chaves públicas do provedor
	GetJWKS(ctx context.Context) (interface{}, error)
}

// Storage define a interface base para armazenamento.
type Storage interface {
	// Set armazena um valor com uma chave
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error

	// Get recupera um valor por chave
	Get(ctx context.Context, key string, dest interface{}) error

	// Delete remove um valor por chave
	Delete(ctx context.Context, key string) error

	// Exists verifica se uma chave existe
	Exists(ctx context.Context, key string) (bool, error)

	// Keys retorna todas as chaves que correspondem a um padrão
	Keys(ctx context.Context, pattern string) ([]string, error)

	// Close fecha a conexão de armazenamento
	Close() error
}

// TokenStorage define a interface específica para armazenamento de tokens.
type TokenStorage interface {
	Storage

	// StoreToken armazena um token
	StoreToken(ctx context.Context, tokenID string, token *TokenInfo) error

	// GetToken recupera um token
	GetToken(ctx context.Context, tokenID string) (*TokenInfo, error)

	// RevokeToken marca um token como revogado
	RevokeToken(ctx context.Context, tokenID string) error

	// IsTokenRevoked verifica se um token foi revogado
	IsTokenRevoked(ctx context.Context, tokenID string) (bool, error)

	// CleanupExpiredTokens remove tokens expirados
	CleanupExpiredTokens(ctx context.Context) error
}

// UserStorage define a interface específica para armazenamento de usuários.
type UserStorage interface {
	Storage

	// StoreUser armazena um usuário
	StoreUser(ctx context.Context, user *User) error

	// GetUser recupera um usuário por ID
	GetUser(ctx context.Context, userID string) (*User, error)

	// GetUserByUsername recupera um usuário por username
	GetUserByUsername(ctx context.Context, username string) (*User, error)

	// GetUserByEmail recupera um usuário por email
	GetUserByEmail(ctx context.Context, email string) (*User, error)

	// UpdateUser atualiza um usuário
	UpdateUser(ctx context.Context, user *User) error

	// DeleteUser remove um usuário
	DeleteUser(ctx context.Context, userID string) error

	// ListUsers lista usuários com paginação
	ListUsers(ctx context.Context, offset, limit int) ([]*User, error)
}

// SessionStorage define a interface específica para armazenamento de sessões.
type SessionStorage interface {
	Storage

	// StoreSession armazena uma sessão
	StoreSession(ctx context.Context, session *SessionInfo) error

	// GetSession recupera uma sessão
	GetSession(ctx context.Context, sessionID string) (*SessionInfo, error)

	// UpdateSession atualiza uma sessão
	UpdateSession(ctx context.Context, session *SessionInfo) error

	// DeleteSession remove uma sessão
	DeleteSession(ctx context.Context, sessionID string) error

	// GetUserSessions retorna todas as sessões de um usuário
	GetUserSessions(ctx context.Context, userID string) ([]*SessionInfo, error)

	// CleanupExpiredSessions remove sessões expiradas
	CleanupExpiredSessions(ctx context.Context) error
}

// Middleware define a interface para middlewares de autenticação.
type Middleware interface {
	// Handler retorna um http.Handler que aplica a autenticação
	Handler(next interface{}) interface{}

	// Wrap aplica o middleware a um handler
	Wrap(handler interface{}) interface{}
}

// AuthenticatorOptions define opções para configuração de autenticadores.
type AuthenticatorOptions struct {
	SkipPaths      []string                       `json:"skip_paths,omitempty"`
	RequiredScopes []string                       `json:"required_scopes,omitempty"`
	TokenSources   []string                       `json:"token_sources,omitempty"` // header, query, cookie
	ContextKeys    map[string]ContextKey          `json:"-"`
	OnError        func(error) interface{}        `json:"-"`
	OnSuccess      func(*AuthContext) interface{} `json:"-"`
}
