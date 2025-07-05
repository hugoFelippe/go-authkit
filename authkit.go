package authkit

import (
	"context"
	"fmt"
	"time"
)

// AuthKit é a estrutura principal que gerencia autenticação e autorização.
type AuthKit struct {
	config *Config

	// Core components
	tokenManager      TokenManager
	userProvider      UserProvider
	permissionChecker PermissionChecker
	roleManager       RoleManager
	scopeChecker      ScopeChecker
	sessionManager    SessionManager
	apiKeyManager     APIKeyManager

	// Storage
	tokenStorage   TokenStorage
	userStorage    UserStorage
	sessionStorage SessionStorage

	// External providers
	oauth2Provider OAuth2Provider
	oidcProvider   OIDCProvider

	// Internal state
	initialized bool
}

// New cria uma nova instância do AuthKit com as opções fornecidas.
func New(options ...Option) *AuthKit {
	config := DefaultConfig()

	// Aplicar opções
	for _, option := range options {
		option(config)
	}

	// Validar configuração
	if err := config.Validate(); err != nil {
		panic(fmt.Sprintf("invalid authkit configuration: %v", err))
	}

	auth := &AuthKit{
		config: config,
	}

	// Inicializar componentes padrão
	if err := auth.initializeDefaults(); err != nil {
		panic(fmt.Sprintf("failed to initialize authkit: %v", err))
	}

	auth.initialized = true
	return auth
}

// initializeDefaults inicializa os componentes padrão do AuthKit.
func (a *AuthKit) initializeDefaults() error {
	// TODO: Implementar inicialização dos componentes padrão
	// Por enquanto, apenas placeholder
	return nil
}

// Config retorna a configuração atual.
func (a *AuthKit) Config() *Config {
	return a.config
}

// Token Management Methods

// TokenValidator retorna o validador de tokens.
func (a *AuthKit) TokenValidator() TokenValidator {
	if a.tokenManager != nil {
		return a.tokenManager
	}
	// TODO: Retornar implementação padrão
	return nil
}

// TokenGenerator retorna o gerador de tokens.
func (a *AuthKit) TokenGenerator() TokenGenerator {
	if a.tokenManager != nil {
		return a.tokenManager
	}
	// TODO: Retornar implementação padrão
	return nil
}

// GenerateToken gera um novo token com as claims fornecidas.
func (a *AuthKit) GenerateToken(ctx context.Context, claims *Claims) (string, error) {
	generator := a.TokenGenerator()
	if generator == nil {
		return "", ErrInvalidConfig
	}
	return generator.GenerateToken(ctx, claims)
}

// GenerateTokenForUser gera um token para um usuário específico.
func (a *AuthKit) GenerateTokenForUser(ctx context.Context, userID string) (string, error) {
	user, err := a.GetUser(ctx, userID)
	if err != nil {
		return "", err
	}

	claims := &Claims{
		Subject:     user.ID,
		Issuer:      a.config.Issuer,
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(a.config.TokenExpiry),
		Email:       user.Email,
		Username:    user.Username,
		Name:        user.Name,
		Roles:       user.Roles,
		Permissions: user.Permissions,
	}

	if len(a.config.Audience) > 0 {
		claims.Audience = a.config.Audience
	}

	return a.GenerateToken(ctx, claims)
}

// ValidateToken valida um token e retorna as claims.
func (a *AuthKit) ValidateToken(ctx context.Context, token string) (*Claims, error) {
	validator := a.TokenValidator()
	if validator == nil {
		return nil, ErrInvalidConfig
	}
	return validator.ValidateToken(ctx, token)
}

// RefreshToken renova um token usando um refresh token.
func (a *AuthKit) RefreshToken(ctx context.Context, refreshToken string) (string, error) {
	if a.tokenManager == nil {
		return "", ErrInvalidConfig
	}
	return a.tokenManager.RefreshToken(ctx, refreshToken)
}

// RevokeToken revoga um token.
func (a *AuthKit) RevokeToken(ctx context.Context, token string) error {
	if a.tokenManager == nil {
		return ErrInvalidConfig
	}
	return a.tokenManager.RevokeToken(ctx, token)
}

// User Management Methods

// GetUser busca um usuário por ID.
func (a *AuthKit) GetUser(ctx context.Context, userID string) (*User, error) {
	if a.userProvider == nil {
		return nil, ErrInvalidConfig
	}
	return a.userProvider.GetUser(ctx, userID)
}

// GetUserByUsername busca um usuário por username.
func (a *AuthKit) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	if a.userProvider == nil {
		return nil, ErrInvalidConfig
	}
	return a.userProvider.GetUserByUsername(ctx, username)
}

// GetUserByEmail busca um usuário por email.
func (a *AuthKit) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	if a.userProvider == nil {
		return nil, ErrInvalidConfig
	}
	return a.userProvider.GetUserByEmail(ctx, email)
}

// ValidateCredentials valida credenciais de usuário.
func (a *AuthKit) ValidateCredentials(ctx context.Context, username, password string) (*User, error) {
	if a.userProvider == nil {
		return nil, ErrInvalidConfig
	}
	return a.userProvider.ValidateCredentials(ctx, username, password)
}

// CreateUser cria um novo usuário.
func (a *AuthKit) CreateUser(ctx context.Context, user *User) error {
	if a.userProvider == nil {
		return ErrInvalidConfig
	}
	return a.userProvider.CreateUser(ctx, user)
}

// Permission Management Methods

// HasPermission verifica se um usuário tem uma permissão específica.
func (a *AuthKit) HasPermission(ctx context.Context, userID string, permission string) (bool, error) {
	if a.permissionChecker == nil {
		return false, ErrInvalidConfig
	}
	return a.permissionChecker.HasPermission(ctx, userID, permission)
}

// HasRole verifica se um usuário tem um papel específico.
func (a *AuthKit) HasRole(ctx context.Context, userID string, role string) (bool, error) {
	if a.roleManager == nil {
		return false, ErrInvalidConfig
	}
	return a.roleManager.HasRole(ctx, userID, role)
}

// HasScope verifica se um token tem um escopo específico.
func (a *AuthKit) HasScope(ctx context.Context, scopes []string, required string) bool {
	if a.scopeChecker == nil {
		return false
	}
	return a.scopeChecker.HasScope(ctx, scopes, required)
}

// API Key Management Methods

// GenerateAPIKey gera uma nova API Key.
func (a *AuthKit) GenerateAPIKey(ctx context.Context, userID, name string, scopes []string) (*APIKey, error) {
	if a.apiKeyManager == nil {
		return nil, ErrInvalidConfig
	}
	return a.apiKeyManager.GenerateAPIKey(ctx, userID, name, scopes)
}

// ValidateAPIKey valida uma API Key e retorna as claims.
func (a *AuthKit) ValidateAPIKey(ctx context.Context, key string) (*Claims, error) {
	if a.apiKeyManager == nil {
		return nil, ErrInvalidConfig
	}
	return a.apiKeyManager.ValidateAPIKey(ctx, key)
}

// Session Management Methods

// CreateSession cria uma nova sessão.
func (a *AuthKit) CreateSession(ctx context.Context, userID string, metadata map[string]string) (*SessionInfo, error) {
	if a.sessionManager == nil {
		return nil, ErrInvalidConfig
	}
	return a.sessionManager.CreateSession(ctx, userID, metadata)
}

// GetSession busca uma sessão por ID.
func (a *AuthKit) GetSession(ctx context.Context, sessionID string) (*SessionInfo, error) {
	if a.sessionManager == nil {
		return nil, ErrInvalidConfig
	}
	return a.sessionManager.GetSession(ctx, sessionID)
}

// OAuth2/OIDC Methods

// GetLoginURL retorna a URL de login OAuth2/OIDC.
func (a *AuthKit) GetLoginURL(state string, scopes ...string) string {
	if a.oauth2Provider != nil {
		return a.oauth2Provider.GetAuthorizationURL(state, scopes)
	}
	if a.oidcProvider != nil {
		return a.oidcProvider.GetAuthorizationURL(state, scopes)
	}
	return ""
}

// HandleCallback processa o callback OAuth2/OIDC.
func (a *AuthKit) HandleCallback(ctx context.Context, code, state string) (*OAuth2Token, error) {
	if a.oauth2Provider != nil {
		return a.oauth2Provider.ExchangeCode(ctx, code, state)
	}
	if a.oidcProvider != nil {
		return a.oidcProvider.ExchangeCode(ctx, code, state)
	}
	return nil, ErrInvalidConfig
}

// Component Injection Methods

// UseTokenManager define um gerenciador de tokens personalizado.
func (a *AuthKit) UseTokenManager(manager TokenManager) {
	a.tokenManager = manager
}

// UseUserProvider define um provedor de usuários personalizado.
func (a *AuthKit) UseUserProvider(provider UserProvider) {
	a.userProvider = provider
}

// UsePermissionChecker define um verificador de permissões personalizado.
func (a *AuthKit) UsePermissionChecker(checker PermissionChecker) {
	a.permissionChecker = checker
}

// UseRoleManager define um gerenciador de papéis personalizado.
func (a *AuthKit) UseRoleManager(manager RoleManager) {
	a.roleManager = manager
}

// UseScopeChecker define um verificador de escopos personalizado.
func (a *AuthKit) UseScopeChecker(checker ScopeChecker) {
	a.scopeChecker = checker
}

// UseSessionManager define um gerenciador de sessões personalizado.
func (a *AuthKit) UseSessionManager(manager SessionManager) {
	a.sessionManager = manager
}

// UseAPIKeyManager define um gerenciador de API keys personalizado.
func (a *AuthKit) UseAPIKeyManager(manager APIKeyManager) {
	a.apiKeyManager = manager
}

// UseOAuth2Provider define um provedor OAuth2 personalizado.
func (a *AuthKit) UseOAuth2Provider(provider OAuth2Provider) {
	a.oauth2Provider = provider
}

// UseOIDCProvider define um provedor OIDC personalizado.
func (a *AuthKit) UseOIDCProvider(provider OIDCProvider) {
	a.oidcProvider = provider
}

// Storage Methods

// UseTokenStorage define um armazenamento de tokens personalizado.
func (a *AuthKit) UseTokenStorage(storage TokenStorage) {
	a.tokenStorage = storage
}

// UseUserStorage define um armazenamento de usuários personalizado.
func (a *AuthKit) UseUserStorage(storage UserStorage) {
	a.userStorage = storage
}

// UseSessionStorage define um armazenamento de sessões personalizado.
func (a *AuthKit) UseSessionStorage(storage SessionStorage) {
	a.sessionStorage = storage
}

// Utility Methods

// IsInitialized verifica se o AuthKit foi inicializado corretamente.
func (a *AuthKit) IsInitialized() bool {
	return a.initialized
}

// Close fecha todos os recursos e conexões.
func (a *AuthKit) Close() error {
	var errors []error

	if a.tokenStorage != nil {
		if err := a.tokenStorage.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if a.userStorage != nil {
		if err := a.userStorage.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if a.sessionStorage != nil {
		if err := a.sessionStorage.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors closing authkit: %v", errors)
	}

	return nil
}

// ExtractTokenFromRequest é uma função helper para extrair tokens de requisições HTTP.
// Esta função será implementada no pacote middleware.
func ExtractTokenFromRequest(req interface{}) string {
	// TODO: Implementar extração de token de diferentes fontes
	// Por enquanto, placeholder
	return ""
}
