package authkit

import (
	"context"
	"fmt"
	"time"

	"github.com/hugoFelippe/go-authkit/contracts"
)

// AuthKit é a estrutura principal que gerencia autenticação e autorização.
type AuthKit struct {
	config *Config

	// Core components
	tokenManager      contracts.TokenManager
	userProvider      contracts.UserProvider
	permissionChecker contracts.PermissionProvider
	storageProvider   contracts.StorageProvider

	// External providers
	oauth2Provider contracts.OAuth2Provider
	jwtProvider    contracts.JWTProvider

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
func (a *AuthKit) TokenValidator() contracts.TokenValidator {
	if a.tokenManager != nil {
		return a.tokenManager
	}
	// TODO: Retornar implementação padrão
	return nil
}

// TokenGenerator retorna o gerador de tokens.
func (a *AuthKit) TokenGenerator() contracts.TokenGenerator {
	if a.tokenManager != nil {
		return a.tokenManager
	}
	// TODO: Retornar implementação padrão
	return nil
}

// GenerateToken gera um novo token com as claims fornecidas.
func (a *AuthKit) GenerateToken(ctx context.Context, claims *contracts.Claims) (string, error) {
	generator := a.TokenGenerator()
	if generator == nil {
		return "", contracts.ErrConfigurationError
	}
	return generator.GenerateToken(ctx, claims)
}

// GenerateTokenForUser gera um token para um usuário específico.
func (a *AuthKit) GenerateTokenForUser(ctx context.Context, userID string) (string, error) {
	user, err := a.GetUser(ctx, userID)
	if err != nil {
		return "", err
	}

	claims := &contracts.Claims{
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
func (a *AuthKit) ValidateToken(ctx context.Context, token string) (*contracts.Claims, error) {
	validator := a.TokenValidator()
	if validator == nil {
		return nil, contracts.ErrConfigurationError
	}
	return validator.ValidateToken(ctx, token)
}

// RefreshToken renova um token usando um refresh token.
func (a *AuthKit) RefreshToken(ctx context.Context, refreshToken string) (string, error) {
	if a.tokenManager == nil {
		return "", contracts.ErrConfigurationError
	}

	// TokenManager retorna (accessToken, newRefreshToken, error)
	accessToken, _, err := a.tokenManager.RefreshToken(ctx, refreshToken)
	return accessToken, err
}

// RevokeToken revoga um token.
func (a *AuthKit) RevokeToken(ctx context.Context, token string) error {
	if a.tokenManager == nil {
		return contracts.ErrConfigurationError
	}
	return a.tokenManager.RevokeToken(ctx, token)
}

// User Management Methods

// GetUser busca um usuário por ID.
func (a *AuthKit) GetUser(ctx context.Context, userID string) (*contracts.User, error) {
	if a.userProvider == nil {
		return nil, contracts.ErrConfigurationError
	}
	return a.userProvider.GetUser(ctx, userID)
}

// GetUserByUsername busca um usuário por username.
func (a *AuthKit) GetUserByUsername(ctx context.Context, username string) (*contracts.User, error) {
	if a.userProvider == nil {
		return nil, contracts.ErrConfigurationError
	}
	return a.userProvider.GetUserByUsername(ctx, username)
}

// GetUserByEmail busca um usuário por email.
func (a *AuthKit) GetUserByEmail(ctx context.Context, email string) (*contracts.User, error) {
	if a.userProvider == nil {
		return nil, contracts.ErrConfigurationError
	}
	return a.userProvider.GetUserByEmail(ctx, email)
}

// ValidateCredentials valida credenciais de usuário.
func (a *AuthKit) ValidateCredentials(ctx context.Context, username, password string) (*contracts.User, error) {
	if a.userProvider == nil {
		return nil, contracts.ErrConfigurationError
	}
	return a.userProvider.ValidateCredentials(ctx, username, password)
}

// CreateUser cria um novo usuário.
func (a *AuthKit) CreateUser(ctx context.Context, user *contracts.User) error {
	if a.userProvider == nil {
		return contracts.ErrConfigurationError
	}
	return a.userProvider.CreateUser(ctx, user)
}

// Permission Management Methods

// HasPermission verifica se um usuário tem uma permissão específica.
func (a *AuthKit) HasPermission(ctx context.Context, userID, resource, action string) (bool, error) {
	if a.permissionChecker == nil {
		return false, contracts.ErrConfigurationError
	}
	return a.permissionChecker.HasPermission(ctx, userID, resource, action)
}

// HasRole verifica se um usuário tem um papel específico.
func (a *AuthKit) HasRole(ctx context.Context, userID, roleName string) (bool, error) {
	if a.permissionChecker == nil {
		return false, contracts.ErrConfigurationError
	}
	return a.permissionChecker.HasRole(ctx, userID, roleName)
}

// HasScope verifica se um token tem um escopo específico.
func (a *AuthKit) HasScope(ctx context.Context, scopes []string, required string) bool {
	// Implementação simplificada de verificação de escopo
	for _, scope := range scopes {
		if scope == required {
			return true
		}
	}
	return false
}

// Storage Methods

// UseStorageProvider define um provedor de armazenamento personalizado.
func (a *AuthKit) UseStorageProvider(provider contracts.StorageProvider) {
	a.storageProvider = provider
}

// Component Injection Methods

// UseTokenManager define um gerenciador de tokens personalizado.
func (a *AuthKit) UseTokenManager(manager contracts.TokenManager) {
	a.tokenManager = manager
}

// UseUserProvider define um provedor de usuários personalizado.
func (a *AuthKit) UseUserProvider(provider contracts.UserProvider) {
	a.userProvider = provider
}

// UsePermissionProvider define um provedor de permissões personalizado.
func (a *AuthKit) UsePermissionProvider(provider contracts.PermissionProvider) {
	a.permissionChecker = provider
}

// UseOAuth2Provider define um provedor OAuth2 personalizado.
func (a *AuthKit) UseOAuth2Provider(provider contracts.OAuth2Provider) {
	a.oauth2Provider = provider
}

// UseJWTProvider define um provedor JWT personalizado.
func (a *AuthKit) UseJWTProvider(provider contracts.JWTProvider) {
	a.jwtProvider = provider
}

// Utility Methods

// IsInitialized verifica se o AuthKit foi inicializado corretamente.
func (a *AuthKit) IsInitialized() bool {
	return a.initialized
}

// Close fecha todos os recursos e conexões.
func (a *AuthKit) Close() error {
	if a.storageProvider != nil {
		return a.storageProvider.Close()
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
