package token

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/hugoFelippe/go-authkit/contracts"
)

// APIKeyManager implementa TokenManager para API Keys
type APIKeyManager struct {
	config  *contracts.APIKeyConfig
	storage contracts.APIKeyStorage
}

// NewAPIKeyManager cria um novo gerenciador de API Keys
func NewAPIKeyManager(config *contracts.APIKeyConfig, storage contracts.APIKeyStorage) *APIKeyManager {
	if config == nil {
		config = DefaultAPIKeyConfig()
	}

	return &APIKeyManager{
		config:  config,
		storage: storage,
	}
}

// GenerateToken gera uma nova API Key
func (m *APIKeyManager) GenerateToken(ctx context.Context, user *contracts.User, options ...contracts.GenerateOption) (string, error) {
	opts := applyGenerateOptions(options)

	// Gerar chave aleatória
	keyBytes := make([]byte, m.config.Length)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}

	key := fmt.Sprintf("%x", keyBytes)
	if m.config.Prefix != "" {
		key = m.config.Prefix + key
	}

	// Preparar dados da chave
	data := &contracts.APIKeyData{
		ID:        generateJTI(),
		UserID:    user.ID,
		Name:      fmt.Sprintf("API Key for %s", user.Name),
		Prefix:    m.config.Prefix,
		Scopes:    opts.Scopes,
		CreatedAt: time.Now(),
		Active:    true,
		Metadata:  opts.CustomClaims,
	}

	// Configurar expiração
	if opts.ExpiresAt != nil {
		data.ExpiresAt = opts.ExpiresAt
	} else if m.config.ExpiryDefault > 0 {
		expiresAt := time.Now().Add(m.config.ExpiryDefault)
		data.ExpiresAt = &expiresAt
	}

	// Hash da chave se configurado
	if m.config.HashKeys {
		data.HashedKey = hashAPIKey(key)
	} else {
		data.HashedKey = key
	}

	// Armazenar
	if err := m.storage.Store(ctx, key, data); err != nil {
		return "", fmt.Errorf("failed to store API key: %w", err)
	}

	return key, nil
}

// GenerateRefreshToken API Keys não suportam refresh tokens
func (m *APIKeyManager) GenerateRefreshToken(ctx context.Context, user *contracts.User) (string, error) {
	return "", fmt.Errorf("API keys do not support refresh tokens")
}

// ValidateToken valida uma API Key
func (m *APIKeyManager) ValidateToken(ctx context.Context, tokenString string) (*contracts.Claims, error) {
	// Buscar no storage
	data, err := m.storage.Get(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("API key not found: %w", err)
	}

	// Verificar se está ativa
	if !data.Active {
		return nil, contracts.ErrInvalidToken
	}

	// Verificar expiração
	if data.ExpiresAt != nil && time.Now().After(*data.ExpiresAt) {
		return nil, contracts.ErrExpiredToken
	}

	// Verificar hash se configurado
	if m.config.HashKeys {
		if data.HashedKey != hashAPIKey(tokenString) {
			return nil, contracts.ErrInvalidToken
		}
	} else {
		if data.HashedKey != tokenString {
			return nil, contracts.ErrInvalidToken
		}
	}

	// Atualizar último uso
	now := time.Now()
	data.LastUsedAt = &now
	m.storage.Store(ctx, tokenString, data) // Ignorar erro de update

	// Criar claims
	claims := &contracts.Claims{
		Subject:  data.UserID,
		Issuer:   "api-key-manager",
		IssuedAt: data.CreatedAt,
		ID:       data.ID,
		Scopes:   data.Scopes,
		Metadata: data.Metadata,
	}

	if data.ExpiresAt != nil {
		claims.ExpiresAt = *data.ExpiresAt
	}

	return claims, nil
}

// ValidateRefreshToken API Keys não suportam refresh tokens
func (m *APIKeyManager) ValidateRefreshToken(ctx context.Context, tokenString string) (*contracts.Claims, error) {
	return nil, fmt.Errorf("API keys do not support refresh tokens")
}

// IntrospectToken retorna informações sobre a API Key
func (m *APIKeyManager) IntrospectToken(ctx context.Context, tokenString string) (*contracts.TokenInfo, error) {
	data, err := m.storage.Get(ctx, tokenString)
	if err != nil {
		return &contracts.TokenInfo{
			Type: contracts.TokenTypeAPIKey,
			Extra: map[string]interface{}{
				"error": err.Error(),
			},
		}, nil
	}

	extra := map[string]interface{}{
		"user_id": data.UserID,
		"name":    data.Name,
		"active":  data.Active,
	}

	if data.LastUsedAt != nil {
		extra["last_used"] = data.LastUsedAt.Format(time.RFC3339)
	}

	info := &contracts.TokenInfo{
		Type:     contracts.TokenTypeAPIKey,
		Active:   data.Active,
		Subject:  data.UserID,
		IssuedAt: &data.CreatedAt,
		Scopes:   data.Scopes,
		Extra:    extra,
	}

	if data.ExpiresAt != nil {
		info.ExpiresAt = data.ExpiresAt
	}

	return info, nil
}

// RevokeToken revoga uma API Key
func (m *APIKeyManager) RevokeToken(ctx context.Context, tokenString string) error {
	return m.storage.Delete(ctx, tokenString)
}

// RevokeAllTokens revoga todas as API Keys de um usuário
func (m *APIKeyManager) RevokeAllTokens(ctx context.Context, userID string) error {
	return m.storage.DeleteByUser(ctx, userID)
}

// RefreshToken API Keys não suportam refresh
func (m *APIKeyManager) RefreshToken(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error) {
	return "", "", fmt.Errorf("API keys do not support token refresh")
}

// GetTokenType retorna o tipo de token
func (m *APIKeyManager) GetTokenType() string {
	return "API-Key"
}

// ListAPIKeys lista todas as API Keys de um usuário
func (m *APIKeyManager) ListAPIKeys(ctx context.Context, userID string) ([]*contracts.APIKeyData, error) {
	return m.storage.List(ctx, userID)
}

// CreateNamedAPIKey cria uma API Key com nome específico
func (m *APIKeyManager) CreateNamedAPIKey(ctx context.Context, user *contracts.User, name string, options ...contracts.GenerateOption) (string, *contracts.APIKeyData, error) {
	key, err := m.GenerateToken(ctx, user, options...)
	if err != nil {
		return "", nil, err
	}

	// Recuperar dados para atualizar o nome
	data, err := m.storage.Get(ctx, key)
	if err != nil {
		return "", nil, fmt.Errorf("failed to retrieve created key: %w", err)
	}

	data.Name = name
	if err := m.storage.Store(ctx, key, data); err != nil {
		return "", nil, fmt.Errorf("failed to update key name: %w", err)
	}

	return key, data, nil
}

// hashAPIKey faz hash de uma API Key (implementação simples)
func hashAPIKey(key string) string {
	// Em produção, usar bcrypt ou similar
	// Para simplicidade, usando apenas um hash simples
	return fmt.Sprintf("hashed_%x", []byte(key))
}

// DefaultAPIKeyConfig retorna configuração padrão para API Keys
func DefaultAPIKeyConfig() *contracts.APIKeyConfig {
	return &contracts.APIKeyConfig{
		Prefix:        "ak_",
		Length:        32,
		ExpiryDefault: 365 * 24 * time.Hour, // 1 ano
		HashKeys:      true,
	}
}
