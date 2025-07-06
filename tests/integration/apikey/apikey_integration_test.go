package apikey_test

import (
	"context"
	"testing"
	"time"

	"github.com/hugoFelippe/go-authkit/contracts"
	"github.com/hugoFelippe/go-authkit/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// MemoryAPIKeyStorage implementa APIKeyStorage em memória para testes
type MemoryAPIKeyStorage struct {
	data map[string]*contracts.APIKeyData
}

func NewMemoryAPIKeyStorage() *MemoryAPIKeyStorage {
	return &MemoryAPIKeyStorage{
		data: make(map[string]*contracts.APIKeyData),
	}
}

func (s *MemoryAPIKeyStorage) Store(ctx context.Context, key string, data *contracts.APIKeyData) error {
	s.data[key] = data
	return nil
}

func (s *MemoryAPIKeyStorage) Get(ctx context.Context, key string) (*contracts.APIKeyData, error) {
	data, exists := s.data[key]
	if !exists {
		return nil, contracts.ErrInvalidAPIKey
	}
	return data, nil
}

func (s *MemoryAPIKeyStorage) Delete(ctx context.Context, key string) error {
	delete(s.data, key)
	return nil
}

func (s *MemoryAPIKeyStorage) List(ctx context.Context, userID string) ([]*contracts.APIKeyData, error) {
	var result []*contracts.APIKeyData
	for _, data := range s.data {
		if data.UserID == userID {
			result = append(result, data)
		}
	}
	return result, nil
}

func (s *MemoryAPIKeyStorage) DeleteByUser(ctx context.Context, userID string) error {
	for key, data := range s.data {
		if data.UserID == userID {
			delete(s.data, key)
		}
	}
	return nil
}

// APIKeyIntegrationSuite testa a integração completa do API Key Manager
type APIKeyIntegrationSuite struct {
	suite.Suite
	ctx        context.Context
	apiManager *token.APIKeyManager
	storage    *MemoryAPIKeyStorage
	testUser   *contracts.User
}

func (suite *APIKeyIntegrationSuite) SetupSuite() {
	suite.ctx = context.Background()

	// Criar usuário de teste
	suite.testUser = &contracts.User{
		ID:          "test-user-123",
		Username:    "testuser",
		Email:       "test@example.com",
		Name:        "Test User",
		Roles:       []string{"user"},
		Permissions: []string{"read", "write"},
		Active:      true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

func (suite *APIKeyIntegrationSuite) SetupTest() {
	// Configurar API Key Manager para cada teste
	suite.storage = NewMemoryAPIKeyStorage()

	config := &contracts.APIKeyConfig{
		Prefix:        "ak_",
		Length:        32,
		ExpiryDefault: 30 * 24 * time.Hour, // 30 dias
		HashKeys:      false,               // Para facilitar os testes
	}

	suite.apiManager = token.NewAPIKeyManager(config, suite.storage)
	require.NotNil(suite.T(), suite.apiManager)
}

func (suite *APIKeyIntegrationSuite) TestAPIKeyFullPipeline() {
	// 1. Gerar API Key
	apiKey, err := suite.apiManager.GenerateToken(suite.ctx, suite.testUser)
	require.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), apiKey)
	assert.Contains(suite.T(), apiKey, "ak_")

	// 2. Validar API Key gerada
	validatedClaims, err := suite.apiManager.ValidateToken(suite.ctx, apiKey)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), validatedClaims)

	// 3. Verificar claims
	assert.Equal(suite.T(), suite.testUser.ID, validatedClaims.Subject)
	// Note: TokenType não está disponível nas Claims, verificamos através de outras formas
}

func (suite *APIKeyIntegrationSuite) TestAPIKeyWithOptions() {
	// Gerar API Key com opções customizadas
	expiry := 7 * 24 * time.Hour // 7 dias
	scopes := []string{"read:users", "write:posts"}

	opts := []contracts.GenerateOption{
		token.WithExpiry(expiry),
		token.WithScopes(scopes...),
		token.WithCustomClaims(map[string]interface{}{
			"app_name": "test-app",
			"version":  "1.0.0",
		}),
	}

	apiKey, err := suite.apiManager.GenerateToken(suite.ctx, suite.testUser, opts...)
	require.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), apiKey)

	// Validar API Key com opções
	claims, err := suite.apiManager.ValidateToken(suite.ctx, apiKey)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), scopes, claims.Scopes)
	assert.NotNil(suite.T(), claims.Metadata)
	assert.Equal(suite.T(), "test-app", claims.Metadata["app_name"])
}

func (suite *APIKeyIntegrationSuite) TestAPIKeyRevokeToken() {
	// Gerar API Key
	apiKey, err := suite.apiManager.GenerateToken(suite.ctx, suite.testUser)
	require.NoError(suite.T(), err)

	// Validar que funciona antes da revogação
	claims, err := suite.apiManager.ValidateToken(suite.ctx, apiKey)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), suite.testUser.ID, claims.Subject)

	// Revogar API Key
	err = suite.apiManager.RevokeToken(suite.ctx, apiKey)
	require.NoError(suite.T(), err)

	// Tentar validar API Key revogada
	claims, err = suite.apiManager.ValidateToken(suite.ctx, apiKey)
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), claims)
}

func (suite *APIKeyIntegrationSuite) TestAPIKeyRevokeAllTokens() {
	// Gerar múltiplas API Keys para o mesmo usuário
	var apiKeys []string
	for i := 0; i < 3; i++ {
		apiKey, err := suite.apiManager.GenerateToken(suite.ctx, suite.testUser)
		require.NoError(suite.T(), err)
		apiKeys = append(apiKeys, apiKey)
	}

	// Validar que todas funcionam
	for _, key := range apiKeys {
		claims, err := suite.apiManager.ValidateToken(suite.ctx, key)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), suite.testUser.ID, claims.Subject)
	}

	// Revogar todas as API Keys do usuário
	err := suite.apiManager.RevokeAllTokens(suite.ctx, suite.testUser.ID)
	require.NoError(suite.T(), err)

	// Verificar que todas foram revogadas
	for _, key := range apiKeys {
		claims, err := suite.apiManager.ValidateToken(suite.ctx, key)
		assert.Error(suite.T(), err)
		assert.Nil(suite.T(), claims)
	}
}

func (suite *APIKeyIntegrationSuite) TestAPIKeyIntrospection() {
	// Gerar API Key
	apiKey, err := suite.apiManager.GenerateToken(suite.ctx, suite.testUser)
	require.NoError(suite.T(), err)

	// Fazer introspecção
	tokenInfo, err := suite.apiManager.IntrospectToken(suite.ctx, apiKey)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), tokenInfo)

	// Verificar informações
	assert.True(suite.T(), tokenInfo.Active)
	assert.Equal(suite.T(), contracts.TokenTypeAPIKey, tokenInfo.Type)
	assert.Equal(suite.T(), suite.testUser.ID, tokenInfo.Subject)
	assert.NotNil(suite.T(), tokenInfo.ExpiresAt)
	assert.NotNil(suite.T(), tokenInfo.IssuedAt)
}

func (suite *APIKeyIntegrationSuite) TestAPIKeyInvalidKeys() {
	testCases := []struct {
		name   string
		apiKey string
	}{
		{
			name:   "empty key",
			apiKey: "",
		},
		{
			name:   "invalid prefix",
			apiKey: "invalid_key_123",
		},
		{
			name:   "nonexistent key",
			apiKey: "ak_nonexistent1234567890abcdef",
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			claims, err := suite.apiManager.ValidateToken(suite.ctx, tc.apiKey)
			assert.Error(t, err)
			assert.Nil(t, claims)
		})
	}
}

func (suite *APIKeyIntegrationSuite) TestAPIKeyExpiration() {
	// Gerar API Key com expiração muito curta
	shortExpiry := 100 * time.Millisecond
	opts := []contracts.GenerateOption{
		token.WithExpiry(shortExpiry),
	}

	apiKey, err := suite.apiManager.GenerateToken(suite.ctx, suite.testUser, opts...)
	require.NoError(suite.T(), err)

	// Validar que funciona imediatamente
	claims, err := suite.apiManager.ValidateToken(suite.ctx, apiKey)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), suite.testUser.ID, claims.Subject)

	// Aguardar expiração
	time.Sleep(200 * time.Millisecond)

	// Tentar validar API Key expirada
	claims, err = suite.apiManager.ValidateToken(suite.ctx, apiKey)
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), claims)
	assert.Contains(suite.T(), err.Error(), "expired")
}

func (suite *APIKeyIntegrationSuite) TestAPIKeyGetTokenType() {
	tokenType := suite.apiManager.GetTokenType()
	assert.Equal(suite.T(), "API-Key", tokenType)
}

func (suite *APIKeyIntegrationSuite) TestAPIKeyStorageOperations() {
	// Testar operações diretas no storage

	// 1. Armazenar dados
	keyData := &contracts.APIKeyData{
		ID:        "test-key-id",
		UserID:    suite.testUser.ID,
		Name:      "Test Key",
		HashedKey: "hashed-key-value",
		Prefix:    "ak_",
		Scopes:    []string{"read", "write"},
		ExpiresAt: nil, // Sem expiração
		CreatedAt: time.Now(),
		Active:    true,
		Metadata:  map[string]interface{}{"test": "value"},
	}

	err := suite.storage.Store(suite.ctx, "test-key", keyData)
	require.NoError(suite.T(), err)

	// 2. Recuperar dados
	retrieved, err := suite.storage.Get(suite.ctx, "test-key")
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), keyData.ID, retrieved.ID)
	assert.Equal(suite.T(), keyData.UserID, retrieved.UserID)
	assert.Equal(suite.T(), keyData.Scopes, retrieved.Scopes)

	// 3. Listar chaves do usuário
	userKeys, err := suite.storage.List(suite.ctx, suite.testUser.ID)
	require.NoError(suite.T(), err)
	assert.Len(suite.T(), userKeys, 1)
	assert.Equal(suite.T(), keyData.ID, userKeys[0].ID)

	// 4. Deletar chave específica
	err = suite.storage.Delete(suite.ctx, "test-key")
	require.NoError(suite.T(), err)

	// 5. Verificar que foi deletada
	_, err = suite.storage.Get(suite.ctx, "test-key")
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), contracts.ErrInvalidAPIKey, err)
}

func (suite *APIKeyIntegrationSuite) TestAPIKeyMultipleUsers() {
	// Criar segundo usuário
	secondUser := &contracts.User{
		ID:       "user-2",
		Username: "user2",
		Email:    "user2@example.com",
		Name:     "User Two",
		Active:   true,
	}

	// Gerar API Keys para ambos os usuários
	key1, err := suite.apiManager.GenerateToken(suite.ctx, suite.testUser)
	require.NoError(suite.T(), err)

	key2, err := suite.apiManager.GenerateToken(suite.ctx, secondUser)
	require.NoError(suite.T(), err)

	// Validar que cada chave pertence ao usuário correto
	claims1, err := suite.apiManager.ValidateToken(suite.ctx, key1)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), suite.testUser.ID, claims1.Subject)

	claims2, err := suite.apiManager.ValidateToken(suite.ctx, key2)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), secondUser.ID, claims2.Subject)

	// Revogar tokens do primeiro usuário
	err = suite.apiManager.RevokeAllTokens(suite.ctx, suite.testUser.ID)
	require.NoError(suite.T(), err)

	// Verificar que apenas o primeiro usuário teve tokens revogados
	_, err = suite.apiManager.ValidateToken(suite.ctx, key1)
	assert.Error(suite.T(), err)

	claims2, err = suite.apiManager.ValidateToken(suite.ctx, key2)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), secondUser.ID, claims2.Subject)
}

func TestAPIKeyIntegrationSuite(t *testing.T) {
	suite.Run(t, new(APIKeyIntegrationSuite))
}
