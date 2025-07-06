package storage_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hugoFelippe/go-authkit/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// MemoryStorage implementa um storage em memória para testes de integração
type MemoryStorage struct {
	tokens   map[string]*contracts.Claims
	sessions map[string]*contracts.Session
	apiKeys  map[string]*contracts.APIKey
	kvStore  map[string]interface{}
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		tokens:   make(map[string]*contracts.Claims),
		sessions: make(map[string]*contracts.Session),
		apiKeys:  make(map[string]*contracts.APIKey),
		kvStore:  make(map[string]interface{}),
	}
}

// Token storage
func (s *MemoryStorage) StoreToken(ctx context.Context, token string, claims *contracts.Claims, expiry time.Duration) error {
	s.tokens[token] = claims
	return nil
}

func (s *MemoryStorage) GetToken(ctx context.Context, token string) (*contracts.Claims, error) {
	claims, exists := s.tokens[token]
	if !exists {
		return nil, contracts.ErrTokenNotFound
	}
	return claims, nil
}

func (s *MemoryStorage) DeleteToken(ctx context.Context, token string) error {
	delete(s.tokens, token)
	return nil
}

func (s *MemoryStorage) DeleteAllTokens(ctx context.Context, userID string) error {
	for token, claims := range s.tokens {
		if claims.Subject == userID {
			delete(s.tokens, token)
		}
	}
	return nil
}

// Session storage
func (s *MemoryStorage) StoreSession(ctx context.Context, session *contracts.Session) error {
	s.sessions[session.ID] = session
	return nil
}

func (s *MemoryStorage) GetSession(ctx context.Context, sessionID string) (*contracts.Session, error) {
	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, contracts.ErrInvalidSession
	}
	return session, nil
}

func (s *MemoryStorage) DeleteSession(ctx context.Context, sessionID string) error {
	delete(s.sessions, sessionID)
	return nil
}

func (s *MemoryStorage) DeleteAllSessions(ctx context.Context, userID string) error {
	for sessionID, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, sessionID)
		}
	}
	return nil
}

// API Key storage
func (s *MemoryStorage) StoreAPIKey(ctx context.Context, apiKey *contracts.APIKey) error {
	s.apiKeys[apiKey.ID] = apiKey
	return nil
}

func (s *MemoryStorage) GetAPIKey(ctx context.Context, key string) (*contracts.APIKey, error) {
	for _, apiKey := range s.apiKeys {
		if apiKey.Key == key {
			return apiKey, nil
		}
	}
	return nil, contracts.ErrInvalidAPIKey
}

func (s *MemoryStorage) DeleteAPIKey(ctx context.Context, keyID string) error {
	delete(s.apiKeys, keyID)
	return nil
}

func (s *MemoryStorage) GetUserAPIKeys(ctx context.Context, userID string) ([]*contracts.APIKey, error) {
	var result []*contracts.APIKey
	for _, apiKey := range s.apiKeys {
		if apiKey.UserID == userID {
			result = append(result, apiKey)
		}
	}
	return result, nil
}

// General key-value storage
func (s *MemoryStorage) Set(ctx context.Context, key string, value interface{}, expiry time.Duration) error {
	s.kvStore[key] = value
	return nil
}

func (s *MemoryStorage) Get(ctx context.Context, key string) (interface{}, error) {
	value, exists := s.kvStore[key]
	if !exists {
		return nil, contracts.ErrTokenNotFound
	}
	return value, nil
}

func (s *MemoryStorage) Delete(ctx context.Context, key string) error {
	delete(s.kvStore, key)
	return nil
}

func (s *MemoryStorage) Exists(ctx context.Context, key string) (bool, error) {
	_, exists := s.kvStore[key]
	return exists, nil
}

// Health check
func (s *MemoryStorage) Ping(ctx context.Context) error {
	return nil
}

func (s *MemoryStorage) Close() error {
	return nil
}

// StorageIntegrationSuite testa a integração do sistema de storage
type StorageIntegrationSuite struct {
	suite.Suite
	ctx      context.Context
	storage  *MemoryStorage
	testUser *contracts.User
}

func (suite *StorageIntegrationSuite) SetupSuite() {
	suite.ctx = context.Background()

	// Criar usuário de teste
	suite.testUser = &contracts.User{
		ID:       "test-user-123",
		Username: "testuser",
		Email:    "test@example.com",
		Name:     "Test User",
		Active:   true,
	}
}

func (suite *StorageIntegrationSuite) SetupTest() {
	suite.storage = NewMemoryStorage()
}

func (suite *StorageIntegrationSuite) TearDownTest() {
	if suite.storage != nil {
		suite.storage.Close()
	}
}

func (suite *StorageIntegrationSuite) TestTokenStorage() {
	// 1. Criar claims de teste
	claims := &contracts.Claims{
		Subject:   suite.testUser.ID,
		Issuer:    "test-issuer",
		Email:     suite.testUser.Email,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		IssuedAt:  time.Now(),
	}

	token := "test-token-12345"

	// 2. Armazenar token
	err := suite.storage.StoreToken(suite.ctx, token, claims, 1*time.Hour)
	require.NoError(suite.T(), err)

	// 3. Recuperar token
	retrievedClaims, err := suite.storage.GetToken(suite.ctx, token)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), retrievedClaims)
	assert.Equal(suite.T(), claims.Subject, retrievedClaims.Subject)
	assert.Equal(suite.T(), claims.Email, retrievedClaims.Email)
	assert.Equal(suite.T(), claims.Issuer, retrievedClaims.Issuer)

	// 4. Deletar token
	err = suite.storage.DeleteToken(suite.ctx, token)
	require.NoError(suite.T(), err)

	// 5. Verificar que foi deletado
	_, err = suite.storage.GetToken(suite.ctx, token)
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), contracts.ErrTokenNotFound, err)
}

func (suite *StorageIntegrationSuite) TestTokenStorageMultipleUsers() {
	// Criar múltiplos usuários e tokens
	users := []*contracts.User{
		{ID: "user-1", Email: "user1@example.com"},
		{ID: "user-2", Email: "user2@example.com"},
		{ID: "user-3", Email: "user3@example.com"},
	}

	var tokens []string
	for i, user := range users {
		for j := 0; j < 3; j++ { // 3 tokens por usuário
			token := fmt.Sprintf("token-%d-%d", i+1, j+1)
			claims := &contracts.Claims{
				Subject: user.ID,
				Email:   user.Email,
				Issuer:  "test-issuer",
			}

			err := suite.storage.StoreToken(suite.ctx, token, claims, 1*time.Hour)
			require.NoError(suite.T(), err)
			tokens = append(tokens, token)
		}
	}

	// Verificar que todos os tokens foram armazenados
	for _, token := range tokens {
		claims, err := suite.storage.GetToken(suite.ctx, token)
		require.NoError(suite.T(), err)
		assert.NotEmpty(suite.T(), claims.Subject)
	}

	// Deletar todos os tokens do primeiro usuário
	err := suite.storage.DeleteAllTokens(suite.ctx, "user-1")
	require.NoError(suite.T(), err)

	// Verificar que apenas os tokens do primeiro usuário foram deletados
	for i, token := range tokens {
		claims, err := suite.storage.GetToken(suite.ctx, token)
		if i < 3 { // Primeiros 3 tokens são do user-1
			assert.Error(suite.T(), err)
		} else {
			require.NoError(suite.T(), err)
			assert.NotEqual(suite.T(), "user-1", claims.Subject)
		}
	}
}

func (suite *StorageIntegrationSuite) TestSessionStorage() {
	// 1. Criar sessão de teste
	session := &contracts.Session{
		ID:        "session-12345",
		UserID:    suite.testUser.ID,
		Token:     "session-token-123",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Active:    true,
		Metadata:  map[string]interface{}{"browser": "chrome", "ip": "192.168.1.1"},
	}

	// 2. Armazenar sessão
	err := suite.storage.StoreSession(suite.ctx, session)
	require.NoError(suite.T(), err)

	// 3. Recuperar sessão
	retrievedSession, err := suite.storage.GetSession(suite.ctx, session.ID)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), retrievedSession)
	assert.Equal(suite.T(), session.ID, retrievedSession.ID)
	assert.Equal(suite.T(), session.UserID, retrievedSession.UserID)
	assert.Equal(suite.T(), session.Token, retrievedSession.Token)
	assert.Equal(suite.T(), session.Active, retrievedSession.Active)
	assert.Equal(suite.T(), session.Metadata["browser"], retrievedSession.Metadata["browser"])

	// 4. Deletar sessão
	err = suite.storage.DeleteSession(suite.ctx, session.ID)
	require.NoError(suite.T(), err)

	// 5. Verificar que foi deletada
	_, err = suite.storage.GetSession(suite.ctx, session.ID)
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), contracts.ErrInvalidSession, err)
}

func (suite *StorageIntegrationSuite) TestSessionStorageMultipleUsers() {
	// Criar múltiplas sessões para múltiplos usuários
	users := []string{"user-1", "user-2", "user-3"}
	var sessions []*contracts.Session

	for i, userID := range users {
		for j := 0; j < 2; j++ { // 2 sessões por usuário
			session := &contracts.Session{
				ID:        fmt.Sprintf("session-%d-%d", i+1, j+1),
				UserID:    userID,
				Token:     fmt.Sprintf("token-%d-%d", i+1, j+1),
				ExpiresAt: time.Now().Add(24 * time.Hour),
				CreatedAt: time.Now(),
				Active:    true,
			}

			err := suite.storage.StoreSession(suite.ctx, session)
			require.NoError(suite.T(), err)
			sessions = append(sessions, session)
		}
	}

	// Verificar que todas as sessões foram armazenadas
	for _, session := range sessions {
		retrievedSession, err := suite.storage.GetSession(suite.ctx, session.ID)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), session.UserID, retrievedSession.UserID)
	}

	// Deletar todas as sessões do primeiro usuário
	err := suite.storage.DeleteAllSessions(suite.ctx, "user-1")
	require.NoError(suite.T(), err)

	// Verificar que apenas as sessões do primeiro usuário foram deletadas
	for i, session := range sessions {
		retrievedSession, err := suite.storage.GetSession(suite.ctx, session.ID)
		if i < 2 { // Primeiras 2 sessões são do user-1
			assert.Error(suite.T(), err)
		} else {
			require.NoError(suite.T(), err)
			assert.NotEqual(suite.T(), "user-1", retrievedSession.UserID)
		}
	}
}

func (suite *StorageIntegrationSuite) TestAPIKeyStorage() {
	// 1. Criar API Key de teste
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	apiKey := &contracts.APIKey{
		ID:          "api-key-123",
		Key:         "ak_test_key_12345",
		Name:        "Test API Key",
		Description: "API Key for testing",
		UserID:      suite.testUser.ID,
		Scopes:      []string{"read", "write"},
		Metadata:    map[string]interface{}{"app": "test-app"},
		ExpiresAt:   &expiresAt,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Active:      true,
	}

	// 2. Armazenar API Key
	err := suite.storage.StoreAPIKey(suite.ctx, apiKey)
	require.NoError(suite.T(), err)

	// 3. Recuperar API Key por chave
	retrievedAPIKey, err := suite.storage.GetAPIKey(suite.ctx, apiKey.Key)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), retrievedAPIKey)
	assert.Equal(suite.T(), apiKey.ID, retrievedAPIKey.ID)
	assert.Equal(suite.T(), apiKey.Key, retrievedAPIKey.Key)
	assert.Equal(suite.T(), apiKey.UserID, retrievedAPIKey.UserID)
	assert.Equal(suite.T(), apiKey.Scopes, retrievedAPIKey.Scopes)

	// 4. Listar API Keys do usuário
	userAPIKeys, err := suite.storage.GetUserAPIKeys(suite.ctx, suite.testUser.ID)
	require.NoError(suite.T(), err)
	assert.Len(suite.T(), userAPIKeys, 1)
	assert.Equal(suite.T(), apiKey.ID, userAPIKeys[0].ID)

	// 5. Deletar API Key
	err = suite.storage.DeleteAPIKey(suite.ctx, apiKey.ID)
	require.NoError(suite.T(), err)

	// 6. Verificar que foi deletada
	_, err = suite.storage.GetAPIKey(suite.ctx, apiKey.Key)
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), contracts.ErrInvalidAPIKey, err)
}

func (suite *StorageIntegrationSuite) TestKeyValueStorage() {
	// 1. Armazenar diferentes tipos de valores
	testCases := []struct {
		key   string
		value interface{}
	}{
		{"string-key", "test-value"},
		{"int-key", 42},
		{"bool-key", true},
		{"map-key", map[string]string{"nested": "value"}},
		{"slice-key", []string{"item1", "item2", "item3"}},
	}

	// 2. Armazenar todos os valores
	for _, tc := range testCases {
		err := suite.storage.Set(suite.ctx, tc.key, tc.value, 1*time.Hour)
		require.NoError(suite.T(), err)
	}

	// 3. Verificar que todos os valores existem
	for _, tc := range testCases {
		exists, err := suite.storage.Exists(suite.ctx, tc.key)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), exists)
	}

	// 4. Recuperar e verificar valores
	for _, tc := range testCases {
		value, err := suite.storage.Get(suite.ctx, tc.key)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), tc.value, value)
	}

	// 5. Deletar alguns valores
	keysToDelete := []string{"string-key", "bool-key"}
	for _, key := range keysToDelete {
		err := suite.storage.Delete(suite.ctx, key)
		require.NoError(suite.T(), err)
	}

	// 6. Verificar que foram deletados
	for _, key := range keysToDelete {
		exists, err := suite.storage.Exists(suite.ctx, key)
		require.NoError(suite.T(), err)
		assert.False(suite.T(), exists)

		_, err = suite.storage.Get(suite.ctx, key)
		assert.Error(suite.T(), err)
	}

	// 7. Verificar que os outros ainda existem
	remainingKeys := []string{"int-key", "map-key", "slice-key"}
	for _, key := range remainingKeys {
		exists, err := suite.storage.Exists(suite.ctx, key)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), exists)
	}
}

func (suite *StorageIntegrationSuite) TestHealthCheck() {
	// Testar ping do storage
	err := suite.storage.Ping(suite.ctx)
	assert.NoError(suite.T(), err)
}

func (suite *StorageIntegrationSuite) TestStorageErrors() {
	// Testar comportamento com chaves inexistentes

	// Token inexistente
	_, err := suite.storage.GetToken(suite.ctx, "nonexistent-token")
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), contracts.ErrTokenNotFound, err)

	// Sessão inexistente
	_, err = suite.storage.GetSession(suite.ctx, "nonexistent-session")
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), contracts.ErrInvalidSession, err)

	// API Key inexistente
	_, err = suite.storage.GetAPIKey(suite.ctx, "nonexistent-key")
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), contracts.ErrInvalidAPIKey, err)

	// Valor inexistente no KV store
	_, err = suite.storage.Get(suite.ctx, "nonexistent-kv-key")
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), contracts.ErrTokenNotFound, err)
}

func TestStorageIntegrationSuite(t *testing.T) {
	suite.Run(t, new(StorageIntegrationSuite))
}
