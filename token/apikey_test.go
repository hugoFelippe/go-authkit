package token

import (
	"context"
	"testing"
	"time"

	"github.com/hugoFelippe/go-authkit/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockAPIKeyStorage implementa a interface APIKeyStorage para testes
type MockAPIKeyStorage struct {
	data             map[string]*contracts.APIKeyData
	storeFunc        func(ctx context.Context, key string, data *contracts.APIKeyData) error
	getFunc          func(ctx context.Context, key string) (*contracts.APIKeyData, error)
	deleteFunc       func(ctx context.Context, key string) error
	listFunc         func(ctx context.Context, userID string) ([]*contracts.APIKeyData, error)
	deleteByUserFunc func(ctx context.Context, userID string) error
}

func NewMockAPIKeyStorage() *MockAPIKeyStorage {
	return &MockAPIKeyStorage{
		data: make(map[string]*contracts.APIKeyData),
	}
}

func (m *MockAPIKeyStorage) Store(ctx context.Context, key string, data *contracts.APIKeyData) error {
	if m.storeFunc != nil {
		return m.storeFunc(ctx, key, data)
	}
	m.data[key] = data
	return nil
}

func (m *MockAPIKeyStorage) Get(ctx context.Context, key string) (*contracts.APIKeyData, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, key)
	}
	data, exists := m.data[key]
	if !exists {
		return nil, contracts.ErrTokenNotFound
	}
	return data, nil
}

func (m *MockAPIKeyStorage) Delete(ctx context.Context, key string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, key)
	}
	delete(m.data, key)
	return nil
}

func (m *MockAPIKeyStorage) List(ctx context.Context, userID string) ([]*contracts.APIKeyData, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, userID)
	}

	var result []*contracts.APIKeyData
	for _, data := range m.data {
		if data.UserID == userID {
			result = append(result, data)
		}
	}
	return result, nil
}

func (m *MockAPIKeyStorage) DeleteByUser(ctx context.Context, userID string) error {
	if m.deleteByUserFunc != nil {
		return m.deleteByUserFunc(ctx, userID)
	}

	for key, data := range m.data {
		if data.UserID == userID {
			delete(m.data, key)
		}
	}
	return nil
}

func TestAPIKeyConfig(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		storage := NewMockAPIKeyStorage()
		manager := NewAPIKeyManager(nil, storage)
		assert.NotNil(t, manager, "Expected manager, got nil")
		// NewAPIKeyManager applies default config when nil is passed
	})

	t.Run("nil storage", func(t *testing.T) {
		config := &contracts.APIKeyConfig{
			Prefix:        "ak_",
			Length:        32,
			ExpiryDefault: 24 * time.Hour,
			HashKeys:      true,
		}
		manager := NewAPIKeyManager(config, nil)
		assert.NotNil(t, manager, "Expected manager, got nil")
		// NewAPIKeyManager doesn't validate storage
	})

	t.Run("valid config", func(t *testing.T) {
		config := &contracts.APIKeyConfig{
			Prefix:        "ak_",
			Length:        32,
			ExpiryDefault: 24 * time.Hour,
			HashKeys:      true,
		}
		storage := NewMockAPIKeyStorage()

		manager := NewAPIKeyManager(config, storage)
		assert.NotNil(t, manager, "Expected manager, got nil")
	})

	t.Run("default values", func(t *testing.T) {
		config := &contracts.APIKeyConfig{}
		storage := NewMockAPIKeyStorage()

		manager := NewAPIKeyManager(config, storage)
		assert.NotNil(t, manager, "Expected manager, got nil")

		// Test that defaults are applied (config is replaced with defaults when nil/empty)
		// Since NewAPIKeyManager replaces nil config with defaults, we can't test the original config
		// Instead, let's test that a nil config gets replaced with defaults
		manager2 := NewAPIKeyManager(nil, storage)
		assert.NotZero(t, manager2.config.Length, "Expected default length to be set")
		assert.NotEmpty(t, manager2.config.Prefix, "Expected default prefix to be set")
	})
}

func TestAPIKeyManagerGenerateToken(t *testing.T) {
	config := &contracts.APIKeyConfig{
		Prefix:        "ak_",
		Length:        32,
		ExpiryDefault: 24 * time.Hour,
		HashKeys:      true,
	}
	storage := NewMockAPIKeyStorage()

	manager := NewAPIKeyManager(config, storage)
	if manager == nil {
		t.Fatalf("Failed to create API key manager")
	}

	ctx := context.Background()
	user := &contracts.User{
		ID:       "test-user-id",
		Username: "testuser",
		Email:    "test@example.com",
		Name:     "Test User",
	}

	t.Run("generate API key", func(t *testing.T) {
		apiKey, err := manager.GenerateToken(ctx, user)
		require.NoError(t, err)
		assert.NotEmpty(t, apiKey)
		assert.Greater(t, len(apiKey), len(config.Prefix))
	})

	t.Run("generate refresh token - not supported", func(t *testing.T) {
		refreshToken, err := manager.GenerateRefreshToken(ctx, user)
		assert.Error(t, err, "Expected error for refresh token generation")
		assert.Empty(t, refreshToken)
	})
}

func TestAPIKeyManagerValidateToken(t *testing.T) {
	config := &contracts.APIKeyConfig{
		Prefix:        "ak_",
		Length:        32,
		ExpiryDefault: 24 * time.Hour,
		HashKeys:      true,
	}
	storage := NewMockAPIKeyStorage()

	manager := NewAPIKeyManager(config, storage)
	if manager == nil {
		t.Fatalf("Failed to create API key manager")
	}

	ctx := context.Background()
	user := &contracts.User{
		ID:       "test-user-id",
		Username: "testuser",
		Email:    "test@example.com",
		Name:     "Test User",
	}

	t.Run("validate valid API key", func(t *testing.T) {
		// Generate an API key first
		apiKey, err := manager.GenerateToken(ctx, user)
		if err != nil {
			t.Fatalf("Failed to generate API key: %v", err)
		}

		// Validate the API key
		claims, err := manager.ValidateToken(ctx, apiKey)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if claims == nil {
			t.Error("Expected claims, got nil")
		} else if claims.Subject != user.ID {
			t.Errorf("Expected subject %s, got %s", user.ID, claims.Subject)
		}
	})

	t.Run("validate invalid API key", func(t *testing.T) {
		claims, err := manager.ValidateToken(ctx, "invalid-api-key")
		if err == nil {
			t.Error("Expected error for invalid API key")
		}
		if claims != nil {
			t.Errorf("Expected nil claims, got %v", claims)
		}
	})

	t.Run("validate empty API key", func(t *testing.T) {
		claims, err := manager.ValidateToken(ctx, "")
		if err == nil {
			t.Error("Expected error for empty API key")
		}
		if claims != nil {
			t.Errorf("Expected nil claims, got %v", claims)
		}
	})

	t.Run("validate refresh token - not supported", func(t *testing.T) {
		claims, err := manager.ValidateRefreshToken(ctx, "any-token")
		if err == nil {
			t.Error("Expected error for refresh token validation")
		}
		if claims != nil {
			t.Errorf("Expected nil claims, got %v", claims)
		}
	})
}

func TestAPIKeyManagerOperations(t *testing.T) {
	config := &contracts.APIKeyConfig{
		Prefix:        "ak_",
		Length:        32,
		ExpiryDefault: 24 * time.Hour,
		HashKeys:      true,
	}
	storage := NewMockAPIKeyStorage()

	manager := NewAPIKeyManager(config, storage)
	if manager == nil {
		t.Fatalf("Failed to create API key manager")
	}

	ctx := context.Background()
	user := &contracts.User{
		ID:       "test-user-id",
		Username: "testuser",
		Email:    "test@example.com",
	}

	t.Run("introspect API key", func(t *testing.T) {
		// Generate an API key first
		apiKey, err := manager.GenerateToken(ctx, user)
		if err != nil {
			t.Fatalf("Failed to generate API key: %v", err)
		}

		// Introspect the API key
		tokenInfo, err := manager.IntrospectToken(ctx, apiKey)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if tokenInfo == nil {
			t.Fatal("Expected token info, got nil")
		}
		// Check if the token is active by looking at the extra field
		if active, exists := tokenInfo.Extra["active"]; !exists || !active.(bool) {
			t.Error("Expected token to be active")
		}
	})

	t.Run("introspect invalid API key", func(t *testing.T) {
		tokenInfo, err := manager.IntrospectToken(ctx, "invalid-api-key")
		if err != nil {
			t.Errorf("Expected no error (introspect returns inactive info), got %v", err)
		}
		if tokenInfo == nil {
			t.Error("Expected token info (with error), got nil")
		}

		// Check that there's an error in the extra field indicating the token was not found
		if tokenInfo == nil {
			t.Error("Expected token info (with error), got nil")
		} else if _, exists := tokenInfo.Extra["error"]; !exists {
			t.Error("Expected error in token info extra field for invalid token")
		}
	})

	t.Run("revoke API key", func(t *testing.T) {
		// Generate an API key first
		apiKey, err := manager.GenerateToken(ctx, user)
		if err != nil {
			t.Fatalf("Failed to generate API key: %v", err)
		}

		// Revoke the API key
		err = manager.RevokeToken(ctx, apiKey)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		// Try to validate the revoked key
		claims, err := manager.ValidateToken(ctx, apiKey)
		if err == nil {
			t.Error("Expected error for revoked API key")
		}
		if claims != nil {
			t.Errorf("Expected nil claims for revoked key, got %v", claims)
		}
	})

	t.Run("revoke all tokens", func(t *testing.T) {
		// Generate multiple API keys
		apiKey1, err := manager.GenerateToken(ctx, user)
		if err != nil {
			t.Fatalf("Failed to generate API key 1: %v", err)
		}

		apiKey2, err := manager.GenerateToken(ctx, user)
		if err != nil {
			t.Fatalf("Failed to generate API key 2: %v", err)
		}

		// Revoke all tokens for the user
		err = manager.RevokeAllTokens(ctx, user.ID)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		// Try to validate the revoked keys
		claims1, err1 := manager.ValidateToken(ctx, apiKey1)
		claims2, err2 := manager.ValidateToken(ctx, apiKey2)

		if err1 == nil || err2 == nil {
			t.Error("Expected errors for revoked API keys")
		}
		if claims1 != nil || claims2 != nil {
			t.Error("Expected nil claims for revoked keys")
		}
	})

	t.Run("refresh token - not supported", func(t *testing.T) {
		accessToken, newRefreshToken, err := manager.RefreshToken(ctx, "any-refresh-token")
		if err == nil {
			t.Error("Expected error for refresh token operation")
		}
		if accessToken != "" || newRefreshToken != "" {
			t.Error("Expected empty tokens for unsupported operation")
		}
	})
}

func TestAPIKeyData(t *testing.T) {
	t.Run("create API key data", func(t *testing.T) {
		now := time.Now()
		expiresAt := now.Add(24 * time.Hour)

		data := &contracts.APIKeyData{
			ID:         "key-id",
			UserID:     "user-id",
			Name:       "Test API Key",
			HashedKey:  "hashed-key",
			Prefix:     "ak_",
			Scopes:     []string{"read", "write"},
			ExpiresAt:  &expiresAt,
			CreatedAt:  now,
			LastUsedAt: nil,
			Active:     true,
			Metadata: map[string]interface{}{
				"purpose": "testing",
			},
		}

		if data.ID != "key-id" {
			t.Errorf("Expected ID 'key-id', got %s", data.ID)
		}
		if data.UserID != "user-id" {
			t.Errorf("Expected UserID 'user-id', got %s", data.UserID)
		}
		if !data.Active {
			t.Error("Expected Active to be true")
		}
		if len(data.Scopes) != 2 {
			t.Errorf("Expected 2 scopes, got %d", len(data.Scopes))
		}
		if data.Metadata["purpose"] != "testing" {
			t.Errorf("Expected metadata purpose 'testing', got %v", data.Metadata["purpose"])
		}
	})
}

func TestMockAPIKeyStorage(t *testing.T) {
	ctx := context.Background()
	storage := NewMockAPIKeyStorage()

	data := &contracts.APIKeyData{
		ID:        "test-key-id",
		UserID:    "test-user-id",
		Name:      "Test Key",
		HashedKey: "hashed-key",
		Active:    true,
		CreatedAt: time.Now(),
	}

	t.Run("store and get", func(t *testing.T) {
		err := storage.Store(ctx, "test-key", data)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		retrieved, err := storage.Get(ctx, "test-key")
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if retrieved == nil {
			t.Error("Expected data, got nil")
		} else if retrieved.ID != data.ID {
			t.Errorf("Expected ID %s, got %s", data.ID, retrieved.ID)
		}
	})

	t.Run("get non-existent key", func(t *testing.T) {
		retrieved, err := storage.Get(ctx, "non-existent")
		if err == nil {
			t.Error("Expected error for non-existent key")
		}
		if retrieved != nil {
			t.Error("Expected nil data for non-existent key")
		}
	})

	t.Run("list by user", func(t *testing.T) {
		// Store another key for the same user
		data2 := &contracts.APIKeyData{
			ID:        "test-key-id-2",
			UserID:    "test-user-id",
			Name:      "Test Key 2",
			HashedKey: "hashed-key-2",
			Active:    true,
			CreatedAt: time.Now(),
		}
		storage.Store(ctx, "test-key-2", data2)

		keys, err := storage.List(ctx, "test-user-id")
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if len(keys) < 2 {
			t.Errorf("Expected at least 2 keys, got %d", len(keys))
		}
	})

	t.Run("delete key", func(t *testing.T) {
		err := storage.Delete(ctx, "test-key")
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		_, err = storage.Get(ctx, "test-key")
		if err == nil {
			t.Error("Expected error for deleted key")
		}
	})

	t.Run("delete by user", func(t *testing.T) {
		err := storage.DeleteByUser(ctx, "test-user-id")
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		keys, err := storage.List(ctx, "test-user-id")
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("Expected 0 keys after deletion, got %d", len(keys))
		}
	})
}
