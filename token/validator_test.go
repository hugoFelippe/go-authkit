package token

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hugoFelippe/go-authkit/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockValidator implementa a interface Validator para testes
type MockValidator struct {
	validateTokenFunc func(ctx context.Context, tokenString string) (*contracts.Claims, error)
	getTokenTypeFunc  func() string
}

func (m *MockValidator) ValidateToken(ctx context.Context, tokenString string) (*contracts.Claims, error) {
	if m.validateTokenFunc != nil {
		return m.validateTokenFunc(ctx, tokenString)
	}
	return &contracts.Claims{Subject: "test-user"}, nil
}

func (m *MockValidator) GetTokenType() string {
	if m.getTokenTypeFunc != nil {
		return m.getTokenTypeFunc()
	}
	return "mock"
}

// MockValidationCache implementa a interface ValidationCache para testes
type MockValidationCache struct {
	data map[string]*contracts.Claims
}

func NewMockValidationCache() *MockValidationCache {
	return &MockValidationCache{
		data: make(map[string]*contracts.Claims),
	}
}

func (m *MockValidationCache) Get(ctx context.Context, key string) (*contracts.Claims, bool) {
	claims, exists := m.data[key]
	return claims, exists
}

func (m *MockValidationCache) Set(ctx context.Context, key string, claims *contracts.Claims, ttl time.Duration) {
	m.data[key] = claims
}

func (m *MockValidationCache) Delete(ctx context.Context, key string) {
	delete(m.data, key)
}

func TestValidatorChain(t *testing.T) {
	ctx := context.Background()

	t.Run("empty chain", func(t *testing.T) {
		chain := NewValidatorChain()

		claims, err := chain.ValidateToken(ctx, "test-token")
		assert.Equal(t, contracts.ErrInvalidToken, err)
		assert.Nil(t, claims)

		tokenType := chain.GetTokenType()
		assert.Equal(t, "unknown", tokenType)
	})

	t.Run("single validator success", func(t *testing.T) {
		validator := &MockValidator{
			validateTokenFunc: func(ctx context.Context, tokenString string) (*contracts.Claims, error) {
				return &contracts.Claims{Subject: "user1"}, nil
			},
			getTokenTypeFunc: func() string { return "jwt" },
		}

		chain := NewValidatorChain(validator)

		claims, err := chain.ValidateToken(ctx, "valid-token")
		require.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, "user1", claims.Subject)

		tokenType := chain.GetTokenType()
		assert.Equal(t, "multi", tokenType)
	})

	t.Run("multiple validators - first succeeds", func(t *testing.T) {
		validator1 := &MockValidator{
			validateTokenFunc: func(ctx context.Context, tokenString string) (*contracts.Claims, error) {
				return &contracts.Claims{Subject: "user1"}, nil
			},
		}
		validator2 := &MockValidator{
			validateTokenFunc: func(ctx context.Context, tokenString string) (*contracts.Claims, error) {
				return nil, errors.New("should not be called")
			},
		}

		chain := NewValidatorChain(validator1, validator2)

		claims, err := chain.ValidateToken(ctx, "valid-token")
		require.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, "user1", claims.Subject)
	})

	t.Run("multiple validators - second succeeds", func(t *testing.T) {
		validator1 := &MockValidator{
			validateTokenFunc: func(ctx context.Context, tokenString string) (*contracts.Claims, error) {
				return nil, errors.New("first validator failed")
			},
		}
		validator2 := &MockValidator{
			validateTokenFunc: func(ctx context.Context, tokenString string) (*contracts.Claims, error) {
				return &contracts.Claims{Subject: "user2"}, nil
			},
		}

		chain := NewValidatorChain(validator1, validator2)

		claims, err := chain.ValidateToken(ctx, "valid-token")
		require.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, "user2", claims.Subject)
	})

	t.Run("all validators fail", func(t *testing.T) {
		validator1 := &MockValidator{
			validateTokenFunc: func(ctx context.Context, tokenString string) (*contracts.Claims, error) {
				return nil, errors.New("first validator failed")
			},
		}
		validator2 := &MockValidator{
			validateTokenFunc: func(ctx context.Context, tokenString string) (*contracts.Claims, error) {
				return nil, errors.New("second validator failed")
			},
		}

		chain := NewValidatorChain(validator1, validator2)

		claims, err := chain.ValidateToken(ctx, "invalid-token")
		assert.Error(t, err)
		assert.Nil(t, claims)
	})

	t.Run("add validator", func(t *testing.T) {
		chain := NewValidatorChain()
		validator := &MockValidator{}

		chain.AddValidator(validator)

		assert.Len(t, chain.validators, 1)
	})
}

func TestContextValidator(t *testing.T) {
	ctx := context.Background()

	t.Run("successful validation with context check", func(t *testing.T) {
		baseValidator := &MockValidator{
			validateTokenFunc: func(ctx context.Context, tokenString string) (*contracts.Claims, error) {
				return &contracts.Claims{Subject: "user1"}, nil
			},
			getTokenTypeFunc: func() string { return "jwt" },
		}

		contextCheck := func(ctx context.Context, claims *contracts.Claims) error {
			if claims.Subject == "user1" {
				return nil
			}
			return errors.New("context check failed")
		}

		validator := NewContextValidator(baseValidator, contextCheck)

		claims, err := validator.ValidateToken(ctx, "valid-token")
		require.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, "user1", claims.Subject)

		tokenType := validator.GetTokenType()
		assert.Equal(t, "jwt", tokenType)
	})

	t.Run("base validator fails", func(t *testing.T) {
		baseValidator := &MockValidator{
			validateTokenFunc: func(ctx context.Context, tokenString string) (*contracts.Claims, error) {
				return nil, errors.New("base validation failed")
			},
		}

		contextCheck := func(ctx context.Context, claims *contracts.Claims) error {
			return nil
		}

		validator := NewContextValidator(baseValidator, contextCheck)

		claims, err := validator.ValidateToken(ctx, "invalid-token")
		assert.Error(t, err)
		assert.Nil(t, claims)
	})

	t.Run("context check fails", func(t *testing.T) {
		baseValidator := &MockValidator{
			validateTokenFunc: func(ctx context.Context, tokenString string) (*contracts.Claims, error) {
				return &contracts.Claims{Subject: "user1"}, nil
			},
		}

		contextCheck := func(ctx context.Context, claims *contracts.Claims) error {
			return errors.New("context check failed")
		}

		validator := NewContextValidator(baseValidator, contextCheck)

		claims, err := validator.ValidateToken(ctx, "valid-token")
		assert.Error(t, err)
		assert.Nil(t, claims)
	})

	t.Run("nil context check", func(t *testing.T) {
		baseValidator := &MockValidator{
			validateTokenFunc: func(ctx context.Context, tokenString string) (*contracts.Claims, error) {
				return &contracts.Claims{Subject: "user1"}, nil
			},
		}

		validator := NewContextValidator(baseValidator, nil)

		claims, err := validator.ValidateToken(ctx, "valid-token")
		require.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, "user1", claims.Subject)
	})
}

func TestCachingValidator(t *testing.T) {
	ctx := context.Background()

	t.Run("cache miss then hit", func(t *testing.T) {
		callCount := 0
		baseValidator := &MockValidator{
			validateTokenFunc: func(ctx context.Context, tokenString string) (*contracts.Claims, error) {
				callCount++
				return &contracts.Claims{
					Subject:   "user1",
					ExpiresAt: time.Now().Add(time.Hour),
				}, nil
			},
			getTokenTypeFunc: func() string { return "jwt" },
		}

		cache := NewMockValidationCache()
		validator := NewCachingValidator(baseValidator, cache)

		// First call - cache miss
		claims1, err := validator.ValidateToken(ctx, "test-token")
		require.NoError(t, err)
		require.NotNil(t, claims1)
		assert.Equal(t, "user1", claims1.Subject)
		assert.Equal(t, 1, callCount)

		// Second call - cache hit
		claims2, err := validator.ValidateToken(ctx, "test-token")
		require.NoError(t, err)
		require.NotNil(t, claims2)
		assert.Equal(t, "user1", claims2.Subject)
		assert.Equal(t, 1, callCount, "Expected still 1 call to base validator (cached)")

		tokenType := validator.GetTokenType()
		assert.Equal(t, "jwt", tokenType)
	})

	t.Run("base validator fails", func(t *testing.T) {
		baseValidator := &MockValidator{
			validateTokenFunc: func(ctx context.Context, tokenString string) (*contracts.Claims, error) {
				return nil, errors.New("validation failed")
			},
		}

		cache := NewMockValidationCache()
		validator := NewCachingValidator(baseValidator, cache)

		claims, err := validator.ValidateToken(ctx, "invalid-token")
		assert.Error(t, err)
		assert.Nil(t, claims)
	})

	t.Run("expired token not cached", func(t *testing.T) {
		baseValidator := &MockValidator{
			validateTokenFunc: func(ctx context.Context, tokenString string) (*contracts.Claims, error) {
				return &contracts.Claims{
					Subject:   "user1",
					ExpiresAt: time.Now().Add(-time.Hour), // Already expired
				}, nil
			},
		}

		cache := NewMockValidationCache()
		validator := NewCachingValidator(baseValidator, cache)

		claims, err := validator.ValidateToken(ctx, "expired-token")
		require.NoError(t, err)
		assert.NotNil(t, claims)

		// Verify token was not cached
		_, found := cache.Get(ctx, "expired-token")
		assert.False(t, found, "Expected expired token not to be cached")
	})

	t.Run("nil cache", func(t *testing.T) {
		baseValidator := &MockValidator{
			validateTokenFunc: func(ctx context.Context, tokenString string) (*contracts.Claims, error) {
				return &contracts.Claims{Subject: "user1"}, nil
			},
		}

		validator := NewCachingValidator(baseValidator, nil)

		claims, err := validator.ValidateToken(ctx, "test-token")
		require.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, "user1", claims.Subject)
	})
}
