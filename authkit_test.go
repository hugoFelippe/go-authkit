package authkit

import (
	"context"
	"testing"
	"time"

	"github.com/hugoFelippe/go-authkit/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
		want func(*testing.T, *AuthKit)
	}{
		{
			name: "default configuration",
			opts: []Option{WithJWTSecret([]byte("test-secret-key-for-testing"))},
			want: func(t *testing.T, auth *AuthKit) {
				assert.NotNil(t, auth)
				assert.NotNil(t, auth.config)
			},
		},
		{
			name: "with issuer option",
			opts: []Option{
				WithIssuer("test-issuer"),
				WithJWTSecret([]byte("test-secret-key-for-testing")),
			},
			want: func(t *testing.T, auth *AuthKit) {
				assert.Equal(t, "test-issuer", auth.config.Issuer)
			},
		},
		{
			name: "with token expiry option",
			opts: []Option{
				WithTokenExpiry(2 * time.Hour),
				WithJWTSecret([]byte("test-secret-key-for-testing")),
			},
			want: func(t *testing.T, auth *AuthKit) {
				assert.Equal(t, 2*time.Hour, auth.config.TokenExpiry)
			},
		},
		{
			name: "with JWT secret option",
			opts: []Option{WithJWTSecret([]byte("test-secret"))},
			want: func(t *testing.T, auth *AuthKit) {
				assert.Equal(t, "test-secret", string(auth.config.JWTSecret))
			},
		},
		{
			name: "with debug option",
			opts: []Option{
				WithDebug(true),
				WithJWTSecret([]byte("test-secret-key-for-testing")),
			},
			want: func(t *testing.T, auth *AuthKit) {
				assert.True(t, auth.config.Debug)
			},
		},
		{
			name: "with API key prefix option",
			opts: []Option{
				WithAPIKeyPrefix("myapp-"),
				WithJWTSecret([]byte("test-secret-key-for-testing")),
			},
			want: func(t *testing.T, auth *AuthKit) {
				assert.Equal(t, "myapp-", auth.config.APIKeyPrefix)
			},
		},
		{
			name: "with token sources option",
			opts: []Option{
				WithTokenSources("bearer", "header"),
				WithJWTSecret([]byte("test-secret-key-for-testing")),
			},
			want: func(t *testing.T, auth *AuthKit) {
				require.Len(t, auth.config.TokenSources, 2)
				assert.Equal(t, "bearer", auth.config.TokenSources[0])
				assert.Equal(t, "header", auth.config.TokenSources[1])
			},
		},
		{
			name: "multiple options",
			opts: []Option{
				WithIssuer("multi-test"),
				WithTokenExpiry(30 * time.Minute),
				WithDebug(true),
				WithJWTSecret([]byte("test-secret-key-for-testing")),
			},
			want: func(t *testing.T, auth *AuthKit) {
				assert.Equal(t, "multi-test", auth.config.Issuer)
				assert.Equal(t, 30*time.Minute, auth.config.TokenExpiry)
				assert.True(t, auth.config.Debug)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := New(tt.opts...)

			require.NotNil(t, auth, "New() returned nil")
			tt.want(t, auth)

			// Cleanup
			err := auth.Close()
			if err != nil {
				t.Logf("Warning: error during cleanup: %v", err)
			}
		})
	}
}

func TestAuthKit_Config(t *testing.T) {
	auth := New(
		WithIssuer("test-config"),
		WithTokenExpiry(1*time.Hour),
		WithDebug(true),
		WithJWTSecret([]byte("test-secret-key-for-testing")),
	)
	defer auth.Close()

	config := auth.Config()

	if config == nil {
		t.Fatal("Config() returned nil")
	}

	if config.Issuer != "test-config" {
		t.Errorf("expected issuer 'test-config', got '%s'", config.Issuer)
	}

	if config.TokenExpiry != 1*time.Hour {
		t.Errorf("expected token expiry '1h', got '%v'", config.TokenExpiry)
	}

	if !config.Debug {
		t.Error("expected debug to be true")
	}
}

func TestAuthKit_IsInitialized(t *testing.T) {
	auth := New(
		WithIssuer("test-init"),
		WithJWTSecret([]byte("test-secret-key-for-testing")),
	)
	defer auth.Close()

	if !auth.IsInitialized() {
		t.Error("AuthKit should be initialized after New()")
	}
}

func TestAuthKit_Close(t *testing.T) {
	auth := New(
		WithIssuer("test-close"),
		WithJWTSecret([]byte("test-secret-key-for-testing")),
	)

	err := auth.Close()
	if err != nil {
		t.Errorf("unexpected error during Close(): %v", err)
	}

	// Multiple closes should not cause panic or error
	err = auth.Close()
	if err != nil {
		t.Errorf("unexpected error during second Close(): %v", err)
	}
}

func TestWithOptions(t *testing.T) {
	t.Run("WithIssuer", func(t *testing.T) {
		config := DefaultConfig()
		opt := WithIssuer("test-issuer")
		opt(config)

		if config.Issuer != "test-issuer" {
			t.Errorf("expected issuer 'test-issuer', got '%s'", config.Issuer)
		}
	})

	t.Run("WithTokenExpiry", func(t *testing.T) {
		config := DefaultConfig()
		opt := WithTokenExpiry(2 * time.Hour)
		opt(config)

		if config.TokenExpiry != 2*time.Hour {
			t.Errorf("expected token expiry '2h', got '%v'", config.TokenExpiry)
		}
	})

	t.Run("WithJWTSecret", func(t *testing.T) {
		config := DefaultConfig()
		secret := []byte("test-secret-key")
		opt := WithJWTSecret(secret)
		opt(config)

		if string(config.JWTSecret) != string(secret) {
			t.Errorf("expected JWT secret '%s', got '%s'", secret, config.JWTSecret)
		}
	})

	t.Run("WithJWTSigningMethod", func(t *testing.T) {
		config := DefaultConfig()
		opt := WithJWTSigningMethod("HS512")
		opt(config)

		if config.JWTSigningMethod != "HS512" {
			t.Errorf("expected signing method 'HS512', got '%s'", config.JWTSigningMethod)
		}
	})

	t.Run("WithDebug", func(t *testing.T) {
		config := DefaultConfig()
		opt := WithDebug(true)
		opt(config)

		if !config.Debug {
			t.Error("expected debug to be true")
		}
	})

	t.Run("WithAPIKeyPrefix", func(t *testing.T) {
		config := DefaultConfig()
		opt := WithAPIKeyPrefix("myapp-")
		opt(config)

		if config.APIKeyPrefix != "myapp-" {
			t.Errorf("expected API key prefix 'myapp-', got '%s'", config.APIKeyPrefix)
		}
	})

	t.Run("WithTokenSources", func(t *testing.T) {
		config := DefaultConfig()
		sources := []string{"bearer", "header", "query"}
		opt := WithTokenSources(sources...)
		opt(config)

		if len(config.TokenSources) != len(sources) {
			t.Errorf("expected %d token sources, got %d", len(sources), len(config.TokenSources))
		}

		for i, source := range sources {
			if config.TokenSources[i] != source {
				t.Errorf("expected token source '%s' at index %d, got '%s'", source, i, config.TokenSources[i])
			}
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	// Verify default values
	if config.Issuer != "authkit" {
		t.Errorf("expected default issuer 'authkit', got '%s'", config.Issuer)
	}

	if config.TokenExpiry != 24*time.Hour {
		t.Errorf("expected default token expiry '24h', got '%v'", config.TokenExpiry)
	}

	if config.JWTSigningMethod != "HS256" {
		t.Errorf("expected default signing method 'HS256', got '%s'", config.JWTSigningMethod)
	}

	if config.Debug != false {
		t.Error("expected default debug to be false")
	}

	if config.APIKeyPrefix != "" {
		t.Errorf("expected default API key prefix to be empty, got '%s'", config.APIKeyPrefix)
	}

	expectedSources := []string{"bearer", "header"}
	if len(config.TokenSources) != len(expectedSources) {
		t.Errorf("expected %d default token sources, got %d", len(expectedSources), len(config.TokenSources))
	}
}

// Test helper functions
func TestAuthKit_UseTokenManager(t *testing.T) {
	auth := New(
		WithIssuer("test-manager"),
		WithJWTSecret([]byte("test-secret-key-for-testing")),
	)
	defer auth.Close()

	// Create a mock token manager
	mockManager := &mockTokenManager{}

	auth.UseTokenManager(mockManager)

	// Verify that the TokenValidator now returns our mock
	validator := auth.TokenValidator()
	if validator == nil {
		t.Error("TokenValidator() returned nil after setting mock manager")
	}
}

func TestAuthKit_TokenValidator(t *testing.T) {
	auth := New(
		WithIssuer("test-get-validator"),
		WithJWTSecret([]byte("test-secret-key-for-testing")),
	)
	defer auth.Close()

	// Without a token manager set, should return nil
	validator := auth.TokenValidator()
	if validator != nil {
		t.Error("TokenValidator() should return nil when no token manager is set")
	}

	// After setting a token manager, should return the manager
	mockManager := &mockTokenManager{}
	auth.UseTokenManager(mockManager)

	validator = auth.TokenValidator()
	if validator == nil {
		t.Error("TokenValidator() returned nil after setting token manager")
	}
}

// Mock implementations for testing
type mockTokenManager struct{}

func (m *mockTokenManager) GenerateToken(ctx context.Context, claims *contracts.Claims) (string, error) {
	return "mock-token", nil
}

func (m *mockTokenManager) GenerateTokenWithExpiry(ctx context.Context, claims *contracts.Claims, expiry time.Duration) (string, error) {
	return "mock-token-with-expiry", nil
}

func (m *mockTokenManager) GenerateRefreshToken(ctx context.Context, user *contracts.User) (string, error) {
	return "mock-refresh-token", nil
}

func (m *mockTokenManager) ValidateToken(ctx context.Context, tokenString string) (*contracts.Claims, error) {
	return &contracts.Claims{Subject: "test-user"}, nil
}

func (m *mockTokenManager) ValidateTokenWithType(ctx context.Context, token string, tokenType contracts.TokenType) (*contracts.Claims, error) {
	return &contracts.Claims{Subject: "test-user"}, nil
}

func (m *mockTokenManager) IntrospectToken(ctx context.Context, tokenString string) (*contracts.TokenInfo, error) {
	return &contracts.TokenInfo{Type: contracts.TokenTypeJWT}, nil
}

func (m *mockTokenManager) RevokeToken(ctx context.Context, tokenString string) error {
	return nil
}

func (m *mockTokenManager) RevokeAllTokens(ctx context.Context, userID string) error {
	return nil
}

func (m *mockTokenManager) RefreshToken(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error) {
	return "new-access-token", "new-refresh-token", nil
}
