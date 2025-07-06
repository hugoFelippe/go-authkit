package token

import (
	"context"
	"testing"
	"time"

	"github.com/hugoFelippe/go-authkit/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateOptions(t *testing.T) {
	tests := []struct {
		name     string
		options  []contracts.GenerateOption
		validate func(*testing.T, *contracts.GenerateOptions)
	}{
		{
			name:    "default options",
			options: []contracts.GenerateOption{},
			validate: func(t *testing.T, opts *contracts.GenerateOptions) {
				assert.Equal(t, "access", opts.TokenType)
				assert.Nil(t, opts.ExpiresAt)
				assert.Empty(t, opts.Audience)
				assert.Empty(t, opts.Scopes)
				assert.Empty(t, opts.CustomClaims)
			},
		},
		{
			name:    "with expiry duration",
			options: []contracts.GenerateOption{WithExpiry(time.Hour)},
			validate: func(t *testing.T, opts *contracts.GenerateOptions) {
				require.NotNil(t, opts.ExpiresAt)
				assert.True(t, opts.ExpiresAt.After(time.Now().Add(59*time.Minute)))
				assert.True(t, opts.ExpiresAt.Before(time.Now().Add(61*time.Minute)))
			},
		},
		{
			name:    "with specific expires at",
			options: []contracts.GenerateOption{WithExpiresAt(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))},
			validate: func(t *testing.T, opts *contracts.GenerateOptions) {
				expected := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
				require.NotNil(t, opts.ExpiresAt)
				assert.True(t, opts.ExpiresAt.Equal(expected))
			},
		},
		{
			name:    "with audience",
			options: []contracts.GenerateOption{WithAudience("api", "web")},
			validate: func(t *testing.T, opts *contracts.GenerateOptions) {
				require.Len(t, opts.Audience, 2)
				assert.Equal(t, "api", opts.Audience[0])
				assert.Equal(t, "web", opts.Audience[1])
			},
		},
		{
			name:    "with scopes",
			options: []contracts.GenerateOption{WithScopes("read", "write")},
			validate: func(t *testing.T, opts *contracts.GenerateOptions) {
				require.Len(t, opts.Scopes, 2)
				assert.Equal(t, "read", opts.Scopes[0])
				assert.Equal(t, "write", opts.Scopes[1])
			},
		},
		{
			name: "with custom claims",
			options: []contracts.GenerateOption{WithCustomClaims(map[string]interface{}{
				"department": "engineering",
				"level":      3,
			})},
			validate: func(t *testing.T, opts *contracts.GenerateOptions) {
				require.Len(t, opts.CustomClaims, 2)
				assert.Equal(t, "engineering", opts.CustomClaims["department"])
				assert.Equal(t, 3, opts.CustomClaims["level"])
			},
		},
		{
			name:    "with token type",
			options: []contracts.GenerateOption{WithTokenType("MAC")},
			validate: func(t *testing.T, opts *contracts.GenerateOptions) {
				assert.Equal(t, "MAC", opts.TokenType)
			},
		},
		{
			name: "multiple options",
			options: []contracts.GenerateOption{
				WithExpiry(time.Hour),
				WithAudience("api"),
				WithScopes("read"),
				WithTokenType("Bearer"),
				WithCustomClaims(map[string]interface{}{"test": "value"}),
			},
			validate: func(t *testing.T, opts *contracts.GenerateOptions) {
				assert.Equal(t, "Bearer", opts.TokenType)
				assert.NotNil(t, opts.ExpiresAt)
				require.Len(t, opts.Audience, 1)
				assert.Equal(t, "api", opts.Audience[0])
				require.Len(t, opts.Scopes, 1)
				assert.Equal(t, "read", opts.Scopes[0])
				assert.Equal(t, "value", opts.CustomClaims["test"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := applyGenerateOptions(tt.options)
			tt.validate(t, opts)
		})
	}
}

func TestWithCustomClaimsMultipleCalls(t *testing.T) {
	// Test that multiple calls to WithCustomClaims merge claims correctly
	options := []contracts.GenerateOption{
		WithCustomClaims(map[string]interface{}{
			"claim1": "value1",
			"claim2": "value2",
		}),
		WithCustomClaims(map[string]interface{}{
			"claim3": "value3",
			"claim2": "overwritten", // Should overwrite previous value
		}),
	}

	opts := applyGenerateOptions(options)

	if len(opts.CustomClaims) != 3 {
		t.Errorf("Expected 3 custom claims, got %d", len(opts.CustomClaims))
	}

	if opts.CustomClaims["claim1"] != "value1" {
		t.Errorf("Expected claim1 to be 'value1', got %v", opts.CustomClaims["claim1"])
	}

	if opts.CustomClaims["claim2"] != "overwritten" {
		t.Errorf("Expected claim2 to be 'overwritten', got %v", opts.CustomClaims["claim2"])
	}

	if opts.CustomClaims["claim3"] != "value3" {
		t.Errorf("Expected claim3 to be 'value3', got %v", opts.CustomClaims["claim3"])
	}
}

func TestDefaultGenerateOptions(t *testing.T) {
	opts := defaultGenerateOptions()

	assert.Equal(t, "access", opts.TokenType)
	assert.Nil(t, opts.ExpiresAt)
	assert.Empty(t, opts.Audience)
	assert.Empty(t, opts.Scopes)
	assert.Empty(t, opts.CustomClaims)
}

// MockTokenManager implementa a interface TokenManager para testes
type MockTokenManager struct {
	generateTokenFunc        func(ctx context.Context, user *contracts.User, options ...contracts.GenerateOption) (string, error)
	generateRefreshTokenFunc func(ctx context.Context, user *contracts.User) (string, error)
	validateTokenFunc        func(ctx context.Context, tokenString string) (*contracts.Claims, error)
	validateRefreshTokenFunc func(ctx context.Context, tokenString string) (*contracts.Claims, error)
	introspectTokenFunc      func(ctx context.Context, tokenString string) (*contracts.TokenInfo, error)
	revokeTokenFunc          func(ctx context.Context, tokenString string) error
	revokeAllTokensFunc      func(ctx context.Context, userID string) error
	refreshTokenFunc         func(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error)
}

func (m *MockTokenManager) GenerateToken(ctx context.Context, user *contracts.User, options ...contracts.GenerateOption) (string, error) {
	if m.generateTokenFunc != nil {
		return m.generateTokenFunc(ctx, user, options...)
	}
	return "mock-token", nil
}

func (m *MockTokenManager) GenerateRefreshToken(ctx context.Context, user *contracts.User) (string, error) {
	if m.generateRefreshTokenFunc != nil {
		return m.generateRefreshTokenFunc(ctx, user)
	}
	return "mock-refresh-token", nil
}

func (m *MockTokenManager) ValidateToken(ctx context.Context, tokenString string) (*contracts.Claims, error) {
	if m.validateTokenFunc != nil {
		return m.validateTokenFunc(ctx, tokenString)
	}
	return &contracts.Claims{Subject: "test-user"}, nil
}

func (m *MockTokenManager) ValidateRefreshToken(ctx context.Context, tokenString string) (*contracts.Claims, error) {
	if m.validateRefreshTokenFunc != nil {
		return m.validateRefreshTokenFunc(ctx, tokenString)
	}
	return &contracts.Claims{Subject: "test-user"}, nil
}

func (m *MockTokenManager) IntrospectToken(ctx context.Context, tokenString string) (*contracts.TokenInfo, error) {
	if m.introspectTokenFunc != nil {
		return m.introspectTokenFunc(ctx, tokenString)
	}
	return &contracts.TokenInfo{Active: true}, nil
}

func (m *MockTokenManager) RevokeToken(ctx context.Context, tokenString string) error {
	if m.revokeTokenFunc != nil {
		return m.revokeTokenFunc(ctx, tokenString)
	}
	return nil
}

func (m *MockTokenManager) RevokeAllTokens(ctx context.Context, userID string) error {
	if m.revokeAllTokensFunc != nil {
		return m.revokeAllTokensFunc(ctx, userID)
	}
	return nil
}

func (m *MockTokenManager) RefreshToken(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error) {
	if m.refreshTokenFunc != nil {
		return m.refreshTokenFunc(ctx, refreshToken)
	}
	return "new-access-token", "new-refresh-token", nil
}

func TestMockTokenManager(t *testing.T) {
	ctx := context.Background()
	user := &contracts.User{
		ID:       "test-user",
		Username: "testuser",
		Email:    "test@example.com",
	}

	mock := &MockTokenManager{}

	// Test GenerateToken
	token, err := mock.GenerateToken(ctx, user)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if token != "mock-token" {
		t.Errorf("Expected 'mock-token', got %s", token)
	}

	// Test GenerateRefreshToken
	refreshToken, err := mock.GenerateRefreshToken(ctx, user)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if refreshToken != "mock-refresh-token" {
		t.Errorf("Expected 'mock-refresh-token', got %s", refreshToken)
	}

	// Test ValidateToken
	claims, err := mock.ValidateToken(ctx, "test-token")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if claims.Subject != "test-user" {
		t.Errorf("Expected subject 'test-user', got %s", claims.Subject)
	}

	// Test RefreshToken
	accessToken, newRefreshToken, err := mock.RefreshToken(ctx, "refresh-token")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if accessToken != "new-access-token" {
		t.Errorf("Expected 'new-access-token', got %s", accessToken)
	}
	if newRefreshToken != "new-refresh-token" {
		t.Errorf("Expected 'new-refresh-token', got %s", newRefreshToken)
	}
}
