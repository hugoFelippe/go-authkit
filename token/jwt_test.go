package token

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hugoFelippe/go-authkit/contracts"
	"github.com/hugoFelippe/go-authkit/tests/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *JWTConfig
		expectError bool
		expectNil   bool
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
			expectNil:   true,
		},
		{
			name: "valid HMAC config",
			config: &JWTConfig{
				Issuer:        "test-issuer",
				SigningMethod: "HS256",
				SecretKey:     []byte("test-secret-key"),
				TokenExpiry:   time.Hour,
				RefreshExpiry: 24 * time.Hour,
			},
			expectError: false,
			expectNil:   false,
		},
		{
			name: "HMAC without secret key",
			config: &JWTConfig{
				Issuer:        "test-issuer",
				SigningMethod: "HS256",
				TokenExpiry:   time.Hour,
				RefreshExpiry: 24 * time.Hour,
			},
			expectError: true,
			expectNil:   true,
		},
		{
			name: "HS384 method",
			config: &JWTConfig{
				Issuer:        "test-issuer",
				SigningMethod: "HS384",
				SecretKey:     []byte("test-secret-key"),
				TokenExpiry:   time.Hour,
				RefreshExpiry: 24 * time.Hour,
			},
			expectError: false,
			expectNil:   false,
		},
		{
			name: "HS512 method",
			config: &JWTConfig{
				Issuer:        "test-issuer",
				SigningMethod: "HS512",
				SecretKey:     []byte("test-secret-key"),
				TokenExpiry:   time.Hour,
				RefreshExpiry: 24 * time.Hour,
			},
			expectError: false,
			expectNil:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewJWTManager(tt.config)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.expectNil {
				assert.Nil(t, manager)
			} else {
				require.NotNil(t, manager)
				// Verify specific signing method for valid configs
				if tt.config != nil && tt.config.SigningMethod == "HS256" {
					assert.Equal(t, jwt.SigningMethodHS256, manager.method)
				} else if tt.config != nil && tt.config.SigningMethod == "HS384" {
					assert.Equal(t, jwt.SigningMethodHS384, manager.method)
				} else if tt.config != nil && tt.config.SigningMethod == "HS512" {
					assert.Equal(t, jwt.SigningMethodHS512, manager.method)
				}
			}
		})
	}
}

func TestJWTManagerGenerateToken(t *testing.T) {
	config := &JWTConfig{
		Issuer:        "test-issuer",
		SigningMethod: "HS256",
		SecretKey:     []byte("test-secret-key-long-enough"),
		TokenExpiry:   time.Hour,
		RefreshExpiry: 24 * time.Hour,
	}

	manager, err := NewJWTManager(config)
	require.NoError(t, err, "Failed to create JWT manager")

	ctx := context.Background()
	user := testutils.TestUser("test-user-id")

	t.Run("generate token with default options", func(t *testing.T) {
		token, err := manager.GenerateToken(ctx, user)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Parse and validate the token structure
		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return config.SecretKey, nil
		})
		require.NoError(t, err, "Failed to parse generated token")
		assert.True(t, parsedToken.Valid, "Generated token should be valid")
	})

	t.Run("generate token with user data", func(t *testing.T) {
		token, err := manager.GenerateToken(ctx, user)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Validate the token and check claims
		claims, err := manager.ValidateToken(ctx, token)
		require.NoError(t, err, "Failed to validate token")
		require.NotNil(t, claims)
		assert.Equal(t, user.ID, claims.Subject)
		assert.Equal(t, user.Email, claims.Email)
	})

	t.Run("generate refresh token", func(t *testing.T) {
		refreshToken, err := manager.GenerateRefreshToken(ctx, user)
		require.NoError(t, err)
		assert.NotEmpty(t, refreshToken)

		// Parse and validate the refresh token structure
		parsedToken, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
			return config.SecretKey, nil
		})
		require.NoError(t, err, "Failed to parse generated refresh token")
		assert.True(t, parsedToken.Valid, "Generated refresh token should be valid")
	})
}

func TestJWTManagerValidateToken(t *testing.T) {
	config := &JWTConfig{
		Issuer:        "test-issuer",
		SigningMethod: "HS256",
		SecretKey:     []byte("test-secret-key-long-enough"),
		TokenExpiry:   time.Hour,
		RefreshExpiry: 24 * time.Hour,
	}

	manager, err := NewJWTManager(config)
	require.NoError(t, err, "Failed to create JWT manager")

	ctx := context.Background()
	user := testutils.TestUser("test-user-id")

	tests := []struct {
		name    string
		setupFn func() string
		wantErr bool
		checkFn func(*testing.T, *contracts.Claims)
	}{
		{
			name: "validate valid token",
			setupFn: func() string {
				token, err := manager.GenerateToken(ctx, user)
				require.NoError(t, err)
				return token
			},
			wantErr: false,
			checkFn: func(t *testing.T, claims *contracts.Claims) {
				require.NotNil(t, claims)
				assert.Equal(t, user.ID, claims.Subject)
				assert.Equal(t, user.Email, claims.Email)
			},
		},
		{
			name: "validate invalid token",
			setupFn: func() string {
				return "invalid-token"
			},
			wantErr: true,
			checkFn: func(t *testing.T, claims *contracts.Claims) {
				assert.Nil(t, claims)
			},
		},
		{
			name: "validate empty token",
			setupFn: func() string {
				return ""
			},
			wantErr: true,
			checkFn: func(t *testing.T, claims *contracts.Claims) {
				assert.Nil(t, claims)
			},
		},
		{
			name: "validate expired token",
			setupFn: func() string {
				// Create a token with expired time by modifying the config temporarily
				originalExpiry := config.TokenExpiry
				config.TokenExpiry = -time.Hour // Set to expired

				token, err := manager.GenerateToken(ctx, user)
				require.NoError(t, err)

				// Restore original expiry
				config.TokenExpiry = originalExpiry
				return token
			},
			wantErr: true,
			checkFn: func(t *testing.T, claims *contracts.Claims) {
				assert.Nil(t, claims)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := tt.setupFn()
			claims, err := manager.ValidateToken(ctx, token)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.checkFn != nil {
				tt.checkFn(t, claims)
			}
		})
	}

	t.Run("validate refresh token", func(t *testing.T) {
		// Generate a refresh token first
		refreshToken, err := manager.GenerateRefreshToken(ctx, user)
		require.NoError(t, err, "Failed to generate refresh token")

		// Validate the refresh token
		claims, err := manager.ValidateRefreshToken(ctx, refreshToken)
		require.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, user.ID, claims.Subject)
	})
}

func TestJWTManagerTokenOperations(t *testing.T) {
	config := &JWTConfig{
		Issuer:        "test-issuer",
		SigningMethod: "HS256",
		SecretKey:     []byte("test-secret-key-long-enough"),
		TokenExpiry:   time.Hour,
		RefreshExpiry: 24 * time.Hour,
	}

	manager, err := NewJWTManager(config)
	require.NoError(t, err, "Failed to create JWT manager")

	ctx := context.Background()
	user := testutils.TestUser("test-user-id")

	t.Run("introspect token", func(t *testing.T) {
		// Generate a token first
		token, err := manager.GenerateToken(ctx, user)
		require.NoError(t, err, "Failed to generate token")

		// Introspect the token
		tokenInfo, err := manager.IntrospectToken(ctx, token)
		require.NoError(t, err)
		require.NotNil(t, tokenInfo)

		// For JWT, check the extra fields for subject
		subject, exists := tokenInfo.Extra["subject"]
		require.True(t, exists, "Subject should exist in token info")
		assert.Equal(t, user.ID, subject)
	})

	t.Run("introspect invalid token", func(t *testing.T) {
		tokenInfo, err := manager.IntrospectToken(ctx, "invalid-token")
		require.NoError(t, err, "Introspect should not error (returns inactive info)")
		require.NotNil(t, tokenInfo, "Token info should not be nil")

		// Check that there's an error in the extra field indicating the token was not found
		_, exists := tokenInfo.Extra["error"]
		assert.True(t, exists, "Error should exist in token info extra field for invalid token")
	})

	t.Run("revoke token", func(t *testing.T) {
		// Generate a token first
		token, err := manager.GenerateToken(ctx, user)
		require.NoError(t, err, "Failed to generate token")

		// Try to revoke the token - expect error due to missing external storage
		err = manager.RevokeToken(ctx, token)
		assert.Error(t, err, "Should error for revoke token without external storage")
	})

	t.Run("revoke all tokens", func(t *testing.T) {
		// Try to revoke all tokens - expect error due to missing external storage
		err := manager.RevokeAllTokens(ctx, user.ID)
		assert.Error(t, err, "Should error for revoke all tokens without external storage")
	})

	t.Run("refresh token", func(t *testing.T) {
		// Generate a refresh token first
		refreshToken, err := manager.GenerateRefreshToken(ctx, user)
		require.NoError(t, err, "Failed to generate refresh token")

		// Refresh the token
		accessToken, newRefreshToken, err := manager.RefreshToken(ctx, refreshToken)
		require.NoError(t, err)
		assert.NotEmpty(t, accessToken, "Access token should not be empty")
		assert.NotEmpty(t, newRefreshToken, "New refresh token should not be empty")
		assert.NotEqual(t, accessToken, refreshToken, "Access token should be different from refresh token")
		assert.NotEqual(t, newRefreshToken, refreshToken, "New refresh token should be different from old refresh token")
	})

	t.Run("refresh with invalid token", func(t *testing.T) {
		accessToken, newRefreshToken, err := manager.RefreshToken(ctx, "invalid-refresh-token")
		assert.Error(t, err, "Should error for invalid refresh token")
		assert.Empty(t, accessToken, "Access token should be empty on error")
		assert.Empty(t, newRefreshToken, "New refresh token should be empty on error")
	})
}

func TestJWTManagerErrors(t *testing.T) {
	t.Run("test error constants", func(t *testing.T) {
		assert.NotNil(t, contracts.ErrInvalidToken, "ErrInvalidToken should not be nil")
		assert.NotNil(t, contracts.ErrExpiredToken, "ErrExpiredToken should not be nil")
	})
}

func TestJWTManagerConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *JWTConfig
		expectError bool
	}{
		{
			name: "valid HS256 config",
			config: &JWTConfig{
				Issuer:        "test",
				SigningMethod: "HS256",
				SecretKey:     []byte("secret"),
				TokenExpiry:   time.Hour,
			},
			expectError: false,
		},
		{
			name: "HS256 without secret",
			config: &JWTConfig{
				Issuer:        "test",
				SigningMethod: "HS256",
				TokenExpiry:   time.Hour,
			},
			expectError: true,
		},
		{
			name: "HS384 without secret",
			config: &JWTConfig{
				Issuer:        "test",
				SigningMethod: "HS384",
				TokenExpiry:   time.Hour,
			},
			expectError: true,
		},
		{
			name: "HS512 without secret",
			config: &JWTConfig{
				Issuer:        "test",
				SigningMethod: "HS512",
				TokenExpiry:   time.Hour,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewJWTManager(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, manager, "Manager should be nil on error")
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, manager, "Manager should not be nil on success")
			}
		})
	}
}
