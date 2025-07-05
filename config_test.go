package authkit_test

import (
	"testing"
	"time"

	"github.com/hugoFelippe/go-authkit"
)

func TestConfig_DefaultValues(t *testing.T) {
	config := authkit.DefaultConfig()

	if config.Issuer != "authkit" {
		t.Errorf("Expected issuer 'authkit', got '%s'", config.Issuer)
	}
	if config.TokenExpiry != time.Hour*24 {
		t.Errorf("Expected token expiry 24h, got %v", config.TokenExpiry)
	}
	if config.JWTSigningMethod != "HS256" {
		t.Errorf("Expected JWT signing method 'HS256', got '%s'", config.JWTSigningMethod)
	}
}

func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name      string
		setupFn   func() *authkit.Config
		wantErr   bool
		errorCode string
	}{
		{
			name: "valid config",
			setupFn: func() *authkit.Config {
				config := authkit.DefaultConfig()
				config.JWTSecret = []byte("test-secret-key-for-testing")
				return config
			},
			wantErr: false,
		},
		{
			name: "empty issuer",
			setupFn: func() *authkit.Config {
				config := authkit.DefaultConfig()
				config.Issuer = ""
				config.JWTSecret = []byte("test-secret")
				return config
			},
			wantErr:   true,
			errorCode: "INVALID_CONFIG",
		},
		{
			name: "negative token expiry",
			setupFn: func() *authkit.Config {
				config := authkit.DefaultConfig()
				config.TokenExpiry = -time.Hour
				config.JWTSecret = []byte("test-secret")
				return config
			},
			wantErr:   true,
			errorCode: "INVALID_CONFIG",
		},
		{
			name: "missing JWT secret",
			setupFn: func() *authkit.Config {
				return authkit.DefaultConfig()
			},
			wantErr:   true,
			errorCode: "INVALID_CONFIG",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupFn()
			err := config.Validate()

			if tt.wantErr && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.wantErr && tt.errorCode != "" {
				if !authkit.IsAuthError(err) {
					t.Errorf("expected AuthError, got %T", err)
				} else if authkit.GetErrorCode(err) != tt.errorCode {
					t.Errorf("expected error code %s, got %s", tt.errorCode, authkit.GetErrorCode(err))
				}
			}
		})
	}
}

func TestConfig_WithOptions(t *testing.T) {
	auth := authkit.New(
		authkit.WithIssuer("test-app"),
		authkit.WithTokenExpiry(30*time.Minute),
		authkit.WithJWTSecret([]byte("test-secret-key-for-testing-purposes")),
	)

	if !auth.IsInitialized() {
		t.Error("AuthKit should be initialized")
	}

	config := auth.Config()
	if config.Issuer != "test-app" {
		t.Errorf("Expected issuer 'test-app', got '%s'", config.Issuer)
	}
	if config.TokenExpiry != 30*time.Minute {
		t.Errorf("Expected token expiry 30m, got %v", config.TokenExpiry)
	}

	err := auth.Close()
	if err != nil {
		t.Errorf("Error closing AuthKit: %v", err)
	}
}
