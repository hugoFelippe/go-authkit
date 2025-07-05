package authkit_test

import (
	"testing"
	"time"

	"github.com/hugoFelippe/go-authkit"
)

func TestDefaultConfig(t *testing.T) {
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
	
	if err := config.Validate(); err == nil {
		t.Error("Expected validation error for missing JWT secret, got nil")
	}
}

func TestNewAuthKitWithOptions(t *testing.T) {
	auth := authkit.New(
		authkit.WithIssuer("test-app"),
		authkit.WithTokenExpiry(30*time.Minute),
		authkit.WithJWTSecret([]byte("my-secret-key-for-testing-purposes")),
		authkit.WithDebug(true),
	)
	
	if !auth.IsInitialized() {
		t.Fatal("AuthKit should be initialized")
	}
	
	config := auth.Config()
	
	if config.Issuer != "test-app" {
		t.Errorf("Expected issuer 'test-app', got '%s'", config.Issuer)
	}
	
	if config.TokenExpiry != 30*time.Minute {
		t.Errorf("Expected token expiry 30m, got %v", config.TokenExpiry)
	}
	
	if !config.Debug {
		t.Error("Expected debug to be true")
	}
	
	// Cleanup
	if err := auth.Close(); err != nil {
		t.Errorf("Error closing AuthKit: %v", err)
	}
}

func TestUserStruct(t *testing.T) {
	user := &authkit.User{
		ID:        "user123",
		Username:  "johndoe",
		Email:     "john@example.com",
		Name:      "John Doe",
		Roles:     []string{"user", "admin"},
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	if user.ID != "user123" {
		t.Errorf("Expected user ID 'user123', got '%s'", user.ID)
	}
	
	if user.Email != "john@example.com" {
		t.Errorf("Expected email 'john@example.com', got '%s'", user.Email)
	}
	
	if len(user.Roles) != 2 {
		t.Errorf("Expected 2 roles, got %d", len(user.Roles))
	}
	
	if !user.Active {
		t.Error("Expected user to be active")
	}
}

func TestClaimsStruct(t *testing.T) {
	now := time.Now()
	claims := &authkit.Claims{
		Subject:   "user123",
		Issuer:    "test-app",
		Email:     "john@example.com",
		Username:  "johndoe",
		Roles:     []string{"user", "admin"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
	
	if claims.Subject != "user123" {
		t.Errorf("Expected subject 'user123', got '%s'", claims.Subject)
	}
	
	if claims.Issuer != "test-app" {
		t.Errorf("Expected issuer 'test-app', got '%s'", claims.Issuer)
	}
	
	if len(claims.Roles) != 2 {
		t.Errorf("Expected 2 roles, got %d", len(claims.Roles))
	}
	
	if claims.ExpiresAt.Before(claims.IssuedAt) {
		t.Error("ExpiresAt should be after IssuedAt")
	}
}

func TestAPIKeyStruct(t *testing.T) {
	apiKey := &authkit.APIKey{
		ID:        "key123",
		Key:       "api-1234567890abcdef",
		Name:      "Test API Key",
		UserID:    "user123",
		Scopes:    []string{"read:users", "write:posts"},
		Active:    true,
		CreatedAt: time.Now(),
	}
	
	if apiKey.ID != "key123" {
		t.Errorf("Expected API key ID 'key123', got '%s'", apiKey.ID)
	}
	
	if apiKey.UserID != "user123" {
		t.Errorf("Expected user ID 'user123', got '%s'", apiKey.UserID)
	}
	
	if len(apiKey.Scopes) != 2 {
		t.Errorf("Expected 2 scopes, got %d", len(apiKey.Scopes))
	}
	
	if !apiKey.Active {
		t.Error("Expected API key to be active")
	}
}

func TestAuthErrors(t *testing.T) {
	// Test basic error
	err1 := authkit.ErrInvalidToken
	if err1.Error() != "INVALID_TOKEN: Invalid token" {
		t.Errorf("Unexpected error message: %s", err1.Error())
	}
	
	// Test error with details
	err2 := authkit.ErrInvalidTokenWithDetails("token format is invalid")
	expectedMsg := "INVALID_TOKEN: Invalid token (token format is invalid)"
	if err2.Error() != expectedMsg {
		t.Errorf("Expected '%s', got '%s'", expectedMsg, err2.Error())
	}
	
	// Test error type checking
	if !authkit.IsAuthError(err2) {
		t.Error("Expected err2 to be an AuthError")
	}
	
	if authkit.GetErrorCode(err2) != "INVALID_TOKEN" {
		t.Errorf("Expected error code 'INVALID_TOKEN', got '%s'", authkit.GetErrorCode(err2))
	}
	
	// Test token error classification
	if !authkit.IsTokenError(err1) {
		t.Error("Expected err1 to be classified as token error")
	}
}

func TestConfigValidation(t *testing.T) {
	// Test invalid configuration - empty issuer
	invalidConfig := authkit.DefaultConfig()
	invalidConfig.Issuer = ""
	
	err := invalidConfig.Validate()
	if err == nil {
		t.Error("Expected validation error for empty issuer")
	}
	
	if !authkit.IsAuthError(err) {
		t.Error("Expected validation error to be AuthError")
	}
	
	// Test invalid configuration - negative token expiry
	invalidConfig2 := authkit.DefaultConfig()
	invalidConfig2.TokenExpiry = -time.Hour
	invalidConfig2.JWTSecret = []byte("test-secret")
	
	err = invalidConfig2.Validate()
	if err == nil {
		t.Error("Expected validation error for negative token expiry")
	}
	
	// Test valid configuration
	validConfig := authkit.DefaultConfig()
	validConfig.JWTSecret = []byte("my-secret-key-for-testing")
	
	err = validConfig.Validate()
	if err != nil {
		t.Errorf("Expected no validation error for valid config, got: %v", err)
	}
}

func TestContextHelpers(t *testing.T) {
	// Test context helpers compilation
	user := &authkit.User{ID: "test-user"}
	claims := &authkit.Claims{Subject: "test-user"}
	
	// These functions should exist and compile
	_ = authkit.WithUser
	_ = authkit.WithClaims
	_ = authkit.WithToken
	_ = authkit.WithScopes
	_ = authkit.GetUserFromContext
	_ = authkit.GetClaimsFromContext
	_ = authkit.GetTokenFromContext
	_ = authkit.GetScopesFromContext
	
	// Basic type checking
	if user.ID != "test-user" {
		t.Error("User ID mismatch")
	}
	
	if claims.Subject != "test-user" {
		t.Error("Claims subject mismatch")
	}
}
