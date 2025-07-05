package authkit_test

import (
	"testing"
	"time"

	"github.com/hugoFelippe/go-authkit"
)

func TestUser_Structure(t *testing.T) {
	user := &authkit.User{
		ID:        "user123",
		Username:  "testuser123",
		Email:     "test123@example.com",
		Name:      "Test User 123",
		Roles:     []string{"user"},
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if user.ID != "user123" {
		t.Errorf("Expected user ID 'user123', got '%s'", user.ID)
	}
	if user.Username != "testuser123" {
		t.Errorf("Expected username 'testuser123', got '%s'", user.Username)
	}
	if user.Email != "test123@example.com" {
		t.Errorf("Expected email 'test123@example.com', got '%s'", user.Email)
	}
	if !user.Active {
		t.Error("User should be active")
	}
	if len(user.Roles) == 0 {
		t.Error("User should have roles")
	}
}

func TestUser_WithRoles(t *testing.T) {
	roles := []string{"admin", "user", "moderator"}
	user := &authkit.User{
		ID:        "admin123",
		Username:  "adminuser",
		Email:     "admin@example.com",
		Name:      "Admin User",
		Roles:     roles,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if len(user.Roles) != 3 {
		t.Errorf("Expected 3 roles, got %d", len(user.Roles))
	}
	if user.Roles[0] != "admin" {
		t.Errorf("Expected first role 'admin', got '%s'", user.Roles[0])
	}
	if user.Roles[1] != "user" {
		t.Errorf("Expected second role 'user', got '%s'", user.Roles[1])
	}
	if user.Roles[2] != "moderator" {
		t.Errorf("Expected third role 'moderator', got '%s'", user.Roles[2])
	}
}

func TestClaims_Structure(t *testing.T) {
	now := time.Now()
	claims := &authkit.Claims{
		Subject:   "user123",
		Issuer:    "test-app",
		Email:     "test@example.com",
		Username:  "testuser",
		Roles:     []string{"user"},
		IssuedAt:  now,
		ExpiresAt: now.Add(1 * time.Hour),
	}

	if claims.Subject != "user123" {
		t.Errorf("Expected subject 'user123', got '%s'", claims.Subject)
	}
	if claims.Issuer != "test-app" {
		t.Errorf("Expected issuer 'test-app', got '%s'", claims.Issuer)
	}
	if claims.Email == "" {
		t.Error("Email should not be empty")
	}
	if claims.Username == "" {
		t.Error("Username should not be empty")
	}
	if len(claims.Roles) == 0 {
		t.Error("Claims should have roles")
	}
	if !claims.ExpiresAt.After(claims.IssuedAt) {
		t.Error("ExpiresAt should be after IssuedAt")
	}
}

func TestAPIKey_Structure(t *testing.T) {
	now := time.Now()
	apiKey := &authkit.APIKey{
		ID:        "key123",
		Key:       "test-api-key-123",
		Name:      "Test API Key 123",
		UserID:    "user123",
		Scopes:    []string{"read", "write"},
		Active:    true,
		CreatedAt: now,
	}

	if apiKey.ID != "key123" {
		t.Errorf("Expected API key ID 'key123', got '%s'", apiKey.ID)
	}
	if apiKey.UserID != "user123" {
		t.Errorf("Expected user ID 'user123', got '%s'", apiKey.UserID)
	}
	if apiKey.Key == "" {
		t.Error("Key should not be empty")
	}
	if apiKey.Name == "" {
		t.Error("Name should not be empty")
	}
	if !apiKey.Active {
		t.Error("API key should be active")
	}
	if len(apiKey.Scopes) == 0 {
		t.Error("API key should have scopes")
	}
}

func TestAPIKey_WithCustomScopes(t *testing.T) {
	now := time.Now()
	apiKey := &authkit.APIKey{
		ID:        "key123",
		Key:       "api-1234567890abcdef",
		Name:      "Test API Key",
		UserID:    "user123",
		Scopes:    []string{"read:users", "write:posts"},
		Active:    true,
		CreatedAt: now,
	}

	if len(apiKey.Scopes) != 2 {
		t.Errorf("Expected 2 scopes, got %d", len(apiKey.Scopes))
	}
	if apiKey.Scopes[0] != "read:users" {
		t.Errorf("Expected first scope 'read:users', got '%s'", apiKey.Scopes[0])
	}
	if apiKey.Scopes[1] != "write:posts" {
		t.Errorf("Expected second scope 'write:posts', got '%s'", apiKey.Scopes[1])
	}
}
