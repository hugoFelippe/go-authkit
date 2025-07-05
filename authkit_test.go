package authkit_test

import (
	"context"
	"testing"
	"time"

	"github.com/hugoFelippe/go-authkit"
)

// Helper functions local to this test file
func setupTestAuth(t *testing.T, opts ...authkit.Option) *authkit.AuthKit {
	t.Helper()

	defaultOpts := []authkit.Option{
		authkit.WithIssuer("test"),
		authkit.WithJWTSecret([]byte("test-secret-key-for-testing-purposes-that-is-long-enough")),
		authkit.WithTokenExpiry(1 * time.Hour),
		authkit.WithDebug(true),
	}

	opts = append(defaultOpts, opts...)
	auth := authkit.New(opts...)

	t.Cleanup(func() {
		if err := auth.Close(); err != nil {
			t.Logf("Error closing AuthKit during cleanup: %v", err)
		}
	})

	return auth
}

func testUser(id string) *authkit.User {
	now := time.Now()
	return &authkit.User{
		ID:        id,
		Username:  "testuser" + id,
		Email:     "test" + id + "@example.com",
		Name:      "Test User " + id,
		Roles:     []string{"user"},
		Active:    true,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func testClaims(subject, issuer string) *authkit.Claims {
	now := time.Now()
	return &authkit.Claims{
		Subject:   subject,
		Issuer:    issuer,
		Email:     "test@example.com",
		Username:  "testuser",
		Roles:     []string{"user"},
		IssuedAt:  now,
		ExpiresAt: now.Add(1 * time.Hour),
	}
}

func TestAuthKit_Initialization(t *testing.T) {
	auth := setupTestAuth(t)

	if !auth.IsInitialized() {
		t.Error("AuthKit should be initialized")
	}

	config := auth.Config()
	if config.Issuer == "" {
		t.Error("Issuer should not be empty")
	}
	if len(config.JWTSecret) == 0 {
		t.Error("JWT Secret should not be empty")
	}
}

func TestAuthKit_ContextHelpers(t *testing.T) {
	ctx := context.Background()
	user := testUser("test-user")
	claims := testClaims("test-user", "test-issuer")

	// Test that context helper functions exist and compile
	ctxWithUser := authkit.WithUser(ctx, user)
	ctxWithClaims := authkit.WithClaims(ctx, claims)
	ctxWithToken := authkit.WithToken(ctx, "test-token")
	ctxWithScopes := authkit.WithScopes(ctx, []string{"read", "write"})

	// Test retrieval
	retrievedUser, ok := authkit.GetUserFromContext(ctxWithUser)
	if !ok {
		t.Error("Should retrieve user from context")
	}
	if retrievedUser.ID != user.ID {
		t.Errorf("Expected user ID %s, got %s", user.ID, retrievedUser.ID)
	}

	retrievedClaims, ok := authkit.GetClaimsFromContext(ctxWithClaims)
	if !ok {
		t.Error("Should retrieve claims from context")
	}
	if retrievedClaims.Subject != claims.Subject {
		t.Errorf("Expected subject %s, got %s", claims.Subject, retrievedClaims.Subject)
	}

	retrievedToken, ok := authkit.GetTokenFromContext(ctxWithToken)
	if !ok {
		t.Error("Should retrieve token from context")
	}
	if retrievedToken != "test-token" {
		t.Errorf("Expected token 'test-token', got %s", retrievedToken)
	}

	retrievedScopes, ok := authkit.GetScopesFromContext(ctxWithScopes)
	if !ok {
		t.Error("Should retrieve scopes from context")
	}
	if len(retrievedScopes) != 2 {
		t.Errorf("Expected 2 scopes, got %d", len(retrievedScopes))
	}
}
