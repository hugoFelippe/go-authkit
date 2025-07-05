package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/hugoFelippe/go-authkit"
	"github.com/hugoFelippe/go-authkit/tests/testutils"
)

func TestAuthKit_Integration_BasicFlow(t *testing.T) {
	// Setup AuthKit with JWT adapter
	auth := testutils.SetupTestAuth(t,
		authkit.WithIssuer("integration-test"),
		authkit.WithTokenExpiry(1*time.Hour),
	)

	ctx := context.Background()

	// Create a test user
	user := testutils.TestUser("integration-user-123")

	// Test token generation (when implemented)
	t.Run("token_generation", func(t *testing.T) {
		// This will be implemented when JWT adapter is ready
		t.Skip("Token generation not yet implemented")
	})

	// Test token validation (when implemented)
	t.Run("token_validation", func(t *testing.T) {
		// This will be implemented when JWT adapter is ready
		t.Skip("Token validation not yet implemented")
	})

	// Test configuration retrieval
	t.Run("config_retrieval", func(t *testing.T) {
		config := auth.Config()
		testutils.AssertEqual(t, config.Issuer, "integration-test")
		testutils.AssertEqual(t, config.TokenExpiry, 1*time.Hour)
	})

	// Test initialization state
	t.Run("initialization_state", func(t *testing.T) {
		testutils.AssertTrue(t, auth.IsInitialized(), "AuthKit should be initialized")
	})

	// Test cleanup
	t.Run("cleanup", func(t *testing.T) {
		err := auth.Close()
		testutils.AssertNoError(t, err)
	})

	_ = user // use the user variable to avoid unused variable error
	_ = ctx  // use the ctx variable to avoid unused variable error
}

func TestAuthKit_Integration_ErrorHandling(t *testing.T) {
	// Test invalid configuration
	t.Run("invalid_config", func(t *testing.T) {
		config := authkit.DefaultConfig()
		config.Issuer = "" // Invalid
		config.JWTSecret = []byte("test")

		err := config.Validate()
		testutils.AssertError(t, err, true, "INVALID_CONFIG")
	})

	// Test missing JWT secret
	t.Run("missing_jwt_secret", func(t *testing.T) {
		config := authkit.DefaultConfig()
		// No JWT secret set

		err := config.Validate()
		testutils.AssertError(t, err, true, "INVALID_CONFIG")
	})
}

func TestAuthKit_Integration_ContextHelpers(t *testing.T) {
	ctx := context.Background()

	// Test user context
	t.Run("user_context", func(t *testing.T) {
		user := testutils.TestUser("ctx-user-123")

		// Add user to context
		ctxWithUser := authkit.WithUser(ctx, user)

		// Retrieve user from context
		retrievedUser, ok := authkit.GetUserFromContext(ctxWithUser)
		testutils.AssertTrue(t, ok, "Should retrieve user from context")
		testutils.AssertEqual(t, retrievedUser.ID, user.ID)
	})

	// Test claims context
	t.Run("claims_context", func(t *testing.T) {
		claims := testutils.TestClaims("ctx-user-123", "test")

		// Add claims to context
		ctxWithClaims := authkit.WithClaims(ctx, claims)

		// Retrieve claims from context
		retrievedClaims, ok := authkit.GetClaimsFromContext(ctxWithClaims)
		testutils.AssertTrue(t, ok, "Should retrieve claims from context")
		testutils.AssertEqual(t, retrievedClaims.Subject, claims.Subject)
	})

	// Test token context
	t.Run("token_context", func(t *testing.T) {
		token := "test-token-123"

		// Add token to context
		ctxWithToken := authkit.WithToken(ctx, token)

		// Retrieve token from context
		retrievedToken, ok := authkit.GetTokenFromContext(ctxWithToken)
		testutils.AssertTrue(t, ok, "Should retrieve token from context")
		testutils.AssertEqual(t, retrievedToken, token)
	})

	// Test scopes context
	t.Run("scopes_context", func(t *testing.T) {
		scopes := []string{"read", "write", "admin"}

		// Add scopes to context
		ctxWithScopes := authkit.WithScopes(ctx, scopes)

		// Retrieve scopes from context
		retrievedScopes, ok := authkit.GetScopesFromContext(ctxWithScopes)
		testutils.AssertTrue(t, ok, "Should retrieve scopes from context")
		testutils.AssertEqual(t, len(retrievedScopes), len(scopes))
		testutils.AssertEqual(t, retrievedScopes[0], scopes[0])
	})
}
