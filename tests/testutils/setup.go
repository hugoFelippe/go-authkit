package testutils

import (
	"context"
	"testing"
	"time"

	"github.com/hugoFelippe/go-authkit"
	"github.com/hugoFelippe/go-authkit/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SetupTestAuth creates a test AuthKit instance with sensible defaults
func SetupTestAuth(t *testing.T, opts ...authkit.Option) *authkit.AuthKit {
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

// TestUser creates a test user with default values
func TestUser(id string) *contracts.User {
	now := time.Now()
	return &contracts.User{
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

// TestUserWithRoles creates a test user with specific roles
func TestUserWithRoles(id string, roles []string) *contracts.User {
	user := TestUser(id)
	user.Roles = roles
	return user
}

// TestAPIKey creates a test API key
func TestAPIKey(id, userID string) *contracts.APIKey {
	now := time.Now()
	return &contracts.APIKey{
		ID:        id,
		Key:       "test-api-key-" + id,
		Name:      "Test API Key " + id,
		UserID:    userID,
		Scopes:    []string{"read", "write"},
		Active:    true,
		CreatedAt: now,
		ExpiresAt: &now,
	}
}

// TestClaims creates test claims
func TestClaims(subject, issuer string) *contracts.Claims {
	now := time.Now()
	return &contracts.Claims{
		Subject:   subject,
		Issuer:    issuer,
		Email:     "test@example.com",
		Username:  "testuser",
		Roles:     []string{"user"},
		IssuedAt:  now,
		ExpiresAt: now.Add(1 * time.Hour),
	}
}

// AssertError checks if an error is of the expected type and code
func AssertError(t *testing.T, err error, wantErr bool, expectedCode string) {
	t.Helper()

	if wantErr && err == nil {
		t.Error("expected error but got none")
		return
	}

	if !wantErr && err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	if wantErr && expectedCode != "" {
		if !contracts.IsAuthError(err) {
			t.Errorf("expected AuthError, got %T", err)
			return
		}

		actualCode := contracts.GetErrorCode(err)
		if actualCode != expectedCode {
			t.Errorf("expected error code %s, got %s", expectedCode, actualCode)
		}
	}
}

// AssertNoError is a helper that fails the test if err is not nil
func AssertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// AssertEqual checks if two values are equal
func AssertEqual(t *testing.T, got, want interface{}) {
	t.Helper()
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

// AssertNotEmpty checks if a string is not empty
func AssertNotEmpty(t *testing.T, value, fieldName string) {
	t.Helper()
	if value == "" {
		t.Errorf("%s should not be empty", fieldName)
	}
}

// AssertTrue checks if a condition is true
func AssertTrue(t *testing.T, condition bool, message string) {
	t.Helper()
	if !condition {
		t.Error(message)
	}
}

// AssertFalse checks if a condition is false
func AssertFalse(t *testing.T, condition bool, message string) {
	t.Helper()
	if condition {
		t.Error(message)
	}
}

// AssertValidToken validates that a token is valid and contains expected claims
func AssertValidToken(t *testing.T, auth *authkit.AuthKit, token string, expectedUserID string) *contracts.Claims {
	t.Helper()

	claims, err := auth.ValidateToken(context.Background(), token)
	require.NoError(t, err, "Token validation should not fail")
	require.NotNil(t, claims, "Claims should not be nil")

	if expectedUserID != "" {
		assert.Equal(t, expectedUserID, claims.Subject, "User ID should match")
	}

	return claims
}

// AssertTokenGeneration generates a token and validates its basic properties
func AssertTokenGeneration(t *testing.T, auth *authkit.AuthKit, user *contracts.User) string {
	t.Helper()

	// Convert user to claims
	claims := &contracts.Claims{
		Subject:   user.ID,
		Email:     user.Email,
		Username:  user.Username,
		Name:      user.Name,
		Roles:     user.Roles,
		Issuer:    "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	token, err := auth.GenerateToken(context.Background(), claims)
	require.NoError(t, err, "Token generation should not fail")
	require.NotEmpty(t, token, "Token should not be empty")

	// Validate the generated token
	validatedClaims := AssertValidToken(t, auth, token, user.ID)
	assert.Equal(t, user.ID, validatedClaims.Subject)

	return token
}

// AssertInvalidToken validates that a token is invalid
func AssertInvalidToken(t *testing.T, auth *authkit.AuthKit, token string, expectedErrorCode string) {
	t.Helper()

	claims, err := auth.ValidateToken(context.Background(), token)
	assert.Error(t, err, "Token validation should fail")
	assert.Nil(t, claims, "Claims should be nil for invalid token")

	if expectedErrorCode != "" {
		assert.Equal(t, expectedErrorCode, contracts.GetErrorCode(err))
	}
}

// AssertJWTClaims validates specific JWT claims
func AssertJWTClaims(t *testing.T, claims *contracts.Claims, expectedIssuer string, expectedAudience []string) {
	t.Helper()

	require.NotNil(t, claims, "Claims should not be nil")

	if expectedIssuer != "" {
		assert.Equal(t, expectedIssuer, claims.Issuer)
	}

	if len(expectedAudience) > 0 {
		assert.Equal(t, expectedAudience, claims.Audience)
	}

	assert.True(t, claims.ExpiresAt.After(time.Now()), "Token should not be expired")
	assert.True(t, claims.IssuedAt.Before(time.Now().Add(time.Second)), "IssuedAt should be in the past")
}
