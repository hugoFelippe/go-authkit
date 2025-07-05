package testutils

import (
	"testing"
	"time"

	"github.com/hugoFelippe/go-authkit"
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
func TestUser(id string) *authkit.User {
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

// TestUserWithRoles creates a test user with specific roles
func TestUserWithRoles(id string, roles []string) *authkit.User {
	user := TestUser(id)
	user.Roles = roles
	return user
}

// TestAPIKey creates a test API key
func TestAPIKey(id, userID string) *authkit.APIKey {
	now := time.Now()
	return &authkit.APIKey{
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
func TestClaims(subject, issuer string) *authkit.Claims {
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
		if !authkit.IsAuthError(err) {
			t.Errorf("expected AuthError, got %T", err)
			return
		}

		actualCode := authkit.GetErrorCode(err)
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
