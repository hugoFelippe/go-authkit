package authkit_test

import (
	"testing"

	"github.com/hugoFelippe/go-authkit"
)

func TestSimpleConfig(t *testing.T) {
	config := authkit.DefaultConfig()
	if config.Issuer != "authkit" {
		t.Errorf("Expected issuer 'authkit', got '%s'", config.Issuer)
	}
}

func TestSimpleAuthKit(t *testing.T) {
	auth := authkit.New(
		authkit.WithIssuer("test"),
		authkit.WithJWTSecret([]byte("test-secret-key-for-testing-purposes")),
	)

	if !auth.IsInitialized() {
		t.Error("AuthKit should be initialized")
	}

	err := auth.Close()
	if err != nil {
		t.Errorf("Error closing AuthKit: %v", err)
	}
}
