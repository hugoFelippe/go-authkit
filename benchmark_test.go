package authkit_test

import (
	"context"
	"testing"

	"github.com/hugoFelippe/go-authkit"
	"github.com/hugoFelippe/go-authkit/tests/testutils"
)

func BenchmarkAuthKit_Config(b *testing.B) {
	b.Run("DefaultConfig", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = authkit.DefaultConfig()
		}
	})

	b.Run("ConfigValidation", func(b *testing.B) {
		config := authkit.DefaultConfig()
		config.JWTSecret = []byte("benchmark-secret-key")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = config.Validate()
		}
	})
}

func BenchmarkAuthKit_Types(b *testing.B) {
	b.Run("UserCreation", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = testutils.TestUser("bench-user")
		}
	})

	b.Run("ClaimsCreation", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = testutils.TestClaims("bench-user", "bench-issuer")
		}
	})

	b.Run("APIKeyCreation", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = testutils.TestAPIKey("bench-key", "bench-user")
		}
	})
}

func BenchmarkAuthKit_Context(b *testing.B) {
	ctx := context.Background()
	user := testutils.TestUser("bench-user")
	claims := testutils.TestClaims("bench-user", "bench-issuer")
	token := "bench-token"
	scopes := []string{"read", "write"}

	b.Run("WithUser", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = authkit.WithUser(ctx, user)
		}
	})

	b.Run("WithClaims", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = authkit.WithClaims(ctx, claims)
		}
	})

	b.Run("WithToken", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = authkit.WithToken(ctx, token)
		}
	})

	b.Run("WithScopes", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = authkit.WithScopes(ctx, scopes)
		}
	})

	// Context retrieval benchmarks
	ctxWithUser := authkit.WithUser(ctx, user)
	ctxWithClaims := authkit.WithClaims(ctx, claims)
	ctxWithToken := authkit.WithToken(ctx, token)
	ctxWithScopes := authkit.WithScopes(ctx, scopes)

	b.Run("GetUserFromContext", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = authkit.GetUserFromContext(ctxWithUser)
		}
	})

	b.Run("GetClaimsFromContext", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = authkit.GetClaimsFromContext(ctxWithClaims)
		}
	})

	b.Run("GetTokenFromContext", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = authkit.GetTokenFromContext(ctxWithToken)
		}
	})

	b.Run("GetScopesFromContext", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = authkit.GetScopesFromContext(ctxWithScopes)
		}
	})
}

func BenchmarkAuthKit_Errors(b *testing.B) {
	b.Run("ErrorCreation", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = authkit.ErrInvalidTokenWithDetails("benchmark error")
		}
	})

	b.Run("ErrorTypeCheck", func(b *testing.B) {
		err := authkit.ErrInvalidToken
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = authkit.IsAuthError(err)
		}
	})

	b.Run("ErrorCodeExtraction", func(b *testing.B) {
		err := authkit.ErrInvalidToken
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = authkit.GetErrorCode(err)
		}
	})

	b.Run("TokenErrorCheck", func(b *testing.B) {
		err := authkit.ErrInvalidToken
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = authkit.IsTokenError(err)
		}
	})
}
