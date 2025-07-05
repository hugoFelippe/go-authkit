package testdata

// TestJWTSecrets contém chaves de teste para JWT
var TestJWTSecrets = map[string][]byte{
	"HS256": []byte("test-secret-key-for-hs256-that-is-long-enough-for-testing"),
	"HS384": []byte("test-secret-key-for-hs384-that-is-long-enough-for-testing-and-more"),
	"HS512": []byte("test-secret-key-for-hs512-that-is-long-enough-for-testing-and-even-more"),
}

// TestAPIKeys contém chaves de API de teste
var TestAPIKeys = []string{
	"test-api-key-1234567890abcdef",
	"test-api-key-abcdef1234567890",
	"test-api-key-fedcba0987654321",
}

// TestUsers contém usuários de teste
var TestUsers = map[string]map[string]interface{}{
	"admin": {
		"id":       "admin-user-123",
		"username": "admin",
		"email":    "admin@example.com",
		"name":     "Administrator",
		"roles":    []string{"admin", "user"},
		"active":   true,
	},
	"user": {
		"id":       "regular-user-456",
		"username": "user",
		"email":    "user@example.com",
		"name":     "Regular User",
		"roles":    []string{"user"},
		"active":   true,
	},
	"inactive": {
		"id":       "inactive-user-789",
		"username": "inactive",
		"email":    "inactive@example.com",
		"name":     "Inactive User",
		"roles":    []string{"user"},
		"active":   false,
	},
}

// TestScopes contém escopos de teste para OAuth2 e API Keys
var TestScopes = []string{
	"read",
	"write",
	"admin",
	"read:users",
	"write:users",
	"read:posts",
	"write:posts",
	"delete:posts",
}
