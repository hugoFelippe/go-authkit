package token

import (
	"time"

	"github.com/hugoFelippe/go-authkit/contracts"
)

// WithExpiry define tempo de expiração customizado
func WithExpiry(expiry time.Duration) contracts.GenerateOption {
	return func(o *contracts.GenerateOptions) {
		expiresAt := time.Now().Add(expiry)
		o.ExpiresAt = &expiresAt
	}
}

// WithExpiresAt define timestamp exato de expiração
func WithExpiresAt(expiresAt time.Time) contracts.GenerateOption {
	return func(o *contracts.GenerateOptions) {
		o.ExpiresAt = &expiresAt
	}
}

// WithAudience define audience para o token
func WithAudience(audience ...string) contracts.GenerateOption {
	return func(o *contracts.GenerateOptions) {
		o.Audience = audience
	}
}

// WithScopes define escopos para o token
func WithScopes(scopes ...string) contracts.GenerateOption {
	return func(o *contracts.GenerateOptions) {
		o.Scopes = scopes
	}
}

// WithCustomClaims adiciona claims customizados
func WithCustomClaims(claims map[string]interface{}) contracts.GenerateOption {
	return func(o *contracts.GenerateOptions) {
		if o.CustomClaims == nil {
			o.CustomClaims = make(map[string]interface{})
		}
		for k, v := range claims {
			o.CustomClaims[k] = v
		}
	}
}

// WithTokenType define o tipo do token
func WithTokenType(tokenType string) contracts.GenerateOption {
	return func(o *contracts.GenerateOptions) {
		o.TokenType = tokenType
	}
}

// defaultGenerateOptions retorna opções padrão para geração
func defaultGenerateOptions() *contracts.GenerateOptions {
	return &contracts.GenerateOptions{
		TokenType: "access",
	}
}

// applyGenerateOptions aplica opções de geração
func applyGenerateOptions(options []contracts.GenerateOption) *contracts.GenerateOptions {
	opts := defaultGenerateOptions()
	for _, option := range options {
		option(opts)
	}
	return opts
}
