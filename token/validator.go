package token

import (
	"context"
	"fmt"
	"time"

	"github.com/hugoFelippe/go-authkit/contracts"
)

// ValidatorChain permite criar uma cadeia de validators
type ValidatorChain struct {
	validators []contracts.Validator
}

// NewValidatorChain cria uma nova cadeia de validators
func NewValidatorChain(validators ...contracts.Validator) *ValidatorChain {
	return &ValidatorChain{
		validators: validators,
	}
}

// ValidateToken tenta validar o token usando cada validator na cadeia
func (c *ValidatorChain) ValidateToken(ctx context.Context, tokenString string) (*contracts.Claims, error) {
	if len(c.validators) == 0 {
		return nil, contracts.ErrInvalidToken
	}

	var lastErr error
	for _, validator := range c.validators {
		claims, err := validator.ValidateToken(ctx, tokenString)
		if err == nil {
			return claims, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("validation failed with all validators: %w", lastErr)
}

// GetTokenType retorna os tipos suportados pela cadeia
func (c *ValidatorChain) GetTokenType() string {
	if len(c.validators) == 0 {
		return "unknown"
	}
	return "multi"
}

// AddValidator adiciona um validator à cadeia
func (c *ValidatorChain) AddValidator(validator contracts.Validator) {
	c.validators = append(c.validators, validator)
}

// ContextValidator permite validação context-aware
type ContextValidator struct {
	validator    contracts.Validator
	contextCheck func(ctx context.Context, claims *contracts.Claims) error
}

// NewContextValidator cria um validator que considera context
func NewContextValidator(validator contracts.Validator, contextCheck func(ctx context.Context, claims *contracts.Claims) error) *ContextValidator {
	return &ContextValidator{
		validator:    validator,
		contextCheck: contextCheck,
	}
}

// ValidateToken valida o token e aplica verificações de contexto
func (cv *ContextValidator) ValidateToken(ctx context.Context, tokenString string) (*contracts.Claims, error) {
	claims, err := cv.validator.ValidateToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	if cv.contextCheck != nil {
		if err := cv.contextCheck(ctx, claims); err != nil {
			return nil, fmt.Errorf("context validation failed: %w", err)
		}
	}

	return claims, nil
}

// GetTokenType retorna o tipo do validator base
func (cv *ContextValidator) GetTokenType() string {
	return cv.validator.GetTokenType()
}

// CachingValidator adiciona cache de validação
type CachingValidator struct {
	validator contracts.Validator
	cache     contracts.ValidationCache
}

// NewCachingValidator cria um validator com cache
func NewCachingValidator(validator contracts.Validator, cache contracts.ValidationCache) *CachingValidator {
	return &CachingValidator{
		validator: validator,
		cache:     cache,
	}
}

// ValidateToken valida usando cache quando possível
func (cv *CachingValidator) ValidateToken(ctx context.Context, tokenString string) (*contracts.Claims, error) {
	// Tentar obter do cache primeiro
	if cv.cache != nil {
		if claims, found := cv.cache.Get(ctx, tokenString); found {
			return claims, nil
		}
	}

	// Validar usando o validator base
	claims, err := cv.validator.ValidateToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	// Armazenar no cache se a validação foi bem-sucedida
	if cv.cache != nil && claims != nil {
		ttl := time.Until(claims.ExpiresAt)
		if ttl > 0 {
			cv.cache.Set(ctx, tokenString, claims, ttl)
		}
	}

	return claims, nil
}

// GetTokenType retorna o tipo do validator base
func (cv *CachingValidator) GetTokenType() string {
	return cv.validator.GetTokenType()
}
