package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hugoFelippe/go-authkit/contracts"
)

// JWTManager implementa TokenManager usando golang-jwt/jwt
type JWTManager struct {
	config       *JWTConfig
	signingKey   interface{}
	verifyingKey interface{}
	method       jwt.SigningMethod
}

// JWTConfig configuração para JWT
type JWTConfig struct {
	Issuer          string
	SigningMethod   string
	SecretKey       []byte
	PrivateKey      []byte
	PublicKey       []byte
	TokenExpiry     time.Duration
	RefreshExpiry   time.Duration
	AllowedIssuers  []string
	RequiredClaims  []string
	SkipClaimsCheck bool
}

// NewJWTManager cria um novo gerenciador JWT
func NewJWTManager(config *JWTConfig) (*JWTManager, error) {
	if config == nil {
		return nil, fmt.Errorf("JWT config cannot be nil")
	}

	manager := &JWTManager{
		config: config,
	}

	// Configurar método de assinatura
	if err := manager.setupSigningMethod(); err != nil {
		return nil, fmt.Errorf("failed to setup signing method: %w", err)
	}

	return manager, nil
}

// setupSigningMethod configura o método de assinatura baseado na configuração
func (m *JWTManager) setupSigningMethod() error {
	switch m.config.SigningMethod {
	case "HS256":
		m.method = jwt.SigningMethodHS256
		if len(m.config.SecretKey) == 0 {
			return fmt.Errorf("secret key is required for HMAC signing")
		}
		m.signingKey = m.config.SecretKey
		m.verifyingKey = m.config.SecretKey

	case "HS384":
		m.method = jwt.SigningMethodHS384
		if len(m.config.SecretKey) == 0 {
			return fmt.Errorf("secret key is required for HMAC signing")
		}
		m.signingKey = m.config.SecretKey
		m.verifyingKey = m.config.SecretKey

	case "HS512":
		m.method = jwt.SigningMethodHS512
		if len(m.config.SecretKey) == 0 {
			return fmt.Errorf("secret key is required for HMAC signing")
		}
		m.signingKey = m.config.SecretKey
		m.verifyingKey = m.config.SecretKey

	case "RS256":
		m.method = jwt.SigningMethodRS256
		return m.setupRSAKeys()

	case "RS384":
		m.method = jwt.SigningMethodRS384
		return m.setupRSAKeys()

	case "RS512":
		m.method = jwt.SigningMethodRS512
		return m.setupRSAKeys()

	default:
		return fmt.Errorf("unsupported signing method: %s", m.config.SigningMethod)
	}

	return nil
}

// setupRSAKeys configura chaves RSA para assinatura
func (m *JWTManager) setupRSAKeys() error {
	if len(m.config.PrivateKey) == 0 {
		return fmt.Errorf("private key is required for RSA signing")
	}

	// Parse private key
	block, _ := pem.Decode(m.config.PrivateKey)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key is not RSA")
		}
	}

	m.signingKey = privateKey

	// Setup public key for verification
	if len(m.config.PublicKey) > 0 {
		block, _ := pem.Decode(m.config.PublicKey)
		if block == nil {
			return fmt.Errorf("failed to parse PEM block containing public key")
		}

		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %w", err)
		}

		rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("public key is not RSA")
		}

		m.verifyingKey = rsaPublicKey
	} else {
		// Use public key from private key
		m.verifyingKey = &privateKey.PublicKey
	}

	return nil
}

// GenerateToken gera um novo JWT token para um usuário
func (m *JWTManager) GenerateToken(ctx context.Context, user *contracts.User) (string, error) {
	now := time.Now()
	expiresAt := now.Add(m.config.TokenExpiry)

	claims := jwt.MapClaims{
		"iss": m.config.Issuer,
		"sub": user.ID,
		"iat": now.Unix(),
		"exp": expiresAt.Unix(),
		"jti": generateJTI(),
	}

	// Adicionar claims do usuário
	if user.Email != "" {
		claims["email"] = user.Email
	}
	if user.Name != "" {
		claims["name"] = user.Name
	}
	if user.Username != "" {
		claims["username"] = user.Username
	}
	if len(user.Roles) > 0 {
		claims["roles"] = user.Roles
	}

	token := jwt.NewWithClaims(m.method, claims)
	tokenString, err := token.SignedString(m.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// GenerateRefreshToken gera um refresh token
func (m *JWTManager) GenerateRefreshToken(ctx context.Context, user *contracts.User) (string, error) {
	now := time.Now()
	expiresAt := now.Add(m.config.RefreshExpiry)

	claims := jwt.MapClaims{
		"iss":  m.config.Issuer,
		"sub":  user.ID,
		"iat":  now.Unix(),
		"exp":  expiresAt.Unix(),
		"jti":  generateJTI(),
		"type": "refresh",
	}

	token := jwt.NewWithClaims(m.method, claims)
	tokenString, err := token.SignedString(m.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken valida um JWT token
func (m *JWTManager) ValidateToken(ctx context.Context, tokenString string) (*contracts.Claims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verificar método de assinatura
		if token.Method != m.method {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.verifyingKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, contracts.ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, contracts.ErrInvalidToken
	}

	return m.mapClaimsToAuthClaims(claims)
}

// ValidateRefreshToken valida um refresh token
func (m *JWTManager) ValidateRefreshToken(ctx context.Context, tokenString string) (*contracts.Claims, error) {
	claims, err := m.ValidateToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	// Verificar se é um refresh token através do metadata
	if tokenType, ok := claims.Metadata["type"].(string); !ok || tokenType != "refresh" {
		return nil, fmt.Errorf("token is not a refresh token")
	}

	return claims, nil
}

// IntrospectToken retorna informações sobre o token
func (m *JWTManager) IntrospectToken(ctx context.Context, tokenString string) (*contracts.TokenInfo, error) {
	claims, err := m.ValidateToken(ctx, tokenString)
	if err != nil {
		return &contracts.TokenInfo{
			Type: contracts.TokenTypeJWT,
			Extra: map[string]interface{}{
				"error": err.Error(),
			},
		}, nil
	}

	return &contracts.TokenInfo{
		Type:      contracts.TokenTypeJWT,
		Active:    true,
		Subject:   claims.Subject,
		Issuer:    claims.Issuer,
		ExpiresAt: &claims.ExpiresAt,
		IssuedAt:  &claims.IssuedAt,
		Scopes:    claims.Scopes,
		Extra: map[string]interface{}{
			"issuer":  claims.Issuer,
			"subject": claims.Subject,
		},
	}, nil
}

// RevokeToken revoga um token (implementação base - requer storage externo)
func (m *JWTManager) RevokeToken(ctx context.Context, tokenString string) error {
	// JWT tokens são stateless, então revogação requer uma blacklist
	// Esta implementação base apenas valida o token
	_, err := m.ValidateToken(ctx, tokenString)
	if err != nil {
		return fmt.Errorf("cannot revoke invalid token: %w", err)
	}

	// TODO: Implementar com storage externo para blacklist
	return fmt.Errorf("token revocation requires external storage implementation")
}

// RevokeAllTokens revoga todos os tokens de um usuário
func (m *JWTManager) RevokeAllTokens(ctx context.Context, userID string) error {
	// Requer storage externo para implementar
	return fmt.Errorf("token revocation requires external storage implementation")
}

// RefreshToken gera um novo access token usando refresh token
func (m *JWTManager) RefreshToken(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error) {
	// Validar refresh token
	claims, err := m.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return "", "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Criar usuário a partir dos claims
	user := &contracts.User{
		ID:        claims.Subject,
		Name:      claims.Name,
		Email:     claims.Email,
		Username:  claims.Username,
		Roles:     claims.Roles,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Gerar novo access token
	accessToken, err = m.GenerateToken(ctx, user)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate new access token: %w", err)
	}

	// Gerar novo refresh token
	newRefreshToken, err = m.GenerateRefreshToken(ctx, user)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate new refresh token: %w", err)
	}

	return accessToken, newRefreshToken, nil
}

// GetTokenType retorna o tipo de token suportado
func (m *JWTManager) GetTokenType() string {
	return "JWT"
}

// mapClaimsToAuthClaims converte jwt.MapClaims para Claims
func (m *JWTManager) mapClaimsToAuthClaims(claims jwt.MapClaims) (*contracts.Claims, error) {
	authClaims := &contracts.Claims{
		Metadata: make(map[string]interface{}),
	}

	// Claims padrão
	if sub, ok := claims["sub"].(string); ok {
		authClaims.Subject = sub
	}

	if iss, ok := claims["iss"].(string); ok {
		authClaims.Issuer = iss
	}

	if exp, ok := claims["exp"].(float64); ok {
		authClaims.ExpiresAt = time.Unix(int64(exp), 0)
	}

	if iat, ok := claims["iat"].(float64); ok {
		authClaims.IssuedAt = time.Unix(int64(iat), 0)
	}

	if jti, ok := claims["jti"].(string); ok {
		authClaims.ID = jti
	}

	// Audience
	if aud, ok := claims["aud"]; ok {
		switch v := aud.(type) {
		case string:
			authClaims.Audience = []string{v}
		case []interface{}:
			for _, a := range v {
				if s, ok := a.(string); ok {
					authClaims.Audience = append(authClaims.Audience, s)
				}
			}
		case []string:
			authClaims.Audience = v
		}
	}

	// Scopes
	if scope, ok := claims["scope"]; ok {
		switch v := scope.(type) {
		case string:
			authClaims.Scopes = []string{v}
		case []interface{}:
			for _, s := range v {
				if str, ok := s.(string); ok {
					authClaims.Scopes = append(authClaims.Scopes, str)
				}
			}
		case []string:
			authClaims.Scopes = v
		}
	}

	// Claims extras
	for k, v := range claims {
		switch k {
		case "sub", "iss", "exp", "iat", "jti", "aud", "scope":
			// Já processados acima
			continue
		case "email":
			if email, ok := v.(string); ok {
				authClaims.Email = email
			}
		case "name":
			if name, ok := v.(string); ok {
				authClaims.Name = name
			}
		case "username":
			if username, ok := v.(string); ok {
				authClaims.Username = username
			}
		case "roles":
			if roles, ok := v.([]interface{}); ok {
				for _, role := range roles {
					if roleStr, ok := role.(string); ok {
						authClaims.Roles = append(authClaims.Roles, roleStr)
					}
				}
			}
		default:
			authClaims.Metadata[k] = v
		}
	}

	return authClaims, nil
}

// generateJTI gera um ID único para o token
func generateJTI() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// DefaultJWTConfig retorna configuração padrão para JWT
func DefaultJWTConfig() *JWTConfig {
	return &JWTConfig{
		Issuer:        "authkit",
		SigningMethod: "HS256",
		TokenExpiry:   15 * time.Minute,
		RefreshExpiry: 24 * time.Hour,
	}
}
