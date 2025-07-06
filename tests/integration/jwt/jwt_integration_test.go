package jwt_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/hugoFelippe/go-authkit/contracts"
	"github.com/hugoFelippe/go-authkit/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// JWTIntegrationSuite testa a integração completa do JWT Manager
type JWTIntegrationSuite struct {
	suite.Suite
	ctx        context.Context
	jwtManager *token.JWTManager
	testUser   *contracts.User
}

func (suite *JWTIntegrationSuite) SetupSuite() {
	suite.ctx = context.Background()

	// Criar usuário de teste
	suite.testUser = &contracts.User{
		ID:          "test-user-123",
		Username:    "testuser",
		Email:       "test@example.com",
		Name:        "Test User",
		Roles:       []string{"user", "admin"},
		Permissions: []string{"read", "write"},
		Active:      true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

func (suite *JWTIntegrationSuite) SetupTest() {
	// Configurar JWT Manager para cada teste
	config := &token.JWTConfig{
		Issuer:        "test-issuer",
		SigningMethod: "HS256",
		SecretKey:     []byte("test-secret-key-for-integration-testing-12345"),
		TokenExpiry:   15 * time.Minute,
		RefreshExpiry: 24 * time.Hour,
	}

	var err error
	suite.jwtManager, err = token.NewJWTManager(config)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), suite.jwtManager)
}

func (suite *JWTIntegrationSuite) TestJWTFullPipeline() {
	// 1. Gerar token JWT usando o usuário de teste
	tokenString, err := suite.jwtManager.GenerateToken(suite.ctx, suite.testUser)
	require.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), tokenString)

	// 2. Validar token gerado
	validatedClaims, err := suite.jwtManager.ValidateToken(suite.ctx, tokenString)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), validatedClaims)

	// 3. Verificar se as claims foram preservadas
	assert.Equal(suite.T(), suite.testUser.ID, validatedClaims.Subject)
	assert.Equal(suite.T(), suite.testUser.Email, validatedClaims.Email)
	assert.Equal(suite.T(), suite.testUser.Username, validatedClaims.Username)
	assert.Equal(suite.T(), suite.testUser.Name, validatedClaims.Name)
	assert.Equal(suite.T(), suite.testUser.Roles, validatedClaims.Roles)
}

func (suite *JWTIntegrationSuite) TestJWTRefreshToken() {
	// 1. Gerar refresh token para usuário
	refreshToken, err := suite.jwtManager.GenerateRefreshToken(suite.ctx, suite.testUser)
	require.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), refreshToken)

	// 2. Usar refresh token para gerar novo access token
	accessToken, newRefreshToken, err := suite.jwtManager.RefreshToken(suite.ctx, refreshToken)
	require.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), accessToken)
	assert.NotEmpty(suite.T(), newRefreshToken)
	assert.NotEqual(suite.T(), refreshToken, newRefreshToken)

	// 3. Validar o novo access token
	claims, err := suite.jwtManager.ValidateToken(suite.ctx, accessToken)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), suite.testUser.ID, claims.Subject)
}

func (suite *JWTIntegrationSuite) TestJWTInvalidTokens() {
	testCases := []struct {
		name     string
		token    string
		errorMsg string
	}{
		{
			name:     "empty token",
			token:    "",
			errorMsg: "token is empty",
		},
		{
			name:     "malformed token",
			token:    "invalid-token",
			errorMsg: "token contains an invalid number of segments",
		},
		{
			name:     "token with invalid signature",
			token:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid-signature",
			errorMsg: "signature is invalid",
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			claims, err := suite.jwtManager.ValidateToken(suite.ctx, tc.token)
			assert.Error(t, err)
			assert.Nil(t, claims)
		})
	}
}

func (suite *JWTIntegrationSuite) TestJWTWithRSA() {
	// Gerar chaves RSA para teste
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(suite.T(), err)

	// Serializar chaves em formato PEM
	privateKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(suite.T(), err)

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Configurar JWT Manager com RSA
	rsaConfig := &token.JWTConfig{
		Issuer:        "test-issuer",
		SigningMethod: "RS256",
		PrivateKey:    privateKeyBytes,
		PublicKey:     publicKeyPEM,
		TokenExpiry:   15 * time.Minute,
	}

	rsaManager, err := token.NewJWTManager(rsaConfig)
	require.NoError(suite.T(), err)

	// Gerar e validar token com RSA
	tokenString, err := rsaManager.GenerateToken(suite.ctx, suite.testUser)
	require.NoError(suite.T(), err)

	validatedClaims, err := rsaManager.ValidateToken(suite.ctx, tokenString)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), suite.testUser.ID, validatedClaims.Subject)
	assert.Equal(suite.T(), suite.testUser.Email, validatedClaims.Email)
}

func (suite *JWTIntegrationSuite) TestJWTIntrospection() {
	// Gerar token
	tokenString, err := suite.jwtManager.GenerateToken(suite.ctx, suite.testUser)
	require.NoError(suite.T(), err)

	// Fazer introspecção do token
	tokenInfo, err := suite.jwtManager.IntrospectToken(suite.ctx, tokenString)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), tokenInfo)

	// Verificar informações do token
	assert.True(suite.T(), tokenInfo.Active)
	assert.Equal(suite.T(), contracts.TokenTypeJWT, tokenInfo.Type)
	assert.Equal(suite.T(), suite.testUser.ID, tokenInfo.Subject)
	assert.Equal(suite.T(), "test-issuer", tokenInfo.Issuer)
	assert.NotNil(suite.T(), tokenInfo.ExpiresAt)
	assert.NotNil(suite.T(), tokenInfo.IssuedAt)
}

func (suite *JWTIntegrationSuite) TestJWTRevokeToken() {
	// Gerar token
	tokenString, err := suite.jwtManager.GenerateToken(suite.ctx, suite.testUser)
	require.NoError(suite.T(), err)

	// Validar que o token funciona antes da revogação
	validatedClaims, err := suite.jwtManager.ValidateToken(suite.ctx, tokenString)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), suite.testUser.ID, validatedClaims.Subject)

	// Tentar revogar token - deve falhar porque requer storage externo
	err = suite.jwtManager.RevokeToken(suite.ctx, tokenString)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "token revocation requires external storage implementation")
}

func (suite *JWTIntegrationSuite) TestJWTRevokeAllTokens() {
	// Gerar múltiplos tokens para o mesmo usuário
	var tokens []string
	for i := 0; i < 3; i++ {
		tokenString, err := suite.jwtManager.GenerateToken(suite.ctx, suite.testUser)
		require.NoError(suite.T(), err)
		tokens = append(tokens, tokenString)
	}

	// Validar que todos os tokens funcionam
	for _, token := range tokens {
		claims, err := suite.jwtManager.ValidateToken(suite.ctx, token)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), suite.testUser.ID, claims.Subject)
	}

	// Tentar revogar todos os tokens do usuário - deve falhar porque requer storage externo
	err := suite.jwtManager.RevokeAllTokens(suite.ctx, suite.testUser.ID)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "token revocation requires external storage implementation")
}

func (suite *JWTIntegrationSuite) TestJWTValidateRefreshToken() {
	// Gerar refresh token
	refreshToken, err := suite.jwtManager.GenerateRefreshToken(suite.ctx, suite.testUser)
	require.NoError(suite.T(), err)

	// Validar refresh token
	claims, err := suite.jwtManager.ValidateRefreshToken(suite.ctx, refreshToken)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), suite.testUser.ID, claims.Subject)
	assert.Equal(suite.T(), "test-issuer", claims.Issuer)
}

func (suite *JWTIntegrationSuite) TestJWTGetTokenType() {
	tokenType := suite.jwtManager.GetTokenType()
	assert.Equal(suite.T(), "JWT", tokenType)
}

func TestJWTIntegrationSuite(t *testing.T) {
	suite.Run(t, new(JWTIntegrationSuite))
}
