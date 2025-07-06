package authkit

import (
	"crypto/rsa"
	"time"

	"github.com/hugoFelippe/go-authkit/contracts"
)

// Config contém todas as configurações do AuthKit.
type Config struct {
	// JWT Configuration
	Issuer             string          `json:"issuer"`
	Audience           []string        `json:"audience,omitempty"`
	TokenExpiry        time.Duration   `json:"token_expiry"`
	RefreshTokenExpiry time.Duration   `json:"refresh_token_expiry"`
	JWTSigningMethod   string          `json:"jwt_signing_method"`
	JWTSecret          []byte          `json:"-"` // Para métodos HMAC
	JWTPrivateKey      *rsa.PrivateKey `json:"-"` // Para métodos RSA/ECDSA
	JWTPublicKey       *rsa.PublicKey  `json:"-"` // Para validação RSA/ECDSA

	// API Key Configuration
	APIKeyPrefix     string        `json:"api_key_prefix,omitempty"`
	APIKeyLength     int           `json:"api_key_length"`
	APIKeyExpiry     time.Duration `json:"api_key_expiry,omitempty"`
	APIKeyLocation   string        `json:"api_key_location"` // header, query, body
	APIKeyHeaderName string        `json:"api_key_header_name"`
	APIKeyQueryParam string        `json:"api_key_query_param"`

	// OAuth2/OIDC Configuration
	OAuth2ClientID     string   `json:"oauth2_client_id,omitempty"`
	OAuth2ClientSecret string   `json:"oauth2_client_secret,omitempty"`
	OAuth2RedirectURL  string   `json:"oauth2_redirect_url,omitempty"`
	OAuth2Scopes       []string `json:"oauth2_scopes,omitempty"`
	OAuth2AuthURL      string   `json:"oauth2_auth_url,omitempty"`
	OAuth2TokenURL     string   `json:"oauth2_token_url,omitempty"`
	OIDCIssuerURL      string   `json:"oidc_issuer_url,omitempty"`
	OIDCUserInfoURL    string   `json:"oidc_userinfo_url,omitempty"`

	// Middleware Configuration
	TokenSources      []string `json:"token_sources"` // bearer, header, query, cookie
	BearerTokenPrefix string   `json:"bearer_token_prefix"`
	TokenHeaderName   string   `json:"token_header_name"`
	TokenQueryParam   string   `json:"token_query_param"`
	TokenCookieName   string   `json:"token_cookie_name"`
	SkipPaths         []string `json:"skip_paths,omitempty"`

	// Security Configuration
	EnableTokenRevocation   bool          `json:"enable_token_revocation"`
	EnableSessionManagement bool          `json:"enable_session_management"`
	MaxSessionsPerUser      int           `json:"max_sessions_per_user"`
	SessionExpiry           time.Duration `json:"session_expiry"`

	// Storage Configuration
	StorageType   string                 `json:"storage_type"` // memory, redis, database
	StorageConfig map[string]interface{} `json:"storage_config,omitempty"`

	// Validation Configuration
	RequireHTTPS   bool          `json:"require_https"`
	AllowedOrigins []string      `json:"allowed_origins,omitempty"`
	ClockSkew      time.Duration `json:"clock_skew"`

	// Performance Configuration
	CacheEnabled bool          `json:"cache_enabled"`
	CacheTTL     time.Duration `json:"cache_ttl"`
	MaxCacheSize int           `json:"max_cache_size"`

	// Debug Configuration
	Debug    bool   `json:"debug"`
	LogLevel string `json:"log_level"`
}

// Option define uma função de configuração.
type Option func(*Config)

// ErrInvalidConfigWithDetails cria um erro de configuração com detalhes específicos.
func ErrInvalidConfigWithDetails(field, message string) error {
	return contracts.WrapError(
		contracts.ErrCodeConfigurationError,
		"configuration error for field '"+field+"': "+message,
		nil,
	)
}

// DefaultConfig retorna uma configuração padrão.
func DefaultConfig() *Config {
	return &Config{
		// JWT defaults
		Issuer:             "authkit",
		TokenExpiry:        time.Hour * 24,      // 24 horas
		RefreshTokenExpiry: time.Hour * 24 * 30, // 30 dias
		JWTSigningMethod:   "HS256",

		// API Key defaults
		APIKeyLength:     32,
		APIKeyExpiry:     time.Hour * 24 * 365, // 1 ano
		APIKeyLocation:   "header",
		APIKeyHeaderName: "X-API-Key",
		APIKeyQueryParam: "api_key",

		// Middleware defaults
		TokenSources:      []string{"bearer", "header"},
		BearerTokenPrefix: "Bearer",
		TokenHeaderName:   "Authorization",
		TokenQueryParam:   "token",
		TokenCookieName:   "authkit_token",

		// Security defaults
		EnableTokenRevocation:   true,
		EnableSessionManagement: true,
		MaxSessionsPerUser:      5,
		SessionExpiry:           time.Hour * 24 * 7, // 7 dias

		// Storage defaults
		StorageType: "memory",

		// Validation defaults
		RequireHTTPS: false, // Para desenvolvimento
		ClockSkew:    time.Minute * 5,

		// Performance defaults
		CacheEnabled: true,
		CacheTTL:     time.Hour,
		MaxCacheSize: 1000,

		// Debug defaults
		Debug:    false,
		LogLevel: "info",
	}
}

// Validate valida a configuração e retorna erros se inválida.
func (c *Config) Validate() error {
	if c.Issuer == "" {
		return ErrInvalidConfigWithDetails("issuer", "cannot be empty")
	}

	if c.TokenExpiry <= 0 {
		return ErrInvalidConfigWithDetails("token_expiry", "must be positive")
	}

	if c.JWTSigningMethod == "" {
		return ErrInvalidConfigWithDetails("jwt_signing_method", "cannot be empty")
	}

	// Validar método de assinatura JWT
	switch c.JWTSigningMethod {
	case "HS256", "HS384", "HS512":
		if len(c.JWTSecret) == 0 {
			return ErrInvalidConfigWithDetails("jwt_secret", "required for HMAC signing methods")
		}
	case "RS256", "RS384", "RS512":
		if c.JWTPrivateKey == nil {
			return ErrInvalidConfigWithDetails("jwt_private_key", "required for RSA signing methods")
		}
	case "ES256", "ES384", "ES512":
		// TODO: Implementar validação para ECDSA
		return ErrInvalidConfigWithDetails("jwt_signing_method", "ECDSA methods not yet supported")
	default:
		return ErrInvalidConfigWithDetails("jwt_signing_method", "unsupported method")
	}

	if c.APIKeyLength < 16 {
		return ErrInvalidConfigWithDetails("api_key_length", "must be at least 16 characters")
	}

	if c.APIKeyLocation != "" {
		switch c.APIKeyLocation {
		case "header", "query", "body":
			// válido
		default:
			return ErrInvalidConfigWithDetails("api_key_location", "must be 'header', 'query', or 'body'")
		}
	}

	if c.MaxSessionsPerUser < 1 {
		return ErrInvalidConfigWithDetails("max_sessions_per_user", "must be at least 1")
	}

	if c.ClockSkew < 0 {
		return ErrInvalidConfigWithDetails("clock_skew", "cannot be negative")
	}

	return nil
}

// JWT Configuration Options

// WithIssuer define o emissor dos tokens.
func WithIssuer(issuer string) Option {
	return func(c *Config) {
		c.Issuer = issuer
	}
}

// WithAudience define a audiência dos tokens.
func WithAudience(audience ...string) Option {
	return func(c *Config) {
		c.Audience = audience
	}
}

// WithTokenExpiry define o tempo de expiração dos tokens.
func WithTokenExpiry(expiry time.Duration) Option {
	return func(c *Config) {
		c.TokenExpiry = expiry
	}
}

// WithRefreshTokenExpiry define o tempo de expiração dos refresh tokens.
func WithRefreshTokenExpiry(expiry time.Duration) Option {
	return func(c *Config) {
		c.RefreshTokenExpiry = expiry
	}
}

// WithJWTSigningMethod define o método de assinatura JWT.
func WithJWTSigningMethod(method string) Option {
	return func(c *Config) {
		c.JWTSigningMethod = method
	}
}

// WithJWTSecret define o segredo para assinatura HMAC.
func WithJWTSecret(secret []byte) Option {
	return func(c *Config) {
		c.JWTSecret = secret
	}
}

// WithJWTKeys define as chaves RSA para assinatura.
func WithJWTKeys(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) Option {
	return func(c *Config) {
		c.JWTPrivateKey = privateKey
		c.JWTPublicKey = publicKey
	}
}

// API Key Configuration Options

// WithAPIKeyPrefix define o prefixo das API keys.
func WithAPIKeyPrefix(prefix string) Option {
	return func(c *Config) {
		c.APIKeyPrefix = prefix
	}
}

// WithAPIKeyLength define o comprimento das API keys.
func WithAPIKeyLength(length int) Option {
	return func(c *Config) {
		c.APIKeyLength = length
	}
}

// WithAPIKeyExpiry define o tempo de expiração das API keys.
func WithAPIKeyExpiry(expiry time.Duration) Option {
	return func(c *Config) {
		c.APIKeyExpiry = expiry
	}
}

// WithAPIKeyLocation define onde procurar API keys (header, query, body).
func WithAPIKeyLocation(location string) Option {
	return func(c *Config) {
		c.APIKeyLocation = location
	}
}

// WithAPIKeyHeader define o nome do header para API keys.
func WithAPIKeyHeader(header string) Option {
	return func(c *Config) {
		c.APIKeyHeaderName = header
	}
}

// OAuth2/OIDC Configuration Options

// WithOAuth2Client define as credenciais do cliente OAuth2.
func WithOAuth2Client(clientID, clientSecret string) Option {
	return func(c *Config) {
		c.OAuth2ClientID = clientID
		c.OAuth2ClientSecret = clientSecret
	}
}

// WithOAuth2RedirectURL define a URL de redirecionamento OAuth2.
func WithOAuth2RedirectURL(redirectURL string) Option {
	return func(c *Config) {
		c.OAuth2RedirectURL = redirectURL
	}
}

// WithOAuth2Scopes define os escopos OAuth2.
func WithOAuth2Scopes(scopes ...string) Option {
	return func(c *Config) {
		c.OAuth2Scopes = scopes
	}
}

// WithOAuth2URLs define as URLs OAuth2.
func WithOAuth2URLs(authURL, tokenURL string) Option {
	return func(c *Config) {
		c.OAuth2AuthURL = authURL
		c.OAuth2TokenURL = tokenURL
	}
}

// WithOIDCIssuer define o emissor OIDC.
func WithOIDCIssuer(issuerURL string) Option {
	return func(c *Config) {
		c.OIDCIssuerURL = issuerURL
	}
}

// Middleware Configuration Options

// WithTokenSources define onde procurar tokens.
func WithTokenSources(sources ...string) Option {
	return func(c *Config) {
		c.TokenSources = sources
	}
}

// WithBearerPrefix define o prefixo do token Bearer.
func WithBearerPrefix(prefix string) Option {
	return func(c *Config) {
		c.BearerTokenPrefix = prefix
	}
}

// WithTokenHeader define o nome do header para tokens.
func WithTokenHeader(header string) Option {
	return func(c *Config) {
		c.TokenHeaderName = header
	}
}

// WithSkipPaths define caminhos que não requerem autenticação.
func WithSkipPaths(paths ...string) Option {
	return func(c *Config) {
		c.SkipPaths = paths
	}
}

// Security Configuration Options

// WithTokenRevocation habilita/desabilita revogação de tokens.
func WithTokenRevocation(enabled bool) Option {
	return func(c *Config) {
		c.EnableTokenRevocation = enabled
	}
}

// WithSessionManagement habilita/desabilita gerenciamento de sessões.
func WithSessionManagement(enabled bool) Option {
	return func(c *Config) {
		c.EnableSessionManagement = enabled
	}
}

// WithMaxSessions define o número máximo de sessões por usuário.
func WithMaxSessions(max int) Option {
	return func(c *Config) {
		c.MaxSessionsPerUser = max
	}
}

// WithHTTPS força o uso de HTTPS.
func WithHTTPS(required bool) Option {
	return func(c *Config) {
		c.RequireHTTPS = required
	}
}

// WithClockSkew define a tolerância para diferença de relógio.
func WithClockSkew(skew time.Duration) Option {
	return func(c *Config) {
		c.ClockSkew = skew
	}
}

// Storage Configuration Options

// WithStorageType define o tipo de armazenamento.
func WithStorageType(storageType string) Option {
	return func(c *Config) {
		c.StorageType = storageType
	}
}

// WithStorageConfig define configurações específicas do storage.
func WithStorageConfig(config map[string]interface{}) Option {
	return func(c *Config) {
		c.StorageConfig = config
	}
}

// Performance Configuration Options

// WithCache habilita/desabilita cache.
func WithCache(enabled bool) Option {
	return func(c *Config) {
		c.CacheEnabled = enabled
	}
}

// WithCacheTTL define o TTL do cache.
func WithCacheTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.CacheTTL = ttl
	}
}

// Debug Configuration Options

// WithDebug habilita/desabilita modo debug.
func WithDebug(enabled bool) Option {
	return func(c *Config) {
		c.Debug = enabled
	}
}

// WithLogLevel define o nível de log.
func WithLogLevel(level string) Option {
	return func(c *Config) {
		c.LogLevel = level
	}
}
