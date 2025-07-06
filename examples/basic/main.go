package main

import (
	"fmt"
	"log"
	"time"

	"github.com/hugoFelippe/go-authkit"
	"github.com/hugoFelippe/go-authkit/contracts"
)

func main() {
	fmt.Println("🔐 AuthKit - Exemplo Básico da Fase 1")
	fmt.Println("==========================================")

	// 1. Criar uma instância do AuthKit com configurações personalizadas
	fmt.Println("\n📋 1. Configurando AuthKit...")

	auth := authkit.New(
		authkit.WithIssuer("my-awesome-app"),
		authkit.WithTokenExpiry(2*time.Hour),
		authkit.WithJWTSecret([]byte("super-secret-key-change-in-production")),
		authkit.WithDebug(true),
		authkit.WithAPIKeyPrefix("myapp-"),
		authkit.WithTokenSources("bearer", "header", "query"),
	)

	config := auth.Config()
	fmt.Printf("   ✓ Issuer: %s\n", config.Issuer)
	fmt.Printf("   ✓ Token válido por: %s\n", config.TokenExpiry)
	fmt.Printf("   ✓ Método de assinatura: %s\n", config.JWTSigningMethod)
	fmt.Printf("   ✓ Debug ativado: %t\n", config.Debug)

	// 2. Criar estruturas de dados de exemplo
	fmt.Println("\n👤 2. Criando usuário de exemplo...")

	user := &contracts.User{
		ID:          "usr_123456",
		Username:    "alice",
		Email:       "alice@example.com",
		Name:        "Alice Silva",
		Roles:       []string{"user", "editor"},
		Permissions: []string{"read:posts", "write:posts", "delete:own_posts"},
		Groups:      []string{"editors", "content_team"},
		Attributes: map[string]interface{}{
			"department": "Marketing",
			"level":      3,
			"region":     "BR",
		},
		Active:    true,
		CreatedAt: time.Now().AddDate(0, -6, 0), // 6 meses atrás
		UpdatedAt: time.Now(),
	}

	fmt.Printf("   ✓ Usuário: %s (%s)\n", user.Name, user.Email)
	fmt.Printf("   ✓ Roles: %v\n", user.Roles)
	fmt.Printf("   ✓ Permissions: %v\n", user.Permissions)
	fmt.Printf("   ✓ Department: %s\n", user.Attributes["department"])

	// 3. Criar claims para token
	fmt.Println("\n🎫 3. Criando claims para token...")

	now := time.Now()
	claims := &contracts.Claims{
		Subject:     user.ID,
		Issuer:      config.Issuer,
		Audience:    []string{"api.myapp.com", "admin.myapp.com"},
		ExpiresAt:   now.Add(config.TokenExpiry),
		NotBefore:   now,
		IssuedAt:    now,
		ID:          "jti_789012",
		Email:       user.Email,
		Username:    user.Username,
		Name:        user.Name,
		Roles:       user.Roles,
		Permissions: user.Permissions,
		Scopes:      []string{"read:api", "write:api"},
		Groups:      user.Groups,
		Metadata: map[string]interface{}{
			"session_id": "sess_345678",
			"ip_address": "192.168.1.100",
		},
		Department: user.Attributes["department"].(string),
		Level:      user.Attributes["level"].(int),
		Region:     user.Attributes["region"].(string),
	}

	fmt.Printf("   ✓ Subject: %s\n", claims.Subject)
	fmt.Printf("   ✓ Válido até: %s\n", claims.ExpiresAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("   ✓ Scopes: %v\n", claims.Scopes)
	fmt.Printf("   ✓ ABAC Level: %d\n", claims.Level)

	// 4. Criar API Key de exemplo
	fmt.Println("\n🔑 4. Criando API Key...")

	apiKey := &contracts.APIKey{
		ID:          "key_456789",
		Key:         config.APIKeyPrefix + "1234567890abcdef1234567890abcdef",
		Name:        "Alice's Personal API Key",
		Description: "Para integração com sistema de CMS",
		UserID:      user.ID,
		Scopes:      []string{"read:posts", "write:posts", "read:media"},
		Metadata: map[string]interface{}{
			"environment": "production",
			"client_app":  "cms_integration",
		},
		CreatedAt: now,
		UpdatedAt: now,
		ExpiresAt: &[]time.Time{now.Add(365 * 24 * time.Hour)}[0], // 1 ano
		Active:    true,
	}

	fmt.Printf("   ✓ Nome: %s\n", apiKey.Name)
	fmt.Printf("   ✓ Key: %s\n", apiKey.Key)
	fmt.Printf("   ✓ Scopes: %v\n", apiKey.Scopes)
	fmt.Printf("   ✓ Expira em: %s\n", apiKey.ExpiresAt.Format("2006-01-02"))

	// 5. Demonstrar sistema de erros
	fmt.Println("\n❌ 5. Demonstrando sistema de erros...")

	// Erro básico
	err1 := contracts.ErrUnauthorized
	fmt.Printf("   • Erro básico: %s\n", err1.Error())

	// Erro com detalhes
	err2 := contracts.ErrInsufficientScope
	fmt.Printf("   • Erro com detalhes: %s\n", err2.Error())

	// Verificação de tipo
	if contracts.IsAuthError(err2) {
		fmt.Printf("   • Código: %s\n", contracts.GetErrorCode(err2))
		fmt.Printf("   • É erro de autenticação: %t\n", contracts.IsAuthError(err2))
	}

	// 6. Testar validação de configuração
	fmt.Println("\n⚙️  6. Testando validação de configuração...")

	// Configuração válida
	validConfig := authkit.DefaultConfig()
	validConfig.JWTSecret = []byte("test-secret-key")
	if err := validConfig.Validate(); err == nil {
		fmt.Printf("   ✓ Configuração válida aprovada\n")
	}

	// Configuração inválida
	invalidConfig := authkit.DefaultConfig()
	invalidConfig.Issuer = ""
	if err := invalidConfig.Validate(); err != nil {
		fmt.Printf("   ✗ Configuração inválida rejeitada: %s\n", err.Error())
	}

	// 7. Demonstrar sessão
	fmt.Println("\n📱 7. Criando informações de sessão...")

	session := &contracts.Session{
		ID:        "sess_345678",
		UserID:    user.ID,
		Token:     "session_token_abcdef123456",
		CreatedAt: now,
		UpdatedAt: now,
		ExpiresAt: now.Add(7 * 24 * time.Hour), // 7 dias
		Metadata: map[string]interface{}{
			"last_access": now,
			"ip_address":  "192.168.1.100",
			"user_agent":  "Mozilla/5.0 (AuthKit Example)",
			"device":      "desktop",
			"location":    "São Paulo, BR",
		},
		Active: true,
	}

	fmt.Printf("   ✓ Session ID: %s\n", session.ID)
	fmt.Printf("   ✓ Expira em: %s\n", session.ExpiresAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("   ✓ Device: %s\n", session.Metadata["device"])

	// 8. Finalizar
	fmt.Println("\n🏁 8. Finalizando...")

	if err := auth.Close(); err != nil {
		log.Printf("Erro ao fechar AuthKit: %v", err)
	} else {
		fmt.Printf("   ✓ AuthKit fechado corretamente\n")
	}

	fmt.Println("\n✅ Exemplo da Fase 1 concluído com sucesso!")
	fmt.Println("🚀 Próximos passos:")
	fmt.Println("   • Implementar Fase 2: Token Management (JWT)")
	fmt.Println("   • Adicionar Storage em memória")
	fmt.Println("   • Criar middlewares básicos")
	fmt.Println()
}
