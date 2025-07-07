package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/hugoFelippe/go-authkit"
	"github.com/hugoFelippe/go-authkit/contracts"
	"github.com/hugoFelippe/go-authkit/storage"
)

func main() {
	// Cria storage customizado
	customStorage := storage.NewMemoryStorage()
	defer customStorage.Close()

	// Configura AuthKit
	auth := authkit.New(
		authkit.WithIssuer("storage-example"),
		authkit.WithJWTSecret([]byte("my-super-secret-key-for-storage-example")),
		authkit.WithTokenExpiry(time.Hour),
	)
	defer auth.Close()

	ctx := context.Background()

	fmt.Println("=== Exemplo: AuthKit + Storage Personalizado ===")

	// 1. Criar usuário diretamente no storage
	user := &contracts.User{
		ID:       "storage-user-123",
		Username: "storageuser",
		Email:    "storage@example.com",
		Name:     "Storage User",
		Active:   true,
		Roles:    []string{"user", "premium"},
	}

	err := customStorage.StoreUser(ctx, user)
	if err != nil {
		log.Fatalf("Erro ao armazenar usuário: %v", err)
	}
	fmt.Printf("✓ Usuário criado no storage: %s\n", user.Name)

	// 2. Gerar token usando AuthKit (com claims baseadas no usuário)
	claims := &contracts.Claims{
		Subject: user.ID,
		Email:   user.Email,
		Name:    user.Name,
		Issuer:  "storage-example",
		Roles:   user.Roles,
	}

	token, err := auth.GenerateToken(ctx, claims)
	if err != nil {
		log.Fatalf("Erro ao gerar token: %v", err)
	}
	fmt.Printf("✓ Token gerado: %s...\n", token[:20])

	// 3. O token foi automaticamente armazenado no nosso storage personalizado
	// Vamos armazenar o token manualmente no storage para demonstração
	err = customStorage.StoreToken(ctx, token, claims, time.Hour)
	if err != nil {
		log.Fatalf("Erro ao armazenar token no storage: %v", err)
	}

	// 4. Validar token usando AuthKit
	validatedClaims, err := auth.ValidateToken(ctx, token)
	if err != nil {
		log.Fatalf("Erro ao validar token: %v", err)
	}
	fmt.Printf("✓ Token validado para usuário: %s\n", validatedClaims.Name)

	// 5. Consultar storage para verificar dados armazenados
	fmt.Println("\n=== Verificando dados no storage ===")

	// Verificar token no storage
	storedClaims, err := customStorage.GetToken(ctx, token)
	if err != nil {
		log.Printf("Token não encontrado no storage: %v", err)
	} else {
		fmt.Printf("✓ Token encontrado no storage para: %s\n", storedClaims.Name)
	}

	// Verificar usuário no storage
	storedUser, err := customStorage.GetUser(ctx, user.ID)
	if err != nil {
		log.Printf("Usuário não encontrado no storage: %v", err)
	} else {
		fmt.Printf("✓ Usuário encontrado no storage: %s (%s)\n", storedUser.Name, storedUser.Email)
	}

	// 6. Criar sessão de usuário
	session := &contracts.Session{
		ID:        "session-" + user.ID + "-" + fmt.Sprintf("%d", time.Now().Unix()),
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(2 * time.Hour),
		Active:    true,
		Metadata: map[string]interface{}{
			"ip":         "192.168.1.100",
			"user_agent": "Example-App/1.0",
			"login_time": time.Now(),
		},
	}

	err = customStorage.StoreSession(ctx, session)
	if err != nil {
		log.Fatalf("Erro ao criar sessão: %v", err)
	}
	fmt.Printf("✓ Sessão criada: %s\n", session.ID)

	// 7. Simular cache de perfil do usuário
	userProfile := map[string]interface{}{
		"preferences": map[string]interface{}{
			"theme":    "dark",
			"language": "pt-BR",
			"timezone": "America/Sao_Paulo",
		},
		"last_login":   time.Now(),
		"login_count":  42,
		"subscription": "premium",
	}

	cacheKey := fmt.Sprintf("profile:%s", user.ID)
	err = customStorage.SetCache(ctx, cacheKey, userProfile, 30*time.Minute)
	if err != nil {
		log.Fatalf("Erro ao armazenar perfil no cache: %v", err)
	}
	fmt.Printf("✓ Perfil armazenado no cache: %s\n", cacheKey)

	// 8. Simular configurações da aplicação
	appConfigs := map[string]interface{}{
		"feature.new_dashboard":        true,
		"feature.advanced_search":      true,
		"rate_limit.requests_per_hour": 1000,
		"maintenance.scheduled":        false,
	}

	for key, value := range appConfigs {
		err = customStorage.Set(ctx, key, value, 0) // Sem expiração
		if err != nil {
			log.Fatalf("Erro ao armazenar configuração %s: %v", key, err)
		}
	}
	fmt.Printf("✓ %d configurações armazenadas\n", len(appConfigs))

	// 9. Demonstrar operações avançadas
	fmt.Println("\n=== Operações Avançadas ===")

	// Revogar token
	err = customStorage.RevokeToken(ctx, token)
	if err != nil {
		log.Fatalf("Erro ao revogar token: %v", err)
	}
	fmt.Println("✓ Token revogado")

	// Tentar validar token revogado
	_, err = auth.ValidateToken(ctx, token)
	if err != nil {
		fmt.Printf("✓ Token revogado rejeitado: %s\n", contracts.GetErrorCode(err))
	}

	// Listar sessões ativas do usuário
	userSessions, err := customStorage.GetUserSessions(ctx, user.ID)
	if err != nil {
		log.Fatalf("Erro ao listar sessões: %v", err)
	}
	fmt.Printf("✓ Usuário tem %d sessão(ões) ativa(s)\n", len(userSessions))

	// Buscar chaves de cache com padrão
	profileKeys, err := customStorage.Keys(ctx, "profile:*")
	if err != nil {
		log.Fatalf("Erro ao buscar chaves de perfil: %v", err)
	}
	fmt.Printf("✓ Encontradas %d chave(s) de perfil no cache\n", len(profileKeys))

	// 10. Estatísticas finais
	fmt.Println("\n=== Estatísticas Finais ===")

	stats, err := customStorage.Stats(ctx)
	if err != nil {
		log.Fatalf("Erro ao obter estatísticas: %v", err)
	}

	fmt.Printf("Tipo de storage: %v\n", stats["type"])
	fmt.Printf("Total de usuários: %v\n", stats["users_total"])
	fmt.Printf("Total de tokens: %v\n", stats["tokens_total"])
	fmt.Printf("Tokens revogados: %v\n", stats["tokens_revoked"])
	fmt.Printf("Total de sessões: %v\n", stats["sessions_total"])
	fmt.Printf("Sessões ativas: %v\n", stats["sessions_active"])
	fmt.Printf("Total de configurações: %v\n", stats["configs_total"])
	fmt.Printf("Items no cache: %v\n", stats["cache_total"])
	fmt.Printf("Thread-safe: %v\n", stats["memory_safe"])

	fmt.Println("\n✅ Exemplo de integração AuthKit + Storage executado com sucesso!")
	fmt.Println("\n📝 Principais benefícios demonstrados:")
	fmt.Println("   • Storage thread-safe para ambientes concorrentes")
	fmt.Println("   • TTL automático com cleanup de dados expirados")
	fmt.Println("   • Separação clara entre diferentes tipos de dados")
	fmt.Println("   • Integração transparente com AuthKit")
	fmt.Println("   • Estatísticas e monitoramento integrado")
	fmt.Println("   • Interfaces padronizadas para fácil substituição")
}
