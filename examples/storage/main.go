package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/hugoFelippe/go-authkit/contracts"
	"github.com/hugoFelippe/go-authkit/storage"
)

func main() {
	// Cria uma nova instância do storage em memória
	store := storage.NewMemoryStorage()
	defer store.Close()

	ctx := context.Background()

	// Exemplo 1: Gerenciamento de Usuários
	fmt.Println("=== Exemplo: Gerenciamento de Usuários ===")

	user := &contracts.User{
		ID:       "user123",
		Username: "johndoe",
		Email:    "john@example.com",
		Name:     "John Doe",
		Active:   true,
	}

	// Armazena o usuário
	err := store.StoreUser(ctx, user)
	if err != nil {
		log.Fatalf("Erro ao armazenar usuário: %v", err)
	}
	fmt.Printf("Usuário armazenado: %s\n", user.Name)

	// Recupera o usuário por ID
	retrievedUser, err := store.GetUser(ctx, user.ID)
	if err != nil {
		log.Fatalf("Erro ao recuperar usuário: %v", err)
	}
	fmt.Printf("Usuário recuperado por ID: %s (%s)\n", retrievedUser.Name, retrievedUser.Email)

	// Recupera o usuário por email
	userByEmail, err := store.GetUserByEmail(ctx, user.Email)
	if err != nil {
		log.Fatalf("Erro ao recuperar usuário por email: %v", err)
	}
	fmt.Printf("Usuário recuperado por email: %s\n", userByEmail.Name)

	// Exemplo 2: Gerenciamento de Tokens
	fmt.Println("\n=== Exemplo: Gerenciamento de Tokens ===")

	claims := &contracts.Claims{
		Subject: user.ID,
		Email:   user.Email,
		Name:    user.Name,
		Issuer:  "my-app",
	}

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
	expiry := time.Hour

	// Armazena o token
	err = store.StoreToken(ctx, token, claims, expiry)
	if err != nil {
		log.Fatalf("Erro ao armazenar token: %v", err)
	}
	fmt.Printf("Token armazenado para usuário: %s\n", claims.Subject)

	// Recupera as claims do token
	retrievedClaims, err := store.GetToken(ctx, token)
	if err != nil {
		log.Fatalf("Erro ao recuperar token: %v", err)
	}
	fmt.Printf("Claims recuperadas: %s (%s)\n", retrievedClaims.Name, retrievedClaims.Email)

	// Revoga o token
	err = store.RevokeToken(ctx, token)
	if err != nil {
		log.Fatalf("Erro ao revogar token: %v", err)
	}
	fmt.Println("Token revogado com sucesso")

	// Tenta recuperar o token revogado
	_, err = store.GetToken(ctx, token)
	if err != nil {
		fmt.Printf("Token revogado não pode ser recuperado: %s\n", contracts.GetErrorCode(err))
	}

	// Exemplo 3: Gerenciamento de Sessões
	fmt.Println("\n=== Exemplo: Gerenciamento de Sessões ===")

	session := &contracts.Session{
		ID:        "session456",
		UserID:    user.ID,
		Token:     "session-token-abc123",
		ExpiresAt: time.Now().Add(2 * time.Hour),
		Active:    true,
	}

	// Armazena a sessão
	err = store.StoreSession(ctx, session)
	if err != nil {
		log.Fatalf("Erro ao armazenar sessão: %v", err)
	}
	fmt.Printf("Sessão armazenada: %s para usuário %s\n", session.ID, session.UserID)

	// Recupera a sessão
	retrievedSession, err := store.GetSession(ctx, session.ID)
	if err != nil {
		log.Fatalf("Erro ao recuperar sessão: %v", err)
	}
	fmt.Printf("Sessão recuperada: %s (expira em %v)\n",
		retrievedSession.ID,
		time.Until(retrievedSession.ExpiresAt).Round(time.Minute))

	// Lista todas as sessões do usuário
	userSessions, err := store.GetUserSessions(ctx, user.ID)
	if err != nil {
		log.Fatalf("Erro ao listar sessões do usuário: %v", err)
	}
	fmt.Printf("Usuário %s tem %d sessão(ões) ativa(s)\n", user.ID, len(userSessions))

	// Exemplo 4: Configurações
	fmt.Println("\n=== Exemplo: Configurações ===")

	// Armazena configurações
	configs := map[string]interface{}{
		"app.name":    "My Auth App",
		"app.version": "1.0.0",
		"app.debug":   true,
		"jwt.expiry":  3600,
	}

	for key, value := range configs {
		err = store.Set(ctx, key, value, 0) // Sem expiração
		if err != nil {
			log.Fatalf("Erro ao armazenar configuração %s: %v", key, err)
		}
	}
	fmt.Println("Configurações armazenadas")

	// Recupera todas as configurações
	allConfigs, err := store.GetAll(ctx)
	if err != nil {
		log.Fatalf("Erro ao recuperar configurações: %v", err)
	}

	fmt.Println("Configurações ativas:")
	for key, value := range allConfigs {
		fmt.Printf("  %s = %v\n", key, value)
	}

	// Exemplo 5: Cache
	fmt.Println("\n=== Exemplo: Cache ===")

	// Armazena dados no cache com TTL
	cacheData := map[string]interface{}{
		"user:profile:123": map[string]string{
			"name":  "John Doe",
			"email": "john@example.com",
		},
		"api:rate_limit:john":   100,
		"temp:verification:456": "temp-code-789",
	}

	for key, value := range cacheData {
		var ttl time.Duration
		if key == "temp:verification:456" {
			ttl = 5 * time.Minute // Código de verificação temporário
		} else {
			ttl = time.Hour // Cache padrão
		}

		err = store.SetCache(ctx, key, value, ttl)
		if err != nil {
			log.Fatalf("Erro ao armazenar no cache %s: %v", key, err)
		}
	}
	fmt.Println("Dados armazenados no cache")

	// Lista chaves com padrão
	userKeys, err := store.Keys(ctx, "user:*")
	if err != nil {
		log.Fatalf("Erro ao listar chaves do usuário: %v", err)
	}
	fmt.Printf("Chaves de usuário no cache: %v\n", userKeys)

	// Verifica tamanho do cache
	cacheSize, err := store.Size(ctx)
	if err != nil {
		log.Fatalf("Erro ao verificar tamanho do cache: %v", err)
	}
	fmt.Printf("Tamanho do cache: %d items\n", cacheSize)

	// Exemplo 6: Saúde e Estatísticas
	fmt.Println("\n=== Exemplo: Saúde e Estatísticas ===")

	// Verifica saúde do storage
	err = store.Ping(ctx)
	if err != nil {
		log.Fatalf("Storage não está saudável: %v", err)
	}
	fmt.Println("Storage está saudável ✓")

	// Recupera estatísticas
	stats, err := store.Stats(ctx)
	if err != nil {
		log.Fatalf("Erro ao recuperar estatísticas: %v", err)
	}

	fmt.Println("Estatísticas do storage:")
	for key, value := range stats {
		fmt.Printf("  %s: %v\n", key, value)
	}

	// Exemplo 7: Limpeza
	fmt.Println("\n=== Exemplo: Limpeza ===")

	// Armazena um token com TTL muito baixo
	shortLivedToken := "short-lived-token"
	shortClaims := &contracts.Claims{Subject: "temp-user"}

	err = store.StoreToken(ctx, shortLivedToken, shortClaims, time.Millisecond)
	if err != nil {
		log.Fatalf("Erro ao armazenar token temporário: %v", err)
	}

	// Espera um pouco para o token expirar
	time.Sleep(10 * time.Millisecond)

	// Executa limpeza manual
	err = store.Cleanup(ctx)
	if err != nil {
		log.Fatalf("Erro na limpeza: %v", err)
	}
	fmt.Println("Limpeza executada - tokens expirados removidos")

	// Verifica se o token expirado foi removido
	_, err = store.GetToken(ctx, shortLivedToken)
	if err != nil {
		fmt.Printf("Token expirado foi removido: %s\n", contracts.GetErrorCode(err))
	}

	fmt.Println("\n✅ Exemplo completo executado com sucesso!")
}
