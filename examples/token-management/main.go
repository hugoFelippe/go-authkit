package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/hugoFelippe/go-authkit/contracts"
	"github.com/hugoFelippe/go-authkit/token"
)

func main() {
	// Configurar JWT Manager
	jwtConfig := &token.JWTConfig{
		Issuer:        "example-app",
		SigningMethod: "HS256",
		SecretKey:     []byte("my-super-secret-key-that-should-be-in-env"),
		TokenExpiry:   15 * time.Minute,
		RefreshExpiry: 24 * time.Hour,
	}

	jwtManager, err := token.NewJWTManager(jwtConfig)
	if err != nil {
		log.Fatalf("Failed to create JWT manager: %v", err)
	}

	// Criar usuário de exemplo
	user := &contracts.User{
		ID:       "user123",
		Username: "john_doe",
		Email:    "john@example.com",
		Name:     "John Doe",
		Roles:    []string{"user", "editor"},
	}

	ctx := context.Background()

	// Gerar token JWT
	fmt.Println("=== JWT Token Example ===")
	jwtToken, err := jwtManager.GenerateToken(ctx, user)
	if err != nil {
		log.Fatalf("Failed to generate JWT token: %v", err)
	}
	fmt.Printf("Generated JWT Token: %s\n", jwtToken)

	// Validar token JWT
	claims, err := jwtManager.ValidateToken(ctx, jwtToken)
	if err != nil {
		log.Fatalf("Failed to validate JWT token: %v", err)
	}
	fmt.Printf("Validated Claims - Subject: %s, Issuer: %s, Email: %s\n",
		claims.Subject, claims.Issuer, claims.Email)

	// Introspect token
	tokenInfo, err := jwtManager.IntrospectToken(ctx, jwtToken)
	if err != nil {
		log.Fatalf("Failed to introspect token: %v", err)
	}
	fmt.Printf("Token Info - Type: %s, Expires: %s\n",
		tokenInfo.Type, tokenInfo.ExpiresAt.Format(time.RFC3339))

	// Gerar refresh token
	refreshToken, err := jwtManager.GenerateRefreshToken(ctx, user)
	if err != nil {
		log.Fatalf("Failed to generate refresh token: %v", err)
	}
	fmt.Printf("Generated Refresh Token: %s\n", refreshToken[:50]+"...")

	// Testar refresh token
	newAccessToken, newRefreshToken, err := jwtManager.RefreshToken(ctx, refreshToken)
	if err != nil {
		log.Fatalf("Failed to refresh token: %v", err)
	}
	fmt.Printf("Refreshed Access Token: %s\n", newAccessToken[:50]+"...")
	fmt.Printf("New Refresh Token: %s\n", newRefreshToken[:50]+"...")

	// Criar servidor HTTP com middleware de autenticação
	fmt.Println("\n=== Starting HTTP Server ===")
	fmt.Println("Server running on http://localhost:8080")
	fmt.Println("Try:")
	fmt.Printf("  curl -H 'Authorization: Bearer %s' http://localhost:8080/protected\n", jwtToken)
	fmt.Println("  curl http://localhost:8080/public")
	fmt.Println("  curl -X POST http://localhost:8080/token")

	http.HandleFunc("/public", publicHandler)
	http.HandleFunc("/protected", authMiddleware(jwtManager, protectedHandler))
	http.HandleFunc("/token", tokenHandler(jwtManager, user))

	log.Fatal(http.ListenAndServe(":8080", nil))
}

// authMiddleware é um middleware simples de autenticação
func authMiddleware(jwtManager *token.JWTManager, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extrair token do header Authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Verificar se é Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		// Validar token
		claims, err := jwtManager.ValidateToken(r.Context(), tokenString)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
			return
		}

		// Adicionar claims ao contexto (em um app real, você faria isso de forma mais robusta)
		fmt.Printf("Authenticated user: %s (%s)\n", claims.Name, claims.Subject)

		// Chamar próximo handler
		next(w, r)
	}
}

// publicHandler handler para endpoint público
func publicHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message": "This is a public endpoint", "timestamp": "%s"}`, time.Now().Format(time.RFC3339))
}

// protectedHandler handler para endpoint protegido
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message": "This is a protected endpoint", "timestamp": "%s"}`, time.Now().Format(time.RFC3339))
}

// tokenHandler handler para gerar novos tokens
func tokenHandler(jwtManager *token.JWTManager, user *contracts.User) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Gerar novo token
		newToken, err := jwtManager.GenerateToken(r.Context(), user)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to generate token: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token": "%s", "type": "Bearer", "expires_in": %d}`,
			newToken, int(time.Minute*15/time.Second))
	}
}
