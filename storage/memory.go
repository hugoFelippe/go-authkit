package storage

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/hugoFelippe/go-authkit/contracts"
)

// MemoryStorage implementa todas as interfaces de storage em memória com thread-safety
type MemoryStorage struct {
	// Maps para diferentes tipos de dados
	tokens          map[string]*tokenEntry
	users           map[string]*contracts.User
	usersByEmail    map[string]string // email -> userID
	usersByUsername map[string]string // username -> userID
	sessions        map[string]*contracts.Session
	userSessions    map[string][]string // userID -> sessionIDs
	configs         map[string]*configEntry
	cache           map[string]*cacheEntry
	revoked         map[string]bool // tokens revogados

	// Mutex para thread-safety
	mu sync.RWMutex

	// Canal para parar o cleanup
	stopCleanup chan struct{}
	cleanupDone chan struct{}
}

// tokenEntry representa um token armazenado com TTL
type tokenEntry struct {
	Claims    *contracts.Claims
	ExpiresAt time.Time
}

// configEntry representa uma configuração com TTL opcional
type configEntry struct {
	Value     interface{}
	ExpiresAt *time.Time
}

// cacheEntry representa um item de cache com TTL
type cacheEntry struct {
	Value     interface{}
	ExpiresAt time.Time
}

// NewMemoryStorage cria uma nova instância do storage em memória
func NewMemoryStorage() *MemoryStorage {
	ms := &MemoryStorage{
		tokens:          make(map[string]*tokenEntry),
		users:           make(map[string]*contracts.User),
		usersByEmail:    make(map[string]string),
		usersByUsername: make(map[string]string),
		sessions:        make(map[string]*contracts.Session),
		userSessions:    make(map[string][]string),
		configs:         make(map[string]*configEntry),
		cache:           make(map[string]*cacheEntry),
		revoked:         make(map[string]bool),
		stopCleanup:     make(chan struct{}),
		cleanupDone:     make(chan struct{}),
	}

	// Inicia o processo de cleanup automático
	go ms.cleanupWorker()

	return ms
}

// cleanupWorker executa cleanup automático a cada 5 minutos
func (ms *MemoryStorage) cleanupWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	defer close(ms.cleanupDone)

	for {
		select {
		case <-ticker.C:
			ms.Cleanup(context.Background())
		case <-ms.stopCleanup:
			return
		}
	}
}

// Close fecha o storage e para o cleanup
func (ms *MemoryStorage) Close() error {
	close(ms.stopCleanup)
	<-ms.cleanupDone
	return nil
}

// =============================================================================
// TokenStorage Implementation
// =============================================================================

// StoreToken armazena um token com sua expiração
func (ms *MemoryStorage) StoreToken(ctx context.Context, token string, claims *contracts.Claims, expiry time.Duration) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	expiresAt := time.Now().Add(expiry)
	ms.tokens[token] = &tokenEntry{
		Claims:    claims,
		ExpiresAt: expiresAt,
	}

	return nil
}

// GetToken recupera as claims de um token
func (ms *MemoryStorage) GetToken(ctx context.Context, token string) (*contracts.Claims, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	entry, exists := ms.tokens[token]
	if !exists {
		return nil, contracts.ErrTokenNotFound
	}

	// Verifica se o token expirou
	if time.Now().After(entry.ExpiresAt) {
		return nil, contracts.ErrExpiredToken
	}

	// Verifica se o token foi revogado
	if ms.revoked[token] {
		return nil, contracts.ErrTokenRevoked
	}

	return entry.Claims, nil
}

// DeleteToken remove um token do armazenamento
func (ms *MemoryStorage) DeleteToken(ctx context.Context, token string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	delete(ms.tokens, token)
	delete(ms.revoked, token)

	return nil
}

// DeleteAllTokens remove todos os tokens de um usuário
func (ms *MemoryStorage) DeleteAllTokens(ctx context.Context, userID string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	for token, entry := range ms.tokens {
		if entry.Claims != nil && entry.Claims.Subject == userID {
			delete(ms.tokens, token)
			delete(ms.revoked, token)
		}
	}

	return nil
}

// IsRevoked verifica se um token foi revogado
func (ms *MemoryStorage) IsRevoked(ctx context.Context, token string) (bool, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	return ms.revoked[token], nil
}

// RevokeToken revoga um token específico
func (ms *MemoryStorage) RevokeToken(ctx context.Context, token string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.revoked[token] = true

	return nil
}

// RevokeAllTokens revoga todos os tokens de um usuário
func (ms *MemoryStorage) RevokeAllTokens(ctx context.Context, userID string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	for token, entry := range ms.tokens {
		if entry.Claims != nil && entry.Claims.Subject == userID {
			ms.revoked[token] = true
		}
	}

	return nil
}

// =============================================================================
// UserStorage Implementation
// =============================================================================

// StoreUser armazena um usuário
func (ms *MemoryStorage) StoreUser(ctx context.Context, user *contracts.User) error {
	if user.ID == "" {
		return contracts.ErrInvalidUserID
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Verifica se email já existe (se fornecido)
	if user.Email != "" {
		if existingUserID, exists := ms.usersByEmail[user.Email]; exists && existingUserID != user.ID {
			return contracts.ErrUserEmailExists
		}
	}

	// Verifica se username já existe (se fornecido)
	if user.Username != "" {
		if existingUserID, exists := ms.usersByUsername[user.Username]; exists && existingUserID != user.ID {
			return contracts.ErrUserUsernameExists
		}
	}

	// Remove os índices antigos se o usuário já existia
	if existingUser, exists := ms.users[user.ID]; exists {
		if existingUser.Email != "" {
			delete(ms.usersByEmail, existingUser.Email)
		}
		if existingUser.Username != "" {
			delete(ms.usersByUsername, existingUser.Username)
		}
	}

	// Armazena o usuário
	userCopy := *user
	userCopy.UpdatedAt = time.Now()
	if userCopy.CreatedAt.IsZero() {
		userCopy.CreatedAt = userCopy.UpdatedAt
	}

	ms.users[user.ID] = &userCopy

	// Atualiza os índices
	if user.Email != "" {
		ms.usersByEmail[user.Email] = user.ID
	}
	if user.Username != "" {
		ms.usersByUsername[user.Username] = user.ID
	}

	return nil
}

// GetUser recupera um usuário por ID
func (ms *MemoryStorage) GetUser(ctx context.Context, userID string) (*contracts.User, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	user, exists := ms.users[userID]
	if !exists {
		return nil, contracts.ErrUserNotFound
	}

	// Retorna uma cópia para evitar modificações acidentais
	userCopy := *user
	return &userCopy, nil
}

// GetUserByEmail recupera um usuário por email
func (ms *MemoryStorage) GetUserByEmail(ctx context.Context, email string) (*contracts.User, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	userID, exists := ms.usersByEmail[email]
	if !exists {
		return nil, contracts.ErrUserNotFound
	}

	user, exists := ms.users[userID]
	if !exists {
		// Cleanup de índice inconsistente
		delete(ms.usersByEmail, email)
		return nil, contracts.ErrUserNotFound
	}

	userCopy := *user
	return &userCopy, nil
}

// GetUserByUsername recupera um usuário por username
func (ms *MemoryStorage) GetUserByUsername(ctx context.Context, username string) (*contracts.User, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	userID, exists := ms.usersByUsername[username]
	if !exists {
		return nil, contracts.ErrUserNotFound
	}

	user, exists := ms.users[userID]
	if !exists {
		// Cleanup de índice inconsistente
		delete(ms.usersByUsername, username)
		return nil, contracts.ErrUserNotFound
	}

	userCopy := *user
	return &userCopy, nil
}

// UpdateUser atualiza um usuário existente
func (ms *MemoryStorage) UpdateUser(ctx context.Context, user *contracts.User) error {
	if user.ID == "" {
		return contracts.ErrInvalidUserID
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Verifica se o usuário existe
	_, exists := ms.users[user.ID]
	if !exists {
		return contracts.ErrUserNotFound
	}

	// Verifica conflitos de email e username (como no StoreUser)
	if user.Email != "" {
		if existingUserID, exists := ms.usersByEmail[user.Email]; exists && existingUserID != user.ID {
			return contracts.ErrUserEmailExists
		}
	}

	if user.Username != "" {
		if existingUserID, exists := ms.usersByUsername[user.Username]; exists && existingUserID != user.ID {
			return contracts.ErrUserUsernameExists
		}
	}

	// Remove índices antigos
	if existingUser, exists := ms.users[user.ID]; exists {
		if existingUser.Email != "" {
			delete(ms.usersByEmail, existingUser.Email)
		}
		if existingUser.Username != "" {
			delete(ms.usersByUsername, existingUser.Username)
		}
	}

	// Atualiza o usuário
	userCopy := *user
	userCopy.UpdatedAt = time.Now()
	ms.users[user.ID] = &userCopy

	// Atualiza índices
	if user.Email != "" {
		ms.usersByEmail[user.Email] = user.ID
	}
	if user.Username != "" {
		ms.usersByUsername[user.Username] = user.ID
	}

	return nil
}

// DeleteUser remove um usuário
func (ms *MemoryStorage) DeleteUser(ctx context.Context, userID string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	user, exists := ms.users[userID]
	if !exists {
		return contracts.ErrUserNotFound
	}

	// Remove índices
	if user.Email != "" {
		delete(ms.usersByEmail, user.Email)
	}
	if user.Username != "" {
		delete(ms.usersByUsername, user.Username)
	}

	// Remove o usuário
	delete(ms.users, userID)

	// Remove sessões do usuário
	if sessionIDs, exists := ms.userSessions[userID]; exists {
		for _, sessionID := range sessionIDs {
			delete(ms.sessions, sessionID)
		}
		delete(ms.userSessions, userID)
	}

	return nil
}

// ListUsers lista usuários com paginação
func (ms *MemoryStorage) ListUsers(ctx context.Context, offset, limit int) ([]*contracts.User, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	users := make([]*contracts.User, 0, len(ms.users))
	for _, user := range ms.users {
		userCopy := *user
		users = append(users, &userCopy)
	}

	// Aplica paginação
	if offset >= len(users) {
		return []*contracts.User{}, nil
	}

	end := offset + limit
	if end > len(users) {
		end = len(users)
	}

	return users[offset:end], nil
}

// CountUsers conta o total de usuários
func (ms *MemoryStorage) CountUsers(ctx context.Context) (int64, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	return int64(len(ms.users)), nil
}

// =============================================================================
// SessionStorage Implementation
// =============================================================================

// StoreSession armazena uma sessão
func (ms *MemoryStorage) StoreSession(ctx context.Context, session *contracts.Session) error {
	if session.ID == "" {
		return contracts.ErrInvalidSessionID
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()

	sessionCopy := *session
	sessionCopy.UpdatedAt = time.Now()
	if sessionCopy.CreatedAt.IsZero() {
		sessionCopy.CreatedAt = sessionCopy.UpdatedAt
	}

	ms.sessions[session.ID] = &sessionCopy

	// Atualiza índice de sessões por usuário
	userSessions := ms.userSessions[session.UserID]
	found := false
	for _, sessionID := range userSessions {
		if sessionID == session.ID {
			found = true
			break
		}
	}
	if !found {
		ms.userSessions[session.UserID] = append(userSessions, session.ID)
	}

	return nil
}

// GetSession recupera uma sessão por ID
func (ms *MemoryStorage) GetSession(ctx context.Context, sessionID string) (*contracts.Session, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	session, exists := ms.sessions[sessionID]
	if !exists {
		return nil, contracts.ErrSessionNotFound
	}

	// Verifica se a sessão expirou
	if time.Now().After(session.ExpiresAt) {
		return nil, contracts.ErrSessionExpired
	}

	sessionCopy := *session
	return &sessionCopy, nil
}

// DeleteSession remove uma sessão
func (ms *MemoryStorage) DeleteSession(ctx context.Context, sessionID string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	session, exists := ms.sessions[sessionID]
	if !exists {
		return contracts.ErrSessionNotFound
	}

	// Remove da lista de sessões do usuário
	userSessions := ms.userSessions[session.UserID]
	for i, id := range userSessions {
		if id == sessionID {
			ms.userSessions[session.UserID] = append(userSessions[:i], userSessions[i+1:]...)
			break
		}
	}

	// Remove a sessão
	delete(ms.sessions, sessionID)

	return nil
}

// DeleteAllSessions remove todas as sessões de um usuário
func (ms *MemoryStorage) DeleteAllSessions(ctx context.Context, userID string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	sessionIDs, exists := ms.userSessions[userID]
	if exists {
		for _, sessionID := range sessionIDs {
			delete(ms.sessions, sessionID)
		}
		delete(ms.userSessions, userID)
	}

	return nil
}

// GetUserSessions recupera todas as sessões ativas de um usuário
func (ms *MemoryStorage) GetUserSessions(ctx context.Context, userID string) ([]*contracts.Session, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	sessionIDs, exists := ms.userSessions[userID]
	if !exists {
		return []*contracts.Session{}, nil
	}

	sessions := make([]*contracts.Session, 0, len(sessionIDs))
	now := time.Now()

	for _, sessionID := range sessionIDs {
		session, exists := ms.sessions[sessionID]
		if exists && now.Before(session.ExpiresAt) && session.Active {
			sessionCopy := *session
			sessions = append(sessions, &sessionCopy)
		}
	}

	return sessions, nil
}

// =============================================================================
// ConfigStorage Implementation
// =============================================================================

// Set define um valor de configuração
func (ms *MemoryStorage) Set(ctx context.Context, key string, value interface{}, expiry time.Duration) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	entry := &configEntry{
		Value: value,
	}

	if expiry > 0 {
		expiresAt := time.Now().Add(expiry)
		entry.ExpiresAt = &expiresAt
	}

	ms.configs[key] = entry

	return nil
}

// Get recupera um valor de configuração
func (ms *MemoryStorage) Get(ctx context.Context, key string) (interface{}, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	entry, exists := ms.configs[key]
	if !exists {
		return nil, contracts.ErrConfigNotFound
	}

	// Verifica expiração
	if entry.ExpiresAt != nil && time.Now().After(*entry.ExpiresAt) {
		return nil, contracts.ErrConfigNotFound
	}

	return entry.Value, nil
}

// Delete remove uma configuração
func (ms *MemoryStorage) Delete(ctx context.Context, key string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	delete(ms.configs, key)
	return nil
}

// Exists verifica se uma chave existe
func (ms *MemoryStorage) Exists(ctx context.Context, key string) (bool, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	entry, exists := ms.configs[key]
	if !exists {
		return false, nil
	}

	// Verifica expiração
	if entry.ExpiresAt != nil && time.Now().After(*entry.ExpiresAt) {
		return false, nil
	}

	return true, nil
}

// GetAll recupera todas as configurações
func (ms *MemoryStorage) GetAll(ctx context.Context) (map[string]interface{}, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	result := make(map[string]interface{})
	now := time.Now()

	for key, entry := range ms.configs {
		// Pula entradas expiradas
		if entry.ExpiresAt != nil && now.After(*entry.ExpiresAt) {
			continue
		}
		result[key] = entry.Value
	}

	return result, nil
}

// Clear remove todas as configurações
func (ms *MemoryStorage) Clear(ctx context.Context) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.configs = make(map[string]*configEntry)
	return nil
}

// =============================================================================
// CacheStorage Implementation
// =============================================================================

// SetCache armazena um valor com TTL opcional
func (ms *MemoryStorage) SetCache(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	} else {
		// Se TTL for 0 ou negativo, nunca expira (seta para um tempo muito no futuro)
		expiresAt = time.Now().Add(100 * 365 * 24 * time.Hour) // 100 anos
	}

	ms.cache[key] = &cacheEntry{
		Value:     value,
		ExpiresAt: expiresAt,
	}

	return nil
}

// GetCache recupera um valor
func (ms *MemoryStorage) GetCache(ctx context.Context, key string) (interface{}, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	entry, exists := ms.cache[key]
	if !exists {
		return nil, contracts.ErrCacheKeyNotFound
	}

	// Verifica expiração
	if time.Now().After(entry.ExpiresAt) {
		return nil, contracts.ErrCacheKeyNotFound
	}

	return entry.Value, nil
}

// DeleteCache remove um valor
func (ms *MemoryStorage) DeleteCache(ctx context.Context, key string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	delete(ms.cache, key)
	return nil
}

// ExistsCache verifica se uma chave existe
func (ms *MemoryStorage) ExistsCache(ctx context.Context, key string) (bool, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	entry, exists := ms.cache[key]
	if !exists {
		return false, nil
	}

	// Verifica expiração
	if time.Now().After(entry.ExpiresAt) {
		return false, nil
	}

	return true, nil
}

// TTL retorna o tempo de vida restante de uma chave
func (ms *MemoryStorage) TTL(ctx context.Context, key string) (time.Duration, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	entry, exists := ms.cache[key]
	if !exists {
		return 0, contracts.ErrCacheKeyNotFound
	}

	ttl := time.Until(entry.ExpiresAt)
	if ttl <= 0 {
		return 0, contracts.ErrCacheKeyNotFound
	}

	return ttl, nil
}

// Expire define um novo TTL para uma chave
func (ms *MemoryStorage) Expire(ctx context.Context, key string, ttl time.Duration) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	entry, exists := ms.cache[key]
	if !exists {
		return contracts.ErrCacheKeyNotFound
	}

	if ttl > 0 {
		entry.ExpiresAt = time.Now().Add(ttl)
	} else {
		entry.ExpiresAt = time.Now().Add(100 * 365 * 24 * time.Hour) // 100 anos
	}

	return nil
}

// Keys lista todas as chaves com um padrão opcional
func (ms *MemoryStorage) Keys(ctx context.Context, pattern string) ([]string, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	var keys []string
	now := time.Now()

	for key, entry := range ms.cache {
		// Pula entradas expiradas
		if now.After(entry.ExpiresAt) {
			continue
		}

		// Se pattern vazio, retorna todas as chaves
		if pattern == "" {
			keys = append(keys, key)
			continue
		}

		// Implementação simples de pattern matching (apenas prefix/suffix/contains)
		if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
			// *pattern* - contains
			substring := pattern[1 : len(pattern)-1]
			if strings.Contains(key, substring) {
				keys = append(keys, key)
			}
		} else if strings.HasPrefix(pattern, "*") {
			// *pattern - suffix
			suffix := pattern[1:]
			if strings.HasSuffix(key, suffix) {
				keys = append(keys, key)
			}
		} else if strings.HasSuffix(pattern, "*") {
			// pattern* - prefix
			prefix := pattern[:len(pattern)-1]
			if strings.HasPrefix(key, prefix) {
				keys = append(keys, key)
			}
		} else {
			// pattern exato
			if key == pattern {
				keys = append(keys, key)
			}
		}
	}

	return keys, nil
}

// ClearCache remove todas as chaves
func (ms *MemoryStorage) ClearCache(ctx context.Context) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.cache = make(map[string]*cacheEntry)
	return nil
}

// Size retorna o número de chaves armazenadas
func (ms *MemoryStorage) Size(ctx context.Context) (int64, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	count := int64(0)
	now := time.Now()

	for _, entry := range ms.cache {
		if now.Before(entry.ExpiresAt) {
			count++
		}
	}

	return count, nil
}

// =============================================================================
// HealthChecker Implementation
// =============================================================================

// Ping verifica se o storage está acessível
func (ms *MemoryStorage) Ping(ctx context.Context) error {
	// Para memory storage, sempre está disponível
	return nil
}

// Stats retorna estatísticas do storage
func (ms *MemoryStorage) Stats(ctx context.Context) (map[string]interface{}, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	now := time.Now()

	// Conta tokens ativos
	activeTokens := 0
	for _, entry := range ms.tokens {
		if now.Before(entry.ExpiresAt) && !ms.revoked[entry.Claims.Subject] {
			activeTokens++
		}
	}

	// Conta sessões ativas
	activeSessions := 0
	for _, session := range ms.sessions {
		if now.Before(session.ExpiresAt) && session.Active {
			activeSessions++
		}
	}

	// Conta cache ativo
	activeCache := 0
	for _, entry := range ms.cache {
		if now.Before(entry.ExpiresAt) {
			activeCache++
		}
	}

	// Conta configs ativas
	activeConfigs := 0
	for _, entry := range ms.configs {
		if entry.ExpiresAt == nil || now.Before(*entry.ExpiresAt) {
			activeConfigs++
		}
	}

	return map[string]interface{}{
		"type":            "memory",
		"tokens_total":    len(ms.tokens),
		"tokens_active":   activeTokens,
		"tokens_revoked":  len(ms.revoked),
		"users_total":     len(ms.users),
		"sessions_total":  len(ms.sessions),
		"sessions_active": activeSessions,
		"configs_total":   len(ms.configs),
		"configs_active":  activeConfigs,
		"cache_total":     len(ms.cache),
		"cache_active":    activeCache,
		"memory_safe":     true,
	}, nil
}

// =============================================================================
// Cleanup Methods
// =============================================================================

// Cleanup remove tokens, sessões e cache expirados
func (ms *MemoryStorage) Cleanup(ctx context.Context) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	now := time.Now()

	// Cleanup tokens expirados
	for token, entry := range ms.tokens {
		if now.After(entry.ExpiresAt) {
			delete(ms.tokens, token)
			delete(ms.revoked, token)
		}
	}

	// Cleanup sessões expiradas
	expiredSessions := make(map[string]string) // sessionID -> userID
	for sessionID, session := range ms.sessions {
		if now.After(session.ExpiresAt) {
			expiredSessions[sessionID] = session.UserID
			delete(ms.sessions, sessionID)
		}
	}

	// Remove sessões expiradas dos índices de usuário
	for sessionID, userID := range expiredSessions {
		userSessions := ms.userSessions[userID]
		for i, id := range userSessions {
			if id == sessionID {
				ms.userSessions[userID] = append(userSessions[:i], userSessions[i+1:]...)
				break
			}
		}
		// Se o usuário não tem mais sessões, remove da lista
		if len(ms.userSessions[userID]) == 0 {
			delete(ms.userSessions, userID)
		}
	}

	// Cleanup cache expirado
	for key, entry := range ms.cache {
		if now.After(entry.ExpiresAt) {
			delete(ms.cache, key)
		}
	}

	// Cleanup configs expiradas
	for key, entry := range ms.configs {
		if entry.ExpiresAt != nil && now.After(*entry.ExpiresAt) {
			delete(ms.configs, key)
		}
	}

	return nil
}
