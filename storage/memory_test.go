package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hugoFelippe/go-authkit/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStorage_TokenStorage(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()

	t.Run("StoreAndGetToken", func(t *testing.T) {
		claims := &contracts.Claims{
			Subject: "user123",
			Email:   "user@example.com",
			Name:    "Test User",
		}

		token := "test-token"
		expiry := time.Hour

		err := storage.StoreToken(ctx, token, claims, expiry)
		require.NoError(t, err)

		retrievedClaims, err := storage.GetToken(ctx, token)
		require.NoError(t, err)
		assert.Equal(t, claims.Subject, retrievedClaims.Subject)
		assert.Equal(t, claims.Email, retrievedClaims.Email)
		assert.Equal(t, claims.Name, retrievedClaims.Name)
	})

	t.Run("GetNonexistentToken", func(t *testing.T) {
		_, err := storage.GetToken(ctx, "nonexistent")
		assert.Error(t, err)
		assert.Equal(t, contracts.ErrCodeTokenNotFound, contracts.GetErrorCode(err))
	})

	t.Run("RevokeToken", func(t *testing.T) {
		claims := &contracts.Claims{Subject: "user456"}
		token := "revoke-token"

		err := storage.StoreToken(ctx, token, claims, time.Hour)
		require.NoError(t, err)

		err = storage.RevokeToken(ctx, token)
		require.NoError(t, err)

		_, err = storage.GetToken(ctx, token)
		assert.Error(t, err)
		assert.Equal(t, contracts.ErrCodeTokenRevoked, contracts.GetErrorCode(err))
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		claims := &contracts.Claims{Subject: "user789"}
		token := "expired-token"

		err := storage.StoreToken(ctx, token, claims, time.Millisecond)
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond)

		_, err = storage.GetToken(ctx, token)
		assert.Error(t, err)
		assert.Equal(t, contracts.ErrCodeExpiredToken, contracts.GetErrorCode(err))
	})
}

func TestMemoryStorage_UserStorage(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()

	t.Run("StoreAndGetUser", func(t *testing.T) {
		user := &contracts.User{
			ID:       "user123",
			Username: "testuser",
			Email:    "test@example.com",
			Name:     "Test User",
			Active:   true,
		}

		err := storage.StoreUser(ctx, user)
		require.NoError(t, err)

		retrievedUser, err := storage.GetUser(ctx, user.ID)
		require.NoError(t, err)
		assert.Equal(t, user.ID, retrievedUser.ID)
		assert.Equal(t, user.Username, retrievedUser.Username)
		assert.Equal(t, user.Email, retrievedUser.Email)
		assert.Equal(t, user.Name, retrievedUser.Name)
		assert.Equal(t, user.Active, retrievedUser.Active)
		assert.False(t, retrievedUser.CreatedAt.IsZero())
		assert.False(t, retrievedUser.UpdatedAt.IsZero())
	})

	t.Run("GetUserByEmail", func(t *testing.T) {
		user := &contracts.User{
			ID:    "user456",
			Email: "email@example.com",
			Name:  "Email User",
		}

		err := storage.StoreUser(ctx, user)
		require.NoError(t, err)

		retrievedUser, err := storage.GetUserByEmail(ctx, user.Email)
		require.NoError(t, err)
		assert.Equal(t, user.ID, retrievedUser.ID)
		assert.Equal(t, user.Email, retrievedUser.Email)
	})

	t.Run("GetUserByUsername", func(t *testing.T) {
		user := &contracts.User{
			ID:       "user789",
			Username: "usernametest",
			Name:     "Username User",
		}

		err := storage.StoreUser(ctx, user)
		require.NoError(t, err)

		retrievedUser, err := storage.GetUserByUsername(ctx, user.Username)
		require.NoError(t, err)
		assert.Equal(t, user.ID, retrievedUser.ID)
		assert.Equal(t, user.Username, retrievedUser.Username)
	})

	t.Run("DuplicateEmail", func(t *testing.T) {
		user1 := &contracts.User{
			ID:    "user1",
			Email: "duplicate@example.com",
		}

		user2 := &contracts.User{
			ID:    "user2",
			Email: "duplicate@example.com",
		}

		err := storage.StoreUser(ctx, user1)
		require.NoError(t, err)

		err = storage.StoreUser(ctx, user2)
		assert.Error(t, err)
		assert.Equal(t, contracts.ErrCodeUserEmailExists, contracts.GetErrorCode(err))
	})

	t.Run("ListUsers", func(t *testing.T) {
		// Limpa storage para este teste
		storage := NewMemoryStorage()
		defer storage.Close()

		users := []*contracts.User{
			{ID: "list1", Name: "User 1"},
			{ID: "list2", Name: "User 2"},
			{ID: "list3", Name: "User 3"},
		}

		for _, user := range users {
			err := storage.StoreUser(ctx, user)
			require.NoError(t, err)
		}

		retrievedUsers, err := storage.ListUsers(ctx, 0, 10)
		require.NoError(t, err)
		assert.Len(t, retrievedUsers, 3)

		count, err := storage.CountUsers(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(3), count)
	})
}

func TestMemoryStorage_SessionStorage(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()

	t.Run("StoreAndGetSession", func(t *testing.T) {
		session := &contracts.Session{
			ID:        "session123",
			UserID:    "user123",
			Token:     "session-token",
			ExpiresAt: time.Now().Add(time.Hour),
			Active:    true,
		}

		err := storage.StoreSession(ctx, session)
		require.NoError(t, err)

		retrievedSession, err := storage.GetSession(ctx, session.ID)
		require.NoError(t, err)
		assert.Equal(t, session.ID, retrievedSession.ID)
		assert.Equal(t, session.UserID, retrievedSession.UserID)
		assert.Equal(t, session.Token, retrievedSession.Token)
		assert.Equal(t, session.Active, retrievedSession.Active)
	})

	t.Run("GetUserSessions", func(t *testing.T) {
		userID := "user456"
		sessions := []*contracts.Session{
			{
				ID:        "session1",
				UserID:    userID,
				ExpiresAt: time.Now().Add(time.Hour),
				Active:    true,
			},
			{
				ID:        "session2",
				UserID:    userID,
				ExpiresAt: time.Now().Add(time.Hour),
				Active:    true,
			},
		}

		for _, session := range sessions {
			err := storage.StoreSession(ctx, session)
			require.NoError(t, err)
		}

		userSessions, err := storage.GetUserSessions(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, userSessions, 2)
	})

	t.Run("ExpiredSession", func(t *testing.T) {
		session := &contracts.Session{
			ID:        "expired-session",
			UserID:    "user789",
			ExpiresAt: time.Now().Add(-time.Hour), // Expirada
			Active:    true,
		}

		err := storage.StoreSession(ctx, session)
		require.NoError(t, err)

		_, err = storage.GetSession(ctx, session.ID)
		assert.Error(t, err)
		assert.Equal(t, contracts.ErrCodeSessionExpired, contracts.GetErrorCode(err))
	})
}

func TestMemoryStorage_ConfigStorage(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()

	t.Run("SetAndGetConfig", func(t *testing.T) {
		key := "test-config"
		value := "test-value"

		err := storage.Set(ctx, key, value, 0) // Sem expiração
		require.NoError(t, err)

		retrievedValue, err := storage.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, retrievedValue)
	})

	t.Run("ConfigWithExpiry", func(t *testing.T) {
		key := "expiring-config"
		value := "expiring-value"

		err := storage.Set(ctx, key, value, time.Millisecond)
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond)

		_, err = storage.Get(ctx, key)
		assert.Error(t, err)
		assert.Equal(t, contracts.ErrCodeConfigNotFound, contracts.GetErrorCode(err))
	})

	t.Run("GetAllConfigs", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer storage.Close()

		configs := map[string]interface{}{
			"config1": "value1",
			"config2": 42,
			"config3": true,
		}

		for key, value := range configs {
			err := storage.Set(ctx, key, value, 0)
			require.NoError(t, err)
		}

		allConfigs, err := storage.GetAll(ctx)
		require.NoError(t, err)
		assert.Len(t, allConfigs, 3)

		for key, expectedValue := range configs {
			assert.Equal(t, expectedValue, allConfigs[key])
		}
	})
}

func TestMemoryStorage_CacheStorage(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()

	t.Run("SetAndGetCache", func(t *testing.T) {
		key := "cache-key"
		value := "cache-value"

		err := storage.SetCache(ctx, key, value, time.Hour)
		require.NoError(t, err)

		retrievedValue, err := storage.GetCache(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, retrievedValue)
	})

	t.Run("CacheTTL", func(t *testing.T) {
		key := "ttl-key"
		value := "ttl-value"

		err := storage.SetCache(ctx, key, value, 50*time.Millisecond)
		require.NoError(t, err)

		// Verifica TTL
		ttl, err := storage.TTL(ctx, key)
		require.NoError(t, err)
		assert.True(t, ttl > 0)
		assert.True(t, ttl <= 50*time.Millisecond)

		time.Sleep(60 * time.Millisecond)

		_, err = storage.GetCache(ctx, key)
		assert.Error(t, err)
		assert.Equal(t, contracts.ErrCodeCacheKeyNotFound, contracts.GetErrorCode(err))
	})

	t.Run("CacheKeys", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer storage.Close()

		keys := []string{"prefix:key1", "prefix:key2", "other:key3"}

		for _, key := range keys {
			err := storage.SetCache(ctx, key, "value", time.Hour)
			require.NoError(t, err)
		}

		// Busca todas as chaves
		allKeys, err := storage.Keys(ctx, "")
		require.NoError(t, err)
		assert.Len(t, allKeys, 3)

		// Busca chaves com prefix
		prefixKeys, err := storage.Keys(ctx, "prefix:*")
		require.NoError(t, err)
		assert.Len(t, prefixKeys, 2)
	})

	t.Run("CacheSize", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer storage.Close()

		size, err := storage.Size(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(0), size)

		err = storage.SetCache(ctx, "size-key", "value", time.Hour)
		require.NoError(t, err)

		size, err = storage.Size(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(1), size)
	})
}

func TestMemoryStorage_HealthChecker(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()

	t.Run("Ping", func(t *testing.T) {
		err := storage.Ping(ctx)
		assert.NoError(t, err)
	})

	t.Run("Stats", func(t *testing.T) {
		// Adiciona alguns dados
		user := &contracts.User{ID: "stats-user", Name: "Stats User"}
		err := storage.StoreUser(ctx, user)
		require.NoError(t, err)

		claims := &contracts.Claims{Subject: "stats-user"}
		err = storage.StoreToken(ctx, "stats-token", claims, time.Hour)
		require.NoError(t, err)

		stats, err := storage.Stats(ctx)
		require.NoError(t, err)

		assert.Equal(t, "memory", stats["type"])
		assert.Equal(t, 1, stats["users_total"])
		assert.Equal(t, 1, stats["tokens_total"])
		assert.Equal(t, true, stats["memory_safe"])
	})
}

func TestMemoryStorage_Cleanup(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()

	t.Run("CleanupExpiredTokens", func(t *testing.T) {
		// Adiciona token expirado
		claims := &contracts.Claims{Subject: "cleanup-user"}
		err := storage.StoreToken(ctx, "expired-token", claims, time.Millisecond)
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond)

		err = storage.Cleanup(ctx)
		require.NoError(t, err)

		_, err = storage.GetToken(ctx, "expired-token")
		assert.Error(t, err)
	})
}

func TestMemoryStorage_ConcurrentAccess(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()

	t.Run("ConcurrentUserOperations", func(t *testing.T) {
		// Teste de concorrência básico
		done := make(chan bool, 2)

		go func() {
			for i := 0; i < 100; i++ {
				user := &contracts.User{
					ID:   fmt.Sprintf("user-a-%d", i),
					Name: fmt.Sprintf("User A %d", i),
				}
				storage.StoreUser(ctx, user)
			}
			done <- true
		}()

		go func() {
			for i := 0; i < 100; i++ {
				user := &contracts.User{
					ID:   fmt.Sprintf("user-b-%d", i),
					Name: fmt.Sprintf("User B %d", i),
				}
				storage.StoreUser(ctx, user)
			}
			done <- true
		}()

		<-done
		<-done

		count, err := storage.CountUsers(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(200), count)
	})
}
