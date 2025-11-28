package internal

import (
	"errors"
	"strings"
	"sync"
	"time"
)

type pendingUserEntry struct {
	Input     UserInput
	ExpiresAt time.Time
}

type pendingUserStore struct {
	mu      sync.RWMutex
	entries map[string]pendingUserEntry
}

var (
	globalPendingUserStore = &pendingUserStore{
		entries: make(map[string]pendingUserEntry),
	}
	defaultPendingUserTTL = 15 * time.Minute
)

func (s *pendingUserStore) cleanupExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, entry := range s.entries {
		if now.After(entry.ExpiresAt) {
			delete(s.entries, key)
		}
	}
}

func savePendingUser(input UserInput, ttl time.Duration) {
	key := normalizeEmail(input.Email)
	if key == "" {
		return
	}

	globalPendingUserStore.cleanupExpired()

	globalPendingUserStore.mu.Lock()
	defer globalPendingUserStore.mu.Unlock()

	globalPendingUserStore.entries[key] = pendingUserEntry{
		Input:     input,
		ExpiresAt: time.Now().Add(ttl),
	}
}

func getPendingUser(email string) (UserInput, error) {
	key := normalizeEmail(email)
	if key == "" {
		return UserInput{}, errors.New("email is required")
	}

	globalPendingUserStore.mu.RLock()
	entry, exists := globalPendingUserStore.entries[key]
	globalPendingUserStore.mu.RUnlock()

	if !exists {
		return UserInput{}, errors.New("no pending registration found for this email")
	}

	if time.Now().After(entry.ExpiresAt) {
		deletePendingUser(email)
		return UserInput{}, errors.New("pending registration has expired")
	}

	return entry.Input, nil
}

func deletePendingUser(email string) {
	key := normalizeEmail(email)
	if key == "" {
		return
	}

	globalPendingUserStore.mu.Lock()
	defer globalPendingUserStore.mu.Unlock()
	delete(globalPendingUserStore.entries, key)
}

func normalizeEmail(email string) string {
	return strings.TrimSpace(strings.ToLower(email))
}

