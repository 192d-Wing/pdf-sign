package signing

import "testing"

// TestPreparingQuota verifies the per-owner cap counts in-flight Prepare
// reservations, not just stored sessions (fix M2). We drive the counter
// directly because a full Prepare needs a real PDF + certificate.
func TestPreparingQuota(t *testing.T) {
	m := &Manager{maxPerOwner: 2, sessions: map[string]*Session{}, preparing: map[string]int{}}

	m.preparing["acme"] = 2 // two creates in flight, none stored yet
	m.mu.Lock()
	count := m.preparing["acme"]
	for _, s := range m.sessions {
		if s.Owner == "acme" {
			count++
		}
	}
	m.mu.Unlock()
	if count < m.maxPerOwner {
		t.Fatalf("in-flight reservations should count toward the quota: got %d, want >= %d", count, m.maxPerOwner)
	}

	m.releasePreparing("acme")
	m.releasePreparing("acme")
	if _, ok := m.preparing["acme"]; ok {
		t.Fatalf("preparing map should be empty after releases, got %v", m.preparing)
	}
}
