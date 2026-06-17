// Package peer manages a node's knowledge of other peers: the on-disk cache
// (peers.json) that survives a handshake-server outage, and the discovery loop
// that keeps it fresh. The cache is what makes the last link of the fallback
// chain — "cached peers, works even if the server is offline" — possible: a
// buddy that has talked to its partner before can try the last known endpoint
// and relay directly, with no server in the loop.
package peer

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/tzero78/buddynet/pkg/protocol"
)

// Registry is an in-memory roster of known peers, keyed by public key, backed
// by an atomically-rewritten peers.json. It is safe for concurrent use.
type Registry struct {
	mu        sync.Mutex
	path      string                   // peers.json; empty = memory only
	peers     map[string]protocol.Peer // pubkey -> peer
	nameByKey map[string]string        // pubkey -> pinned name (TOFU)
	keyByName map[string]string        // name   -> pubkey (uniqueness guard)
}

// Open loads the registry from path (peers.json). A missing file is not an
// error — it just means nothing has been learned yet. An empty path makes the
// registry memory-only (handy for tests and ephemeral runs).
func Open(path string) (*Registry, error) {
	r := &Registry{
		path:      path,
		peers:     map[string]protocol.Peer{},
		nameByKey: map[string]string{},
		keyByName: map[string]string{},
	}
	if path == "" {
		return r, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, err
	}
	var list []protocol.Peer
	if err := json.Unmarshal(data, &list); err != nil {
		// A corrupt cache should not be fatal: a buddy can always re-learn its
		// peers from the handshake server. Start empty and overwrite on save.
		return r, nil
	}
	for _, p := range list {
		if p.PubKey == "" {
			continue
		}
		r.peers[p.PubKey] = p
		if p.Name != "" {
			r.nameByKey[p.PubKey] = p.Name
			r.keyByName[p.Name] = p.PubKey
		}
	}
	return r, nil
}

// Upsert merges newly-learned facts about a peer into the registry and stamps
// LastSeen, then persists. Candidates and relay from a fresh sighting overwrite
// the cached ones; an entry is only ever replaced by a same-or-newer view.
// Names are TOFU-pinned: the first name for a key wins and never changes;
// a collision (two keys claiming the same name) silently drops the name from
// the newcomer — it remains reachable by fingerprint only.
func (r *Registry) Upsert(p protocol.Peer) error {
	r.mu.Lock()
	if p.LastSeen == 0 {
		p.LastSeen = time.Now().Unix()
	}
	p.Name = r.pinNameLocked(p.PubKey, p.Name)
	r.peers[p.PubKey] = p
	snapshot := r.list()
	r.mu.Unlock()
	return r.save(snapshot)
}

// pinNameLocked resolves the name to store for pubkey according to TOFU rules.
// Must be called with r.mu held.
//
//   - Empty name: no change, return existing pinned name (or "").
//   - Same key, same name: idempotent, return name.
//   - Same key, different name: keep pinned name, warn, return pinned.
//   - New key, name unclaimed: pin it, return name.
//   - New key, name already claimed by another key: drop name, warn, return "".
func (r *Registry) pinNameLocked(pubkey, name string) string {
	if name == "" {
		return r.nameByKey[pubkey] // keep whatever was pinned; "" if nothing
	}
	if pinned, ok := r.nameByKey[pubkey]; ok {
		if pinned == name {
			return pinned // idempotent
		}
		log.Printf("WARNING: peer %s tried to change name %q→%q; keeping pinned name", shortKey(pubkey), pinned, name)
		return pinned
	}
	// Key has no name yet — check uniqueness.
	if owner, taken := r.keyByName[name]; taken {
		if owner != pubkey {
			log.Printf("WARNING: name %q already claimed by another key; peer %s resolvable by fingerprint only", name, shortKey(pubkey))
			return ""
		}
	}
	r.nameByKey[pubkey] = name
	r.keyByName[name] = pubkey
	return name
}

// Snapshot returns all known peers in canonical order. Used by the DNS server
// to build the .buddy lookup table without holding the registry lock.
func (r *Registry) Snapshot() []protocol.Peer {
	return r.List()
}

// Get returns the cached peer for a public key, if known.
func (r *Registry) Get(pubkey string) (protocol.Peer, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.peers[pubkey]
	return p, ok
}

// List returns all known peers in canonical (ID-sorted) order, so callers that
// sign or compare a roster produce reproducible bytes.
func (r *Registry) List() []protocol.Peer {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.list()
}

// list returns a sorted snapshot. Caller must hold r.mu.
func (r *Registry) list() []protocol.Peer {
	out := make([]protocol.Peer, 0, len(r.peers))
	for _, p := range r.peers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// shortKey returns the first 8 chars of a pubkey (or the full string if shorter),
// safe to log without leaking the full key.
func shortKey(pubkey string) string {
	if len(pubkey) <= 8 {
		return pubkey
	}
	return pubkey[:8]
}

// save atomically rewrites peers.json (write tmp, rename). A memory-only
// registry (empty path) is a no-op.
func (r *Registry) save(list []protocol.Peer) error {
	if r.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}
