package role

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

// nextAttemptFn yields the connection plan for the next reconnect round. The
// single-peer path wraps nextAttempt; a multi-peer worker uses reconnectSource,
// scoped to one pinned partner.
type nextAttemptFn func() (attempt, error)

// errSessionRevoked ends a peer worker cleanly when its stored session vanished
// from the known_peers store between reconnects (the operator revoked it): the
// supervisor logs it and that one buddy stops while the others keep running.
var errSessionRevoked = errors.New("stored session removed — peer revoked")

// peerLoop maintains ONE buddy until ctx is cancelled: it draws an attempt from
// next, runs the tunnel (buddyRun), then reconnects with its OWN backoff/jitter so
// many peers never retry in lockstep (no thundering herd). It is the per-partner
// unit the supervisor runs N of; lt (lazy) is only ever non-nil on the
// single-peer path. inviteStart bounds a one-time invite's first-pairing window.
func peerLoop(ctx context.Context, cfg BuddyConfig, nd *node, lt *lazyTunnel, next nextAttemptFn, inviteStart time.Time) error {
	backoff := reconnectBase
	for {
		// In lazy mode, sleep until a local connection needs a tunnel.
		if lt != nil {
			select {
			case <-lt.wake:
			case <-ctx.Done():
				return nil
			}
		}

		att, aerr := next()
		if aerr != nil {
			return aerr
		}
		// A one-time invite is only valid for a limited window of first pairing.
		if cfg.Ephemeral && att.firstPairing && time.Since(inviteStart) > cfg.InviteTimeout {
			return fmt.Errorf("invite token expired after %s without pairing — run --invite again for a fresh one", cfg.InviteTimeout)
		}

		runStart := time.Now()
		if err := buddyRun(ctx, cfg, att, nd, lt); err != nil && ctx.Err() == nil {
			// An unconfirmed SAS (mismatch or timeout) is a deliberate "do not
			// trust" — retrying would just re-prompt forever, so stop this peer
			// instead of reconnecting. In multi-peer mode the other peers are
			// unaffected (each runs its own peerLoop).
			if errors.Is(err, ErrSASRejected) || errors.Is(err, ErrSASTimeout) {
				return fmt.Errorf("aborted: %w", err)
			}
			log.Printf("tunnel error: %v", err)
		}
		if ctx.Err() != nil {
			return nil
		}
		// A run that lasted longer than the cap means a real tunnel was up; reset
		// the backoff so a single long-lived session always reconnects promptly. A
		// run that failed fast (server/network flapping) grows the delay, jittered.
		if time.Since(runStart) > reconnectMax {
			backoff = reconnectBase
		}
		wait := jitter(backoff)
		log.Printf("reconnecting in %s...", wait.Round(100*time.Millisecond))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		if backoff *= 2; backoff > reconnectMax {
			backoff = reconnectMax
		}
	}
}

// superviseReconnect runs one peerLoop per stored session concurrently — the
// multi-peer core. A worker that stops (revoked session, or an unconfirmed SAS)
// takes down ONLY its own buddy; the others keep running. It returns when ctx is
// cancelled and every worker has drained (no goroutine leak).
func superviseReconnect(ctx context.Context, cfg BuddyConfig, nd *node, sessions []storedSession) error {
	log.Printf("multi-peer: supervising %d paired buddies", len(sessions))
	var wg sync.WaitGroup
	for _, s := range sessions {
		pin := s.pin
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := peerLoop(ctx, cfg, nd, nil, reconnectSource(cfg, pin), time.Time{}); err != nil {
				log.Printf("peer %s stopped: %v", keyTag(bcrypto.PubKeyB64(pin)), err)
			}
		}()
	}
	wg.Wait()
	return nil
}

// reconnectSource is one peer worker's attempt source: it reloads THIS peer's
// session secret each round (so a re-pair is picked up, and a session removed
// from the store ends the worker via errSessionRevoked) and pins the recorded
// partner key — never an unauthenticated, publicly computable rendezvous.
func reconnectSource(cfg BuddyConfig, pin ed25519.PublicKey) nextAttemptFn {
	return func() (attempt, error) {
		secret, ok, err := loadSessionFor(cfg.KnownPeers, pin)
		if err != nil {
			return attempt{}, fmt.Errorf("session store %s: %w", cfg.KnownPeers, err)
		}
		if !ok {
			return attempt{}, errSessionRevoked
		}
		return attempt{rendezvous: secret, pin: pin}, nil
	}
}
