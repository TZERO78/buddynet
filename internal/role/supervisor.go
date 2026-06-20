package role

import (
	"context"
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

// supervise runs one peerLoop per peer spec concurrently — the multi-peer core.
// Each worker bootstraps (first pairing via its token) or reconnects (via a
// stored session), independently. A worker that stops (revoked session and no
// token, or an unconfirmed SAS) takes down ONLY its own buddy; the others keep
// running. It returns when ctx is cancelled and every worker has drained (no
// goroutine leak).
func supervise(ctx context.Context, cfg BuddyConfig, nd *node, specs []peerSpec) error {
	log.Printf("SUPERVISOR: action=start buddies=%d", len(specs))
	var wg sync.WaitGroup
	for _, s := range specs {
		s := s
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := peerLoop(ctx, cfg, nd, nil, peerSource(cfg, s), time.Time{}); err != nil {
				log.Printf("SUPERVISOR: action=peer-stopped key=%s detail=%q", keyTag(bcrypto.PubKeyB64(s.pin)), err.Error())
			}
		}()
	}
	wg.Wait()
	return nil
}

// peerSource is one worker's attempt source. It reloads THIS peer's stored
// session each round: if a session exists, reconnect with its secret (pinning the
// recorded key — never an unauthenticated, publicly computable rendezvous); a
// re-pair is thus picked up automatically. With no session yet, fall back to the
// one-time bootstrap token (first pairing, pinned, storing a session on success).
// With neither, the worker stops via errSessionRevoked (a paired peer whose
// session was removed = revoked; a manifest peer without a token has no path).
func peerSource(cfg BuddyConfig, spec peerSpec) nextAttemptFn {
	return func() (attempt, error) {
		secret, ok, err := loadSessionFor(cfg.KnownPeers, spec.pin)
		if err != nil {
			return attempt{}, fmt.Errorf("session store %s: %w", cfg.KnownPeers, err)
		}
		if ok {
			return attempt{rendezvous: secret, pin: spec.pin}, nil
		}
		if spec.token == "" {
			return attempt{}, errSessionRevoked
		}
		// First pairing: meet at the shared bootstrap token, pin the manifest key
		// (so no SAS prompt — Model A), and store a session secret on success.
		return attempt{rendezvous: spec.token, inviteToken: spec.token, pin: spec.pin, firstPairing: true}, nil
	}
}
