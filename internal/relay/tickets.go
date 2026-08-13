package relay

import (
	"crypto/ed25519"
	"encoding/base64"
	"log"
	"net"
	"time"

	"github.com/tzero78/buddynet/internal/safe"
	"github.com/tzero78/buddynet/internal/ticket"
)

// Rejection reasons that belong to the relay rather than to the ticket itself.
// Like ticket.Reason they are FIXED strings, never derived from the input, so
// logging one can never become a log injection.
const (
	reasonNoTicket  = "no ticket presented (this relay verifies tickets)"
	reasonEncoding  = "ticket fields are not well-formed base64url"
	reasonSIDClaim  = "bind names a different session than its ticket"
	reasonBudget    = "verification budget exhausted"
	reasonInFlight  = "too many verifications already in flight"
	reasonLegTaken  = "leg already held by another ephemeral key"
	reasonLegCap    = "session or source is at its leg cap"
	reasonCapacity  = "relay is at capacity"
	reasonMigration = "address migration refused"
)

// admitTicketBind decides whether this bind may spend verification work, then
// does that work OFF the read loop. It runs after the cookie check, so the source
// address is already proven; everything here is about bounding CPU.
//
// The read loop must not perform the two Ed25519 verifications itself: the same
// loop forwards the tunnel's data, so a flood of valid-cookie binds from many
// real addresses would stall the traffic the relay exists to carry.
func (s *Server) admitTicketBind(conn *net.UDPConn, b Bind, src *net.UDPAddr, acct string, cookie []byte) {
	if b.Ticket == "" || b.TicketSig == "" || b.BindSig == "" {
		// The clear refusal §10 asks for: an old-style bind reaching a ticket-mode
		// relay must produce a log line here, not a silent timeout at the buddy.
		s.rejectTicket(reasonNoTicket, b.SessionToken, "", src)
		return
	}
	sid := b.SessionToken
	// The reserve is a ROUTING HINT and nothing else. sid arrives in an unverified
	// packet — it is not a secret and never an authenticator — so preferring on it
	// may only decide whether the work happens NOW or is refused, never whether the
	// work is checked. Both signature checks still run below, in the same order,
	// before anything is recorded.
	admitted := false
	if s.halfOpen(sid) {
		admitted = s.reserveRL.Allow(sid)
	}
	if !admitted {
		// Either not half-open, or the reserve is spent. Falling through to the
		// global budget is deliberate: the reserve does not ADD to the global
		// ceiling, and a bind draws from one or the other, never both.
		if !s.sigRL.AllowGlobal() {
			s.statRejected.Add(1)
			s.rejectTicket(reasonBudget, sid, "", src)
			return
		}
	}
	select {
	case s.inFlight <- struct{}{}:
	default:
		s.statRejected.Add(1)
		s.rejectTicket(reasonInFlight, sid, "", src)
		return
	}
	safe.Go("relay.ticket", func() {
		defer func() { <-s.inFlight }()
		s.verifyTicketBind(conn, b, src, acct, cookie)
	})
}

// halfOpen reports whether a session with this id exists and holds exactly one
// leg — the state the reserve exists to protect, where one more bind completes a
// pairing. It grants nothing on its own.
func (s *Server) halfOpen(sid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ses := s.sessions[sid]
	return ses != nil && len(ses.legs) == 1
}

// verifyTicketBind is steps 5-7 of the check order: the server signature over the
// EXACT received bytes, then the field checks, then the proof of possession. Only
// if all of them hold does it touch any state.
func (s *Server) verifyTicketBind(conn *net.UDPConn, b Bind, src *net.UDPAddr, acct string, cookie []byte) {
	payload, err := base64.RawURLEncoding.DecodeString(b.Ticket)
	if err != nil {
		s.rejectTicket(reasonEncoding, b.SessionToken, "", src)
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(b.TicketSig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		s.rejectTicket(reasonEncoding, b.SessionToken, "", src)
		return
	}
	bindSig, err := base64.RawURLEncoding.DecodeString(b.BindSig)
	if err != nil || len(bindSig) != ed25519.SignatureSize {
		s.rejectTicket(reasonEncoding, b.SessionToken, "", src)
		return
	}
	// Counted HERE, at the last point before the first Ed25519 operation: every
	// check that is supposed to happen earlier (size, CIDR, per-source rate, cookie,
	// budgets) is only doing its job if this counter stays put when they refuse.
	s.statVerify.Add(1)
	// The signature is checked over the bytes AS RECEIVED, before they are parsed.
	// Nothing below this line is reached by a blob the configured server key did
	// not sign.
	if !ticket.Verify(s.serverKeys, payload, sig) {
		s.rejectTicket(string(ticket.ReasonSignature), b.SessionToken, "", src)
		return
	}
	p, err := ticket.Parse(payload)
	if err != nil {
		s.rejectTicket(string(ticket.ReasonOf(err)), b.SessionToken, "", src)
		return
	}
	if err := p.CheckWindow(time.Now()); err != nil {
		s.rejectWindow(p)
		return
	}
	if err := p.CheckRelay(s.relayID); err != nil {
		s.rejectTicket(string(ticket.ReasonRelay), p.SID, p.Leg, src)
		return
	}
	// The bind must name the session its ticket names. Both values are the
	// server's, so a mismatch is either a mangled client or someone trying to file
	// a valid ticket under a different session.
	if b.SessionToken != p.SID {
		s.rejectTicket(reasonSIDClaim, p.SID, p.Leg, src)
		return
	}
	epk, err := p.EphPub()
	if err != nil {
		s.rejectTicket(string(ticket.ReasonMalformed), p.SID, p.Leg, src)
		return
	}
	if err := ticket.VerifyBind(epk, payload, sig, cookie, bindSig); err != nil {
		s.rejectTicket(string(ticket.ReasonProof), p.SID, p.Leg, src)
		return
	}
	s.bindTicketed(conn, p, src, acct)
}

// bindTicketed is step 8: allocate or update state, and only now. Per sid the
// relay accepts exactly one leg "a" and one leg "b", both named by the server, so
// a third party cannot join a pair however valid-looking its packet is.
func (s *Server) bindTicketed(conn *net.UDPConn, p ticket.Payload, src *net.UDPAddr, acct string) {
	sid := p.SID
	s.mu.Lock()
	ses := s.sessions[sid]
	created := false
	if ses == nil {
		if len(s.sessions) >= s.maxSessions {
			s.mu.Unlock()
			s.statRejected.Add(1)
			s.rejectTicket(reasonCapacity, sid, p.Leg, src)
			return
		}
		ses = &session{token: sid, created: time.Now()}
		s.sessions[sid] = ses
		created = true
	}
	// A session this call created must be taken back out if the leg is then
	// refused, or a refused bind still costs a global session slot.
	dropIfEmptyLocked := func() {
		if created && len(ses.legs) == 0 {
			delete(s.sessions, sid)
		}
	}

	var held *leg
	for _, l := range ses.legs {
		if l.name == p.Leg {
			held = l
			break
		}
	}

	// The leg is free: claim it.
	if held == nil {
		if len(ses.legs) >= maxLegsPerSes {
			// Unreachable while a session holds at most one leg of each name, and kept
			// as the backstop for exactly that assumption: a session is two buddies.
			dropIfEmptyLocked()
			s.mu.Unlock()
			s.statRejected.Add(1)
			s.rejectTicket(reasonLegCap, sid, p.Leg, src)
			return
		}
		if s.legsPerIP[acct] >= s.maxLegsPerIP {
			s.statHoard.Add(1)
			s.warnHoardLocked(acct)
			dropIfEmptyLocked()
			s.mu.Unlock()
			s.statRejected.Add(1)
			s.rejectTicket(reasonLegCap, sid, p.Leg, src)
			return
		}
		l := &leg{addr: src, fwd: &fwd{}, acctKey: acct, name: p.Leg, epk: p.EPK}
		ses.legs = append(ses.legs, l)
		s.byAddr.Store(src.String(), l.fwd)
		s.legsPerIP[acct]++
		s.pairLocked(ses)
		l.fwd.seen.Store(time.Now().UnixNano())
		s.mu.Unlock()
		conn.WriteToUDP(MarshalBind(Bind{SessionToken: sid}), src)
		return
	}

	// The leg is held by a DIFFERENT ephemeral key: refused, whatever it carries.
	// This is the third-party case, and it is why the leg records the epk.
	if held.epk != p.EPK {
		dropIfEmptyLocked()
		s.mu.Unlock()
		s.statRejected.Add(1)
		s.rejectTicket(reasonLegTaken, sid, p.Leg, src)
		return
	}

	// Same key, same address: an ordinary re-bind (keepalive).
	if held.addr.String() == src.String() {
		held.fwd.seen.Store(time.Now().UnixNano())
		s.mu.Unlock()
		conn.WriteToUDP(MarshalBind(Bind{SessionToken: sid}), src)
		return
	}

	// Same key, NEW address: a legitimate migration (NAT rebind, a mobile switch).
	// It is allowed because a buddy that changes address is not a third party — and
	// it is safe because all three of the following have already been established
	// by the time we get here:
	//
	//   - a fresh cookie bound to the NEW source address (checked in bind), so the
	//     mover actually receives packets there;
	//   - a proof of possession over that cookie, which only the holder of the
	//     ephemeral private key can produce — a copied ticket and bind cannot;
	//   - a ticket that is STILL VALID, because a migration is a new bind and took
	//     the same expiry check as any other. The ephemeral key proves WHO, never
	//     HOW LONG: letting a known epk re-bind on an expired ticket would turn it
	//     into an unbounded re-entry credential and quietly undo the lifetime
	//     design.
	//
	// The swap is atomic under s.mu: the old address stops forwarding in the same
	// critical section that starts the new one, so there is no moment where both
	// (or neither) are live.
	if held.acctKey != acct && s.legsPerIP[acct] >= s.maxLegsPerIP {
		// The destination budget is full. Refuse the move and leave the existing
		// address untouched, rather than dropping a working leg for a move that
		// cannot complete.
		s.mu.Unlock()
		s.statRejected.Add(1)
		s.rejectTicket(reasonMigration, sid, p.Leg, src)
		return
	}
	s.byAddr.Delete(held.addr.String())
	if held.acctKey != acct {
		s.releaseIPLocked(held.acctKey)
		s.legsPerIP[acct]++
		held.acctKey = acct
	}
	held.addr = src
	s.byAddr.Store(src.String(), held.fwd)
	// Re-publish the partner pointers so the OTHER leg sends to the new address.
	if len(ses.legs) == 2 {
		ses.legs[0].fwd.peer.Store(ses.legs[1].addr)
		ses.legs[1].fwd.peer.Store(ses.legs[0].addr)
	}
	held.fwd.seen.Store(time.Now().UnixNano())
	s.mu.Unlock()
	s.logRelay("action=leg-migrated sid=%s leg=%s", ticket.ShortSID(sid), p.Leg)
	conn.WriteToUDP(MarshalBind(Bind{SessionToken: sid}), src)
}

// pairLocked publishes the partner pointers once both legs are bound, so
// forward() can route without taking the lock. Caller holds s.mu.
func (s *Server) pairLocked(ses *session) {
	if len(ses.legs) != 2 {
		return
	}
	ses.paired = true
	s.statPaired.Add(1)
	ses.legs[0].fwd.peer.Store(ses.legs[1].addr)
	ses.legs[1].fwd.peer.Store(ses.legs[0].addr)
	// Ticket mode logs the SESSION, never the two addresses: a relay that prints
	// "a=<addr> b=<addr>" has written down who talks to whom, which is precisely
	// the knowledge this design keeps out of it.
	s.logRelay("action=session-paired sid=%s", ticket.ShortSID(ses.token))
}

// rejectWindow reports a timestamp refusal with its own distinguishable message.
// A relay CANNOT tell a skewed clock from a tampered or wrongly-issued ticket —
// both look identical from here — so the line names both causes and asserts
// neither. Sending an operator to chase NTP while someone replays stale tickets
// would be worse than saying nothing.
func (s *Server) rejectWindow(p ticket.Payload) {
	s.statTicket.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.throttleLocked(string(ticket.ReasonWindow)) {
		return
	}
	log.Printf("RELAY: action=ticket-rejected sid=%s leg=%s reason=%q detail=%q",
		ticket.ShortSID(p.SID), p.Leg, ticket.ReasonWindow,
		"iat/exp outside the accepted window; check that this relay's and the handshake server's clocks are in sync (NTP), and that the ticket was issued by the expected server")
}

// rejectTicket logs a refusal at most once per reason per interval, with the
// short session id and the leg — enough to correlate the two legs of one session
// in one log, deliberately not enough to link a session to a buddy.
//
// The source address is included ONLY in debug mode. The relay's whole claim is
// that it does not build a picture of who talks to whom, and an address next to a
// session id in a shipped log undermines exactly that. The cost is accepted:
// routine debugging is harder, and --debug is there for when it is needed.
func (s *Server) rejectTicket(reason, sid, leg string, src *net.UDPAddr) {
	s.statTicket.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.throttleLocked(reason) {
		return
	}
	// sid arrives unverified on the failing paths, so it is only ever logged
	// through ShortSID, which truncates it — never echoed whole.
	line := "RELAY: action=ticket-rejected sid=%s leg=%s reason=%q"
	args := []any{ticket.ShortSID(sid), leg, reason}
	if s.debug && src != nil {
		line += " src=%s"
		args = append(args, src.IP)
	}
	log.Printf(line, args...)
}

// throttleLocked reports whether a line for this reason may be written now,
// recording it if so. Bounded like every other latch here. Caller holds s.mu.
func (s *Server) throttleLocked(reason string) bool {
	now := time.Now()
	if last, ok := s.rejectWarned[reason]; ok && now.Sub(last) < statsInterval {
		return false
	}
	// The key space is the fixed set of reasons in this file plus ticket.Reason,
	// so this cannot grow with traffic; the bound is belt and braces.
	if len(s.rejectWarned) >= 64 {
		return false
	}
	s.rejectWarned[reason] = now
	return true
}

// logRelay writes an operational relay line. Kept as one helper so every line the
// relay emits about a session goes through the same place — the one that knows a
// session id must be shortened and an address must not appear.
func (s *Server) logRelay(format string, args ...any) {
	log.Printf("RELAY: "+format, args...)
}
