// Command wg-vip is an AUTHORIZED pentest attacker for a LOCAL BuddyNet lab. It
// proves WG-4: the VIP↔pubkey binding stays strict on the WireGuard path. It
// registers with the handshake server claiming a VirtualIP that does NOT match its
// own public key (a hostile/buggy roster, or a squat with a forged VIP), then
// parks so a victim buddy pairs with it. The victim must reject the roster
// (connect.go: "partner virtual IP does not match its key") BEFORE any data plane
// is brought up — identical on the QUIC and WireGuard paths, since the check sits
// in the shared pre-connect step.
//
// The server relays the self-reported VirtualIP verbatim (handshake.go), trusting
// the receiving buddy to enforce the binding — so this is a faithful vector that
// exercises the buddy-side defense.
//
// Usage: wg-vip -server H:P -server-key B64 -key FILE -token T [-vip FORGED]
//
//	-vip empty  → advertise the CORRECT VIP (control: the victim must NOT reject).
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"net"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/tunnel"
	"github.com/tzero78/buddynet/pkg/protocol"
)

func main() {
	server := flag.String("server", "10.50.0.10:51820", "handshake server host:port")
	serverKeyB64 := flag.String("server-key", "", "server public key (base64)")
	keyPath := flag.String("key", "", "attacker identity key file (created if missing)")
	token := flag.String("token", "", "pairing token")
	vip := flag.String("vip", "", "FORGED virtual IP to advertise (empty = advertise the correct one)")
	quic := flag.Bool("quic", true, "register over the QUIC control plane (the default since QUIC-by-default); -quic=false uses the legacy plain-UDP plane")
	flag.Parse()

	srvPub, err := bcrypto.DecodePubKey(*serverKeyB64)
	if err != nil {
		log.Fatalf("wg-vip: server-key: %v", err)
	}
	priv, _, err := bcrypto.LoadOrCreateKey(*keyPath)
	if err != nil {
		log.Fatalf("wg-vip: key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	correct := bcrypto.VirtualIPString(pub)
	adv := *vip
	if adv == "" {
		adv = correct
	}
	log.Printf("wg-vip: pubkey=%s key-derives-vip=%s advertising-vip=%s", bcrypto.PubKeyB64(pub), correct, adv)

	// signedRegister builds ONE registration the way an honest v7 client does:
	// fresh nonce + current timestamp, signed over the payload with the plaintext
	// token, then the token sealed to the server key. Everything here is legitimate
	// client behaviour — the ONLY hostile part of this tool is the VirtualIP it
	// claims. It must be rebuilt per attempt: the nonce is single-use (the server
	// rejects a replay of the same (key, nonce)) and the timestamp has to stay
	// inside the server's skew window while the attacker parks.
	signedRegister := func() protocol.Message {
		nonce, nerr := protocol.NewNonce()
		if nerr != nil {
			log.Fatalf("wg-vip: nonce: %v", nerr)
		}
		m := protocol.Message{
			Type: protocol.TypeRegister, Ver: protocol.Version, Role: protocol.RoleBuddy,
			ID: "vip-attacker", PubKey: bcrypto.PubKeyB64(pub), VirtualIP: adv,
			Token: *token, Ts: time.Now().Unix(), Nonce: nonce,
		}
		m.RegSig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, protocol.RegistrationPayload(m)))
		enc, serr := bcrypto.SealCode(*token, srvPub)
		if serr != nil {
			log.Fatalf("wg-vip: seal token: %v", serr)
		}
		m.TokenEnc = enc
		m.Token = "" // sealed on the wire; the signature covers the plaintext
		return m
	}

	// The attacker only needs to REGISTER a parked entry carrying the forged VIP; the
	// victim rejects it at the pre-connect VIP↔key check, so no data plane is needed.
	// The control transport must match the server's — QUIC by default (the server and
	// victim both default to QUIC since #97), plain UDP under -quic=false.
	if *quic {
		addr, rerr := net.ResolveUDPAddr("udp", *server)
		if rerr != nil {
			log.Fatalf("wg-vip: resolve server: %v", rerr)
		}
		conn, lerr := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		if lerr != nil {
			log.Fatalf("wg-vip: udp socket: %v", lerr)
		}
		defer conn.Close()
		cli, derr := tunnel.DialControl(context.Background(), conn, addr, srvPub, priv, 2*time.Minute)
		if derr != nil {
			log.Fatalf("wg-vip: QUIC control dial (is the server on QUIC? pass -quic=false for plain UDP): %v", derr)
		}
		defer cli.Close()
		// Re-roundtrip periodically so the parked entry survives the server's
		// registration TTL until the victim pairs (each stream re-asserts the REGISTER).
		for {
			raw, merr := json.Marshal(signedRegister())
			if merr != nil {
				log.Fatalf("wg-vip: marshal register: %v", merr)
			}
			rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, _ = cli.Roundtrip(rctx, raw)
			cancel()
			log.Printf("wg-vip: registered+parked (QUIC) under the token — waiting for a victim to pair")
			time.Sleep(3 * time.Second)
		}
	}

	// Legacy plain-UDP plane (server started with --quic-handshake=false).
	c, err := net.Dial("udp", *server)
	if err != nil {
		log.Fatalf("wg-vip: dial: %v", err)
	}
	defer c.Close()
	register := func() {
		m := signedRegister()
		r, _ := json.Marshal(m)
		c.Write(r)
		c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		buf := make([]byte, 2048)
		n, rerr := c.Read(buf)
		if rerr != nil {
			return
		}
		var cm protocol.Message
		if json.Unmarshal(buf[:n], &cm) == nil && cm.Type == protocol.TypeCookie {
			m.Cookie = cm.Cookie
			r, _ = json.Marshal(m)
			c.Write(r)
		}
	}
	register()
	log.Printf("wg-vip: registered+parked (plain UDP) under the token — waiting for a victim to pair")
	for range time.Tick(3 * time.Second) {
		register()
	}
}
