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
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"log"
	"net"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/pkg/protocol"
)

func main() {
	server := flag.String("server", "10.50.0.10:51820", "handshake server host:port")
	serverKeyB64 := flag.String("server-key", "", "server public key (base64)")
	keyPath := flag.String("key", "", "attacker identity key file (created if missing)")
	token := flag.String("token", "", "pairing token")
	vip := flag.String("vip", "", "FORGED virtual IP to advertise (empty = advertise the correct one)")
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

	enc, err := bcrypto.SealCode(*token, srvPub)
	if err != nil {
		log.Fatalf("wg-vip: seal token: %v", err)
	}
	c, err := net.Dial("udp", *server)
	if err != nil {
		log.Fatalf("wg-vip: dial: %v", err)
	}
	defer c.Close()

	base := protocol.Message{
		Type: protocol.TypeRegister, Ver: protocol.Version, Role: protocol.RoleBuddy,
		ID: "vip-attacker", PubKey: bcrypto.PubKeyB64(pub), TokenEnc: enc, VirtualIP: adv,
	}

	// One register does the cookie dance and parks; re-register periodically so the
	// parked entry survives the server's registration TTL until the victim pairs.
	register := func() {
		m := base
		raw, _ := json.Marshal(m)
		c.Write(raw)
		c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		buf := make([]byte, 2048)
		n, rerr := c.Read(buf)
		if rerr != nil {
			return
		}
		var cm protocol.Message
		if json.Unmarshal(buf[:n], &cm) == nil && cm.Type == protocol.TypeCookie {
			m.Cookie = cm.Cookie
			raw, _ = json.Marshal(m)
			c.Write(raw)
		}
	}

	register()
	log.Printf("wg-vip: registered+parked under the token — waiting for a victim to pair")
	for range time.Tick(3 * time.Second) {
		register()
	}
}
