package role

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"fmt"
	"github.com/tzero78/buddynet/pkg/protocol"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/tzero78/buddynet/internal/atomicfile"
	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/nft"
	"gopkg.in/yaml.v3"
)

// peerSpec is one buddy the supervisor maintains: its pinned identity key, an
// optional one-time bootstrap token, an optional display name, and an optional
// per-buddy exposure scope for the WireGuard data plane. token is needed only
// until a session secret has been derived and stored for pin; afterwards
// reconnects use that session and the token is ignored. token == "" means
// "reconnect only" (a stored session must already exist, e.g. a previously
// paired peer not listed in the manifest). expose == nil means "no per-buddy
// scope set" — the buddy inherits the global --expose flag, else fail-closed.
type peerSpec struct {
	pin    ed25519.PublicKey
	token  string
	name   string
	expose *nft.Scope
}

// sameScope reports whether two per-buddy exposure scopes are equivalent. Two
// nil scopes are equal (both "inherit --expose"); one nil and one set differ.
// Otherwise the normalized string form (deterministic — see nft.Scope) decides,
// so re-ordered or duplicate ports do not count as a change. Used by the
// supervisor to detect a manifest `expose:` edit on SIGHUP.
func sameScope(a, b *nft.Scope) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.String() == b.String()
}

// maxManifestBytes bounds the manifest read. The file is the operator's own,
// but parsing stays defensive (fail loud on something absurd, never OOM).
const maxManifestBytes = 1 << 20

// manifestHeader is prepended to every manifest this program writes, so a
// hand-editing operator sees the schema without reading docs.
const manifestHeader = `# BuddyNet peers manifest (YAML). Managed by 'peers add/remove/list'; hand-editable.
# NOTE: 'peers add/remove' rewrite this file and drop custom comments.
# One entry per buddy:
#   - name: alice             # optional (display / .buddy hint)
#     key: <pubkey-base64>    # required — the buddy's pinned Ed25519 identity
#     token: <bootstrap>      # optional, only needed until the first pairing
#     expose: [873]           # optional (WireGuard): ports this buddy may reach
#                             # on THIS host, e.g. [873, "udp/51820"]; 'all' =
#                             # explicit whole host; omitted = inherit --expose,
#                             # else fail-closed (nothing exposed)
`

// peersManifest is the YAML schema of the peers manifest.
type peersManifest struct {
	Buddies []manifestBuddy `yaml:"buddies"`
}

type manifestBuddy struct {
	Name   string       `yaml:"name,omitempty"`
	Key    string       `yaml:"key"`
	Token  string       `yaml:"token,omitempty"`
	Expose *exposeValue `yaml:"expose,omitempty"`
}

// exposeValue adapts nft.Scope to the manifest's YAML forms: the scalar `all`,
// or a sequence like [873, "udp/51820"] (bare numbers are tcp).
type exposeValue struct {
	scope nft.Scope
}

func (e *exposeValue) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		if strings.EqualFold(strings.TrimSpace(n.Value), "all") {
			e.scope = nft.Scope{All: true}
			return nil
		}
		return fmt.Errorf("expose: got %q — want 'all' or a list like [873, \"udp/51820\"]", n.Value)
	case yaml.SequenceNode:
		if len(n.Content) == 0 {
			return fmt.Errorf("expose: empty list — omit the field to inherit --expose (or fail closed)")
		}
		parts := make([]string, len(n.Content))
		for i, item := range n.Content {
			parts[i] = item.Value
		}
		scope, err := nft.ParseScope(strings.Join(parts, ","))
		if err != nil {
			return fmt.Errorf("expose: %w", err)
		}
		e.scope = scope
		return nil
	default:
		return fmt.Errorf("expose: want 'all' or a list of ports")
	}
}

func (e exposeValue) MarshalYAML() (any, error) {
	if e.scope.All {
		return "all", nil
	}
	out := make([]any, len(e.scope.Ports))
	for i, p := range e.scope.Ports {
		if p.Proto == "tcp" {
			out[i] = int(p.Port)
		} else {
			out[i] = fmt.Sprintf("%s/%d", p.Proto, p.Port)
		}
	}
	return out, nil
}

// loadPeersFile parses a peers manifest. The current format is YAML (see
// manifestHeader); the pinned key is mandatory (Model A: every tunnel is
// pinned, no trust-on-first-use), everything else optional. Duplicate keys are
// rejected so a typo can't silently shadow a peer. The file is the same trust
// domain as known_peers (keep it 0600); an empty path yields no specs.
//
// The pre-YAML line format (`<peer-pubkey-b64> [bootstrap-token]`) is still
// read for one release, with a deprecation warning pointing at `peers migrate`.
func loadPeersFile(path string) ([]peerSpec, error) {
	if path == "" {
		return nil, nil
	}
	data, err := readManifest(path)
	if err != nil || data == nil {
		return nil, err
	}
	if manifestIsLegacy(data) {
		log.Printf("WARNING: %s uses the deprecated line format — run `buddynet --peers-file %s peers migrate` to convert it to YAML (the old format will stop being read in a future release)", path, path)
		return parseLegacyManifest(path, data)
	}
	return parseYAMLManifest(path, data)
}

// readManifest reads the manifest with the defensive size bound. A missing
// file is not an error (absent manifest = no peers, consistent with loadSessions).
func readManifest(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("peers-file %s: %w", path, err)
	}
	if fi.Size() > maxManifestBytes {
		return nil, fmt.Errorf("peers-file %s: %d bytes exceeds the %d-byte limit (not a manifest?)", path, fi.Size(), maxManifestBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("peers-file %s: %w", path, err)
	}
	return data, nil
}

// manifestIsLegacy reports whether data is in the pre-YAML line format: the
// first non-blank, non-comment line starts with a decodable Ed25519 public key.
// A YAML manifest's first content line is `buddies:`, which never decodes.
func manifestIsLegacy(data []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		_, err := bcrypto.DecodePubKey(fields[0])
		return err == nil
	}
	return false // empty/comment-only file: parse as (empty) YAML
}

func parseLegacyManifest(path string, data []byte) ([]peerSpec, error) {
	var specs []peerSpec
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) > 2 {
			return nil, fmt.Errorf("peers-file %s line %d: expected '<peer-key> [token]', got %d fields", path, line, len(fields))
		}
		pin, err := bcrypto.DecodePubKey(fields[0])
		if err != nil {
			return nil, fmt.Errorf("peers-file %s line %d: bad peer key: %w", path, line, err)
		}
		keyB64 := bcrypto.PubKeyB64(pin)
		if seen[keyB64] {
			return nil, fmt.Errorf("peers-file %s line %d: duplicate peer key %s", path, line, keyTag(keyB64))
		}
		seen[keyB64] = true
		spec := peerSpec{pin: pin}
		if len(fields) == 2 {
			spec.token = fields[1]
		}
		specs = append(specs, spec)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("peers-file %s: %w", path, err)
	}
	return specs, nil
}

func parseYAMLManifest(path string, data []byte) ([]peerSpec, error) {
	var m peersManifest
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// Strict: a typo'd field is a clear error, never silently ignored.
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		if err.Error() == "EOF" { // empty/comment-only file
			return nil, nil
		}
		return nil, fmt.Errorf("peers-file %s: %w", path, err)
	}
	var specs []peerSpec
	seen := map[string]bool{}
	for i, b := range m.Buddies {
		spec, err := b.toSpec()
		if err != nil {
			return nil, fmt.Errorf("peers-file %s buddies[%d]: %w", path, i, err)
		}
		keyB64 := bcrypto.PubKeyB64(spec.pin)
		if seen[keyB64] {
			return nil, fmt.Errorf("peers-file %s buddies[%d]: duplicate peer key %s", path, i, keyTag(keyB64))
		}
		seen[keyB64] = true
		specs = append(specs, spec)
	}
	return specs, nil
}

// toSpec validates one manifest entry into a peerSpec.
func (b manifestBuddy) toSpec() (peerSpec, error) {
	if b.Key == "" {
		return peerSpec{}, fmt.Errorf("missing key (the buddy's pinned public key is mandatory)")
	}
	pin, err := bcrypto.DecodePubKey(b.Key)
	if err != nil {
		return peerSpec{}, fmt.Errorf("bad peer key: %w", err)
	}
	// The handshake server accepts a token only in the base64url alphabet (see
	// role.validField), which is what --invite mints. Catching it HERE means the
	// operator gets a pointed error at startup instead of a pairing that silently
	// never happens — the server would just drop those registrations, and nothing
	// on the buddy side would say why.
	if b.Token != "" && !validField(b.Token) {
		return peerSpec{}, fmt.Errorf("bootstrap token %q is not usable: it must be 1..%d characters "+
			"of A-Z a-z 0-9 - _ (that is what `--invite` mints; a token with spaces, punctuation or "+
			"control characters is rejected by the handshake server)", b.Token, protocol.MaxFieldLen)
	}
	if err := validateBuddyName(b.Name); err != nil {
		return peerSpec{}, err
	}
	spec := peerSpec{pin: pin, token: b.Token, name: b.Name}
	if b.Expose != nil {
		scope := b.Expose.scope
		spec.expose = &scope
	}
	return spec, nil
}

// validateBuddyName checks an optional manifest name: same shape as --name
// (letters/digits/hyphens, max 63) so it can double as a .buddy label.
func validateBuddyName(name string) error {
	if name == "" {
		return nil
	}
	if len(name) > 63 {
		return fmt.Errorf("name %q too long (max 63 chars)", name)
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return fmt.Errorf("name %q: only letters, digits and hyphens are allowed", name)
		}
	}
	return nil
}

// toManifest is the inverse of toSpec, used when rewriting the file.
func (s peerSpec) toManifest() manifestBuddy {
	b := manifestBuddy{Name: s.name, Key: bcrypto.PubKeyB64(s.pin), Token: s.token}
	if s.expose != nil {
		b.Expose = &exposeValue{scope: *s.expose}
	}
	return b
}

// saveManifest writes the YAML manifest (0600 in a 0700 dir, same trust domain
// as known_peers), with the schema header for hand-editors.
//
// A-12: this used to be a bare os.WriteFile — neither atomic nor locked, the one
// trust file left out of the treatment the allowlist, the peer cache and the
// session store all get. A crash mid-write left a truncated YAML, which parses
// as "no buddies"; a concurrent CLI write could lose the other's edit. It now
// goes through the same trust-state lock and the same atomic rename.
func saveManifest(knownPeers, path string, specs []peerSpec) error {
	return withTrustStateLock(knownPeers, path, func() error {
		return saveManifestLocked(path, specs)
	})
}

// saveManifestLocked is saveManifest's body; the caller holds the trust-state
// lock (the revocation transactions in peerscmd.go write several files under one
// lock, and taking it again here would deadlock on flock).
func saveManifestLocked(path string, specs []peerSpec) error {
	m := peersManifest{}
	for _, s := range specs {
		m.Buddies = append(m.Buddies, s.toManifest())
	}
	body, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("peers-file %s: encode: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(path, append([]byte(manifestHeader), body...), 0o600)
}

// manifestNeedsMigration reports whether path exists in the legacy line format.
func manifestNeedsMigration(path string) (bool, error) {
	data, err := readManifest(path)
	if err != nil || data == nil {
		return false, err
	}
	return manifestIsLegacy(data), nil
}

// assemblePeers builds the supervisor's worker set as the union of the peers
// manifest and the stored sessions, keyed by pinned identity. A manifest entry
// contributes its bootstrap token; a stored session for a key already in the
// manifest just confirms it (the session, once present, takes over from the
// token). Stored sessions for keys NOT in the manifest are still maintained as
// reconnect-only peers, so previously paired buddies are not dropped.
func assemblePeers(cfg BuddyConfig) ([]peerSpec, error) {
	manifest, err := loadPeersFile(cfg.PeersFile)
	if err != nil {
		return nil, err
	}
	// A revoked key is filtered out of BOTH sources. This is the third of the
	// three places the revocation has to bite (the other two are the attempt
	// source and saveSession): it is what makes the SIGHUP that applies a
	// revocation stop the worker even if a session line for that buddy exists —
	// which is exactly the crash-safe intermediate state the revoke transaction
	// can leave behind, and was the resurrection path in A-01.
	revoked, err := revokedSet(trustBase(cfg.KnownPeers, cfg.PeersFile))
	if err != nil {
		return nil, err
	}
	byKey := map[string]int{} // pubkey b64 → index into specs
	var specs []peerSpec
	for _, s := range manifest {
		keyB64 := bcrypto.PubKeyB64(s.pin)
		if _, gone := revoked[keyB64]; gone {
			log.Printf("TRUST: action=revoked-skipped key=%s source=manifest", keyTag(keyB64))
			continue
		}
		byKey[keyB64] = len(specs)
		specs = append(specs, s)
	}

	sessions, err := loadSessions(cfg.KnownPeers)
	if err != nil {
		return nil, err
	}
	for _, s := range sessions {
		keyB64 := bcrypto.PubKeyB64(s.pin)
		if _, gone := revoked[keyB64]; gone {
			log.Printf("TRUST: action=revoked-skipped key=%s source=session", keyTag(keyB64))
			continue
		}
		if _, ok := byKey[keyB64]; ok {
			continue // already covered by the manifest (session resolved at runtime)
		}
		specs = append(specs, peerSpec{pin: s.pin}) // reconnect-only
	}

	// Hard cap: BuddyNet is a personal overlay for small trusted groups, not a
	// large-scale mesh. Above MaxBuddies, refuse fail-closed rather than run
	// degraded — the error names no product, operators pick their own scaler.
	if len(specs) > MaxBuddies {
		return nil, errTooManyBuddies(len(specs))
	}

	// VIP collision: two distinct keys whose SHA-256 maps to the same 10.66.X.Y
	// would make per-buddy routing ambiguous. Reject explicitly here instead of
	// silently misrouting — the VIP is an address, never an auth boundary.
	vips := make(map[netip.Addr]string, len(specs))
	for _, s := range specs {
		v := bcrypto.VirtualIP(s.pin)
		keyB64 := bcrypto.PubKeyB64(s.pin)
		if existing, collision := vips[v]; collision {
			return nil, fmt.Errorf(
				"VIP collision: keys %s and %s both map to %s — cannot maintain both "+
					"(use a different key, or report a bug)", keyTag(existing), keyTag(keyB64), v)
		}
		vips[v] = keyB64
	}
	return specs, nil
}
