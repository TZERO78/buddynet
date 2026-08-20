// Package flagdrift scans the artifacts this project ships — systemd units, the
// compose file, the Unraid plugin, the lab scripts — for command-line flags that
// the binaries no longer define.
//
// It exists because of finding A-05: the shipped
// deployments/systemd/buddynet-public-handshake.service passed --quic-handshake
// for a full release after protocol v8 removed it. The binary exits 2 on an
// unknown flag, so the unit never started, and nothing in CI ever looked at a
// shipped file.
//
// Two design rules, both learned from that finding:
//
//  1. The flag names come from the binary's own registerFlags via a throwaway
//     flag.FlagSet — never from a pattern over main.go. A pattern would be a
//     second definition of the flag set, i.e. a second thing that can drift.
//
//  2. Only ACTIVE artifacts are scanned, by explicit list. CHANGELOG.md,
//     docs/plans/ and the archived plans are supposed to name flags that no
//     longer exist; a hit there is a false alarm, and a gate that cries wolf is
//     a gate somebody switches off.
//
// Each binary's package has a small test that calls Scan with its own flag set;
// keeping the scan here rather than duplicating it means the two tests cannot
// disagree about what an artifact is.
package flagdrift

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Artifact is one shipped file to scan.
type Artifact struct{ Path string }

// ActiveArtifacts is deliberately an explicit list plus a few narrow globs, not
// a repo-wide walk: a new deployment file has to be added here on purpose.
func ActiveArtifacts(root string) []Artifact {
	paths := []string{
		filepath.Join(root, "deployments/docker-compose.yml"),
		filepath.Join(root, "unraid/BuddyNet/buddynet.plg"),
	}
	for _, pat := range []string{
		"deployments/systemd/*.service",
		"lab/*.sh",
		"lab/*/*.sh",
	} {
		matches, err := filepath.Glob(filepath.Join(root, pat))
		if err != nil {
			continue
		}
		paths = append(paths, matches...)
	}
	seen := map[string]bool{}
	var out []Artifact
	for _, p := range paths {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, Artifact{Path: p})
	}
	return out
}

// FlagPattern matches long-form flag references: --name or --name=value.
// Single-dash forms are deliberately not matched — in shell text a bare "-L" is
// as likely to be an ls option as a buddynet flag.
var FlagPattern = regexp.MustCompile(`--([a-zA-Z][a-zA-Z0-9-]*)`)

// BinaryOf reports which binary a line invokes, or "" for a line that invokes
// neither. vars holds shell variables THIS file assigns a buddynet path to (see
// BuddynetVars): the lab scripts run the binary through $BN or $BIN, but other
// scripts point those very same names at a different tool (lab/wg-spike), and
// charging its flags to buddynet would be a false alarm — the kind that gets a
// gate switched off.
func BinaryOf(line string, vars []string) string {
	if strings.Contains(line, "buddynet-handshake") {
		return "buddynet-handshake"
	}
	markers := append([]string{"buddynet", "ExecStart", "command:"}, vars...)
	for _, marker := range markers {
		if strings.Contains(line, marker) {
			return "buddynet"
		}
	}
	return ""
}

// shellAssign matches a shell variable assignment at the start of a line.
var shellAssign = regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)

// BuddynetVars returns the "$NAME"/"${NAME}" forms of every shell variable this
// file assigns a value that names the buddynet binary. It is what makes
// "$BIN --foo" in one lab script count and the identical line in another (where
// BIN is lab/wg-spike) not.
func BuddynetVars(content string) []string {
	var out []string
	for _, m := range shellAssign.FindAllStringSubmatch(content, -1) {
		name, val := m[1], m[2]
		if !strings.Contains(val, "buddynet") || strings.Contains(val, "buddynet-handshake") {
			continue
		}
		out = append(out, "$"+name, "${"+name+"}")
	}
	return out
}

// foreign lists long flags belonging to OTHER tools that appear on the same
// lines (docker, systemd-run, ip, wg, curl, rsync …). Without this the gate
// would report them as drift and be switched off within a week.
var foreign = map[string]bool{
	"help": true, "version": true, "quiet": true, "verbose": true, "rm": true,
	"network": true, "detach": true, "build": true, "no-cache": true,
	"file": true, "format": true, "filter": true, "user": true, "workdir": true,
	"env": true, "privileged": true, "cap-add": true, "device": true,
	"volume": true, "publish": true, "tty": true, "interactive": true,
	"entrypoint": true, "pull": true, "force": true, "all": true, "long": true,
	"short": true, "color": true, "no-pager": true, "unit": true, "since": true,
	"follow": true, "lines": true, "output": true, "property": true,
	"type": true, "json": true, "brief": true, "numeric": true, "oneline": true,
	"details": true, "statistics": true, "recursive": true, "delete": true,
	"exclude": true, "archive": true, "checksum": true, "dry-run": true,
	"progress": true, "partial": true, "timeout": true, "silent": true,
	"connect-timeout": true, "show-error": true, "location": true, "data": true,
	"header": true, "insecure": true, "fail": true, "retry": true,
	"max-time": true, "user-agent": true, "cacert": true, "cert": true,
	"no-buffer": true, "wait": true, "no-healthcheck": true, "abort-on-container-exit": true,
	"exit-code-from": true, "remove-orphans": true, "project-name": true,
	// docker network/run and curl, on lines that also mention buddynet (a network
	// or container named after it, or a curl into the lab):
	"subnet": true, "ip": true, "resolve": true, "gateway": true, "label": true,
	"restart": true, "add-host": true, "sysctl": true, "hostname": true,
}

// Names returns every flag name a register function defines, by running it
// against a throwaway FlagSet. -h/-help are added because the flag package
// answers them itself.
func Names(register func(*flag.FlagSet)) map[string]bool {
	fs := flag.NewFlagSet("flagdrift", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	register(fs)
	names := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) { names[f.Name] = true })
	names["h"] = true
	names["help"] = true
	return names
}

// Finding is one artifact line passing a flag the binary does not define.
type Finding struct {
	Path string
	Line int
	Flag string
	Text string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d passes --%s, which the binary does not define:\n  %s", f.Path, f.Line, f.Flag, f.Text)
}

// Scan checks every active artifact for flags passed to the named binary that
// are not in known. Lines that invoke a different binary — or nothing at all —
// are skipped, as are comments: a comment MAY name a removed flag (the fixed
// systemd unit explains why the old one went away), and documentation is not an
// invocation.
func Scan(root, binary string, known map[string]bool) ([]Finding, int, error) {
	var findings []Finding
	scanned := 0
	for _, a := range ActiveArtifacts(root) {
		f, err := os.Open(a.Path) // #nosec G304 -- paths come from this package's own list
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, scanned, err
		}
		scanned++
		content, rerr := os.ReadFile(a.Path) // #nosec G304 -- this package's own list
		if rerr != nil {
			f.Close()
			return nil, scanned, rerr
		}
		vars := BuddynetVars(string(content))
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		line := 0
		for sc.Scan() {
			line++
			text := sc.Text()
			trimmed := strings.TrimSpace(text)
			if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
				continue
			}
			if BinaryOf(text, vars) != binary {
				continue
			}
			for _, m := range FlagPattern.FindAllStringSubmatch(text, -1) {
				name := m[1]
				if foreign[name] || known[name] {
					continue
				}
				rel, rerr := filepath.Rel(root, a.Path)
				if rerr != nil {
					rel = a.Path
				}
				findings = append(findings, Finding{Path: rel, Line: line, Flag: name, Text: trimmed})
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return nil, scanned, err
		}
	}
	return findings, scanned, nil
}
