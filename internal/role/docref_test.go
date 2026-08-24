package role

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// docsRef matches a "docs/<NAME>.md" path mentioned anywhere in the Go sources.
// (The placeholder above is deliberately written with angle brackets so this
// comment does not match its own pattern.)
var docsRef = regexp.MustCompile(`docs/[A-Za-z0-9_-]+\.md`)

// TestDocReferencesExist keeps operator-facing error messages honest. The
// "no path to the partner" advice in noPathAdvice pointed at docs/CONNECTIVITY.md
// for two releases while that file did not exist — a dead link handed to somebody
// at the exact moment nothing works. Nothing caught it, because a missing file is
// not a compile error and no test read the string.
//
// So: every docs/*.md path named in the Go sources of this module has to resolve
// to a real file. Cheap, and it fails on the commit that breaks it rather than in
// somebody's terminal.
func TestDocReferencesExist(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	seen := map[string][]string{} // doc path -> source files naming it
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip VCS, build output and nested checkouts. `.claude/worktrees`
			// holds git worktrees of this same repo: walking them would report
			// another branch's sources as if they were this tree's, and they are
			// absent in CI anyway. lab/ and cmd/ are deliberately included — an
			// operator reads those strings too.
			switch d.Name() {
			case ".git", "dist", ".claude":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, rerr := os.ReadFile(path) // #nosec G304 -- walking this module's own tree
		if rerr != nil {
			return rerr
		}
		for _, ref := range docsRef.FindAllString(string(src), -1) {
			rel, _ := filepath.Rel(root, path)
			seen[ref] = append(seen[ref], rel)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk sources: %v", walkErr)
	}
	if len(seen) == 0 {
		t.Fatal("no docs/*.md references found at all — the regexp or the walk is broken, " +
			"and a test that can never fail is worse than no test")
	}

	for ref, sources := range seen {
		if _, statErr := os.Stat(filepath.Join(root, ref)); statErr != nil {
			t.Errorf("%s is referenced by %s but does not exist — an operator following that "+
				"pointer lands nowhere", ref, strings.Join(sources, ", "))
		}
	}
}
