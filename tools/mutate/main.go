// Command mutate is a mutation-testing pilot: it makes small, deliberate changes
// to a package's source and reports which ones the package's own tests fail to
// notice.
//
// The question it answers is not "are there tests" and not "what is the
// coverage" — coverage says a line RAN, never that anything checked what it did.
// A mutant that survives is a line the tests execute and do not constrain: break
// it for real and the suite still goes green. In a package like internal/ticket,
// where every branch is a refusal that something else depends on, that
// distinction is the entire point.
//
// A surviving mutant is a QUESTION, not a verdict. It is either a genuine gap or
// an EQUIVALENT mutant — a change that cannot alter observable behaviour (a
// tightened bound nothing can reach, a guard another guard already covers).
// Telling the two apart is manual work, and it is where the value of a run
// actually lands.
//
// Design notes, since this is deliberately a tool and not a dependency:
//
//   - Mutants are compiled through `go test -overlay`, so mutated source lives in
//     a temp file and the working tree is NEVER written to. An interrupted run
//     leaves nothing to clean up — unlike edit-in-place-and-restore, which loses
//     that race exactly when it is least convenient.
//   - Every mutant re-parses the file from disk and applies the Nth candidate in
//     a fixed walk order, so runs are reproducible and no mutation can leak into
//     the next one.
//   - A mutant that fails to COMPILE is reported apart from one the tests killed.
//     Counting it as killed would flatter the score: the tests did not catch it,
//     the type checker did.
//
// Usage:
//
//	go run ./tools/mutate -pkg ./internal/ticket -src internal/ticket/ticket.go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

func main() {
	pkg := flag.String("pkg", "", "package pattern to test (e.g. ./internal/ticket)")
	src := flag.String("src", "", "source file to mutate (e.g. internal/ticket/ticket.go)")
	timeout := flag.Duration("timeout", 90*time.Second, "per-mutant test timeout")
	runFilter := flag.String("run", "", "optional -run filter passed to go test")
	verbose := flag.Bool("v", false, "print every mutant, not only survivors")
	flag.Parse()

	if *pkg == "" || *src == "" {
		fmt.Fprintln(os.Stderr, "usage: mutate -pkg ./internal/ticket -src internal/ticket/ticket.go")
		os.Exit(2)
	}
	if err := runPilot(*pkg, *src, *runFilter, *timeout, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "mutate: %v\n", err)
		os.Exit(1)
	}
}

// interactive reports whether stdout is a terminal, which decides whether the
// per-mutant progress line is worth printing at all.
var interactive = func() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

// outcome is what became of one mutant.
type outcome int

const (
	killed   outcome = iota // a test failed: the change was noticed
	survived                // every test passed: the change was not noticed
	invalid                 // the mutant did not compile, so the tests never ran
)

type result struct {
	desc string
	pos  token.Position
	out  outcome
}

func runPilot(pkg, src, runFilter string, timeout time.Duration, verbose bool) error {
	absSrc, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	orig, err := os.ReadFile(absSrc)
	if err != nil {
		return err
	}

	total, err := countCandidates(absSrc, orig)
	if err != nil {
		return err
	}
	if total == 0 {
		return fmt.Errorf("no mutation candidates in %s", src)
	}

	// The unmutated package must be green first. Without this check a red
	// baseline reads as "every mutant killed" — a perfect score that only means
	// the suite was failing the whole time.
	fmt.Printf("baseline: %s unmutated ... ", pkg)
	if ok, out := goTest(pkg, "", runFilter, timeout); !ok {
		fmt.Println("FAILED")
		return fmt.Errorf("tests do not pass before any mutation; fix that first:\n%s", out)
	}
	fmt.Println("ok")
	fmt.Printf("%d mutants to run against %s\n\n", total, pkg)

	tmp, err := os.MkdirTemp("", "mutate-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	results := make([]result, 0, total)
	for i := range total {
		mutSrc, meta, err := mutate(absSrc, orig, i)
		if err != nil {
			return fmt.Errorf("mutant %d: %w", i, err)
		}

		overlay, err := writeOverlay(tmp, i, absSrc, mutSrc)
		if err != nil {
			return err
		}

		r := result{desc: meta.desc, pos: meta.pos}
		ok, out := goTest(pkg, overlay, runFilter, timeout)
		switch {
		case ok:
			r.out = survived
		case looksLikeBuildFailure(out):
			r.out = invalid
		default:
			r.out = killed
		}
		results = append(results, r)

		switch {
		case verbose || r.out == survived:
			fmt.Printf("%-10s %s:%d  %s\n", label(r.out), filepath.Base(r.pos.Filename), r.pos.Line, r.desc)
		case interactive:
			// Only rewrite the line when something is there to rewrite it on.
			// Redirected to a file, \r turns the whole run into one unreadable
			// line — which is exactly where the output gets read from later.
			fmt.Printf("\r%d/%d mutants ", i+1, total)
		}
	}
	if interactive {
		fmt.Print("\r                    \r")
	}
	report(results)
	return nil
}

// writeOverlay puts the mutated source in a temp file and points a go overlay at
// it, so the compiler reads the mutant where the original sits without either
// file moving.
func writeOverlay(dir string, n int, absSrc string, mutSrc []byte) (string, error) {
	mutPath := filepath.Join(dir, fmt.Sprintf("mutant%d.go", n))
	// #nosec G703 -- dir comes from os.MkdirTemp and the name from an int
	// counter; no part of this path is derived from input.
	if err := os.WriteFile(mutPath, mutSrc, 0o600); err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]map[string]string{"Replace": {absSrc: mutPath}})
	if err != nil {
		return "", err
	}
	overlay := filepath.Join(dir, fmt.Sprintf("overlay%d.json", n))
	if err := os.WriteFile(overlay, body, 0o600); err != nil {
		return "", err
	}
	return overlay, nil
}

func label(o outcome) string {
	switch o {
	case survived:
		return "SURVIVED"
	case invalid:
		return "no-compile"
	default:
		return "killed"
	}
}

func report(results []result) {
	var k, s, inv int
	var survivors []result
	for _, r := range results {
		switch r.out {
		case killed:
			k++
		case survived:
			s++
			survivors = append(survivors, r)
		case invalid:
			inv++
		}
	}

	fmt.Println("── mutation pilot ───────────────────────────────────────────")
	fmt.Printf("  %d mutants: %d killed, %d survived, %d did not compile\n", len(results), k, s, inv)
	// The score counts only mutants the tests could actually run. A mutant that
	// does not compile says nothing about the tests in either direction, so
	// folding it in would move the number without meaning anything.
	if k+s > 0 {
		fmt.Printf("  score: %.1f%% of the %d compiling mutants killed\n", 100*float64(k)/float64(k+s), k+s)
	}
	if len(survivors) == 0 {
		fmt.Println("  no survivors")
		return
	}
	slices.SortFunc(survivors, func(a, b result) int { return a.pos.Line - b.pos.Line })
	fmt.Println("\n  survivors — each is either a test gap or an equivalent mutant:")
	for _, r := range survivors {
		fmt.Printf("    %s:%d  %s\n", filepath.Base(r.pos.Filename), r.pos.Line, r.desc)
	}
}

// goTest runs the package's tests, optionally through an overlay, and reports
// whether they passed along with the output needed to tell why they did not.
func goTest(pkg, overlay, runFilter string, timeout time.Duration) (bool, string) {
	// The outer deadline is the inner one plus room for the build: `go test
	// -timeout` only bounds the RUNNING tests, and a mutant that makes the
	// package loop at init would never reach them.
	ctx, cancel := context.WithTimeout(context.Background(), timeout+30*time.Second)
	defer cancel()

	args := []string{"test", "-count=1", "-timeout=" + timeout.String()}
	if overlay != "" {
		args = append(args, "-overlay="+overlay)
	}
	if runFilter != "" {
		args = append(args, "-run="+runFilter)
	}
	args = append(args, pkg)

	// #nosec G204 -- the command is the literal "go"; the arguments are this
	// tool's own flags, supplied by the developer running it. There is no trust
	// boundary here to cross: anyone who can pass -pkg can already run go.
	out, err := exec.CommandContext(ctx, "go", args...).CombinedOutput()
	return err == nil, string(out)
}

// looksLikeBuildFailure separates "the mutant is not valid Go" from "the tests
// failed". go test reports build errors under a [build failed] / setup failed
// banner rather than as a failing test, which is the seam used here.
func looksLikeBuildFailure(out string) bool {
	for _, marker := range []string{"[build failed]", "[setup failed]", "build constraints exclude"} {
		if strings.Contains(out, marker) {
			return true
		}
	}
	return false
}

// ---- mutation operators ----------------------------------------------------

// candidate is one mutation, identified by its index in a fixed walk order.
// apply takes the file so an operator that must REPLACE a node (rather than edit
// one in place) can reach the parent that holds the pointer.
type candidate struct {
	desc  string
	pos   token.Pos
	apply func(f *ast.File)
}

type meta struct {
	desc string
	pos  token.Position
}

// comparisonFlips are the operator swaps worth making. Boundary swaps (< ↔ <=)
// find off-by-one holes; sense swaps (== ↔ !=, < ↔ >=) find branches that
// nothing constrains at all. Both matter here, because a ticket check is a
// boundary AND a sense at the same time.
var comparisonFlips = map[token.Token][]token.Token{
	token.EQL: {token.NEQ},
	token.NEQ: {token.EQL},
	token.LSS: {token.LEQ, token.GEQ},
	token.LEQ: {token.LSS, token.GTR},
	token.GTR: {token.GEQ, token.LEQ},
	token.GEQ: {token.GTR, token.LSS},
}

var logicalFlips = map[token.Token]token.Token{
	token.LAND: token.LOR,
	token.LOR:  token.LAND,
}

// collect walks the file in a fixed order and offers every mutation it can make.
// That order is the only thing identifying a mutant, so it must not depend on
// map iteration: the operator tables are INDEXED by the token found in the
// source, never ranged over.
func collect(f *ast.File) []candidate {
	var out []candidate

	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BinaryExpr:
			for _, alt := range comparisonFlips[x.Op] {
				out = append(out, candidate{
					desc:  fmt.Sprintf("comparison %s -> %s", x.Op, alt),
					pos:   x.OpPos,
					apply: func(*ast.File) { x.Op = alt },
				})
			}
			if alt, ok := logicalFlips[x.Op]; ok {
				out = append(out, candidate{
					desc:  fmt.Sprintf("logic %s -> %s", x.Op, alt),
					pos:   x.OpPos,
					apply: func(*ast.File) { x.Op = alt },
				})
			}

		case *ast.UnaryExpr:
			// Dropping a `!` inverts a guard — the cheapest way to ask whether
			// anything actually depends on the condition being that way round.
			if x.Op == token.NOT {
				pos := x.OpPos
				out = append(out, candidate{
					desc:  "drop negation (!x -> x)",
					pos:   pos,
					apply: func(f *ast.File) { dropNegation(f, pos) },
				})
			}

		case *ast.ReturnStmt:
			if len(x.Results) != 1 {
				return true
			}
			id, ok := x.Results[0].(*ast.Ident)
			if !ok || (id.Name != "true" && id.Name != "false") {
				return true
			}
			flipped := "false"
			if id.Name == "false" {
				flipped = "true"
			}
			out = append(out, candidate{
				desc:  fmt.Sprintf("return %s -> return %s", id.Name, flipped),
				pos:   id.Pos(),
				apply: func(*ast.File) { id.Name = flipped },
			})

		case *ast.BasicLit:
			if x.Kind != token.INT {
				return true
			}
			v, err := strconv.Atoi(x.Value)
			if err != nil {
				return true
			}
			for _, d := range []int{1, -1} {
				want := strconv.Itoa(v + d)
				out = append(out, candidate{
					desc:  fmt.Sprintf("literal %s -> %s", x.Value, want),
					pos:   x.Pos(),
					apply: func(*ast.File) { x.Value = want },
				})
			}

		case *ast.BlockStmt:
			// Deleting a whole guard is the strongest operator for this codebase:
			// nearly every check here is `if <bad> { return reject(...) }`, and a
			// suite that stays green with one of them simply GONE never exercised
			// that refusal in the first place.
			for i, stmt := range x.List {
				ifs, ok := stmt.(*ast.IfStmt)
				if !ok || ifs.Else != nil || len(ifs.Body.List) != 1 {
					continue
				}
				if _, isReturn := ifs.Body.List[0].(*ast.ReturnStmt); !isReturn {
					continue
				}
				out = append(out, candidate{
					desc: "delete guard (if … { return … })",
					pos:  ifs.Pos(),
					// Clip the prefix so the append allocates instead of writing
					// through the slice the AST still holds.
					apply: func(*ast.File) { x.List = append(x.List[:i:i], x.List[i+1:]...) },
				})
			}
		}
		return true
	})
	return out
}

// dropNegation replaces `!x` with `x`. Removing a unary operator means swapping
// the NODE, which only the parent holding the pointer can do — hence the second
// walk rather than an edit in place.
func dropNegation(f *ast.File, target token.Pos) {
	unwrap := func(e ast.Expr) (ast.Expr, bool) {
		u, ok := e.(*ast.UnaryExpr)
		if !ok || u.Op != token.NOT || u.OpPos != target {
			return nil, false
		}
		return u.X, true
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.IfStmt:
			if inner, ok := unwrap(x.Cond); ok {
				x.Cond = inner
			}
		case *ast.BinaryExpr:
			if inner, ok := unwrap(x.X); ok {
				x.X = inner
			}
			if inner, ok := unwrap(x.Y); ok {
				x.Y = inner
			}
		case *ast.ParenExpr:
			if inner, ok := unwrap(x.X); ok {
				x.X = inner
			}
		case *ast.ReturnStmt:
			for i, r := range x.Results {
				if inner, ok := unwrap(r); ok {
					x.Results[i] = inner
				}
			}
		}
		return true
	})
}

func countCandidates(path string, src []byte) (int, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	return len(collect(f)), nil
}

// mutate re-parses the original source and applies exactly the nth candidate.
func mutate(path string, src []byte, n int) ([]byte, meta, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, meta{}, fmt.Errorf("parse %s: %w", path, err)
	}
	cands := collect(f)
	if n < 0 || n >= len(cands) {
		return nil, meta{}, fmt.Errorf("candidate %d out of range (have %d)", n, len(cands))
	}
	c := cands[n]
	c.apply(f)

	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, f); err != nil {
		return nil, meta{}, fmt.Errorf("print mutant: %w", err)
	}
	return buf.Bytes(), meta{desc: c.desc, pos: fset.Position(c.pos)}, nil
}
