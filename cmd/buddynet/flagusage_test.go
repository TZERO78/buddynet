package main

import (
	"flag"
	"strings"
	"testing"
)

// TestFlagPlaceholdersAreNames guards a quiet trap in the standard flag package:
// the FIRST backticked word in a flag's usage string becomes the placeholder
// shown after the flag name. Backticks are also the natural way to mark a command
// in prose, so
//
//	"…legacy line format still read — run `peers migrate`"
//
// rendered as
//
//	-peers-file peers migrate
//
// instead of `-peers-file PATH`. Nothing fails, the help text just quietly starts
// lying about how the flag is used — and `--help` is this project's single source
// for flags, so it has to be right.
//
// A placeholder containing whitespace is always this mistake: real ones are one
// word (PATH, ID, DURATION).
func TestFlagPlaceholdersAreNames(t *testing.T) {
	fs := flag.NewFlagSet("buddynet", flag.ContinueOnError)
	registerFlags(fs)

	var checked int
	fs.VisitAll(func(f *flag.Flag) {
		name, _ := flag.UnquoteUsage(f)
		checked++
		if strings.ContainsAny(name, " \t") {
			t.Errorf("--%s renders as %q — the flag package took the first backticked "+
				"phrase in its usage text as the placeholder. Backtick the placeholder "+
				"itself (`PATH`, `ID`) and quote commands in the prose some other way",
				f.Name, "-"+f.Name+" "+name)
		}
	})
	if checked < 20 {
		t.Fatalf("only %d flags visited — registerFlags is not wiring them up, so this "+
			"test would pass vacuously", checked)
	}
}
