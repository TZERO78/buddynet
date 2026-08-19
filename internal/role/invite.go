package role

import (
	"fmt"
	"os"

	"github.com/tzero78/buddynet/internal/secret"
)

// showInvite displays the one-time invite blob for the human to hand over, then
// hides it again on a terminal (reveal-and-hide, so it does not linger in the
// scrollback of a shared screen) or prints it plainly when stdout is piped, so
// `INVITE=$(buddynet ... --invite)` keeps working for scripts and the Unraid
// plugin.
//
// The blob is still a bearer secret and still belongs on a trusted channel — the
// embedded key does not make the rendezvous token public. What the key changes is
// what a WRONG channel costs: the joining buddy pins this exact identity, so a
// handshake server that tries to put someone else on this end is refused without
// a human having to notice anything.
func showInvite(blob string) {
	if !secret.Interactive() {
		fmt.Println(blob)
		return
	}
	fmt.Fprint(os.Stderr, "\nInvite for your buddy — hand it over on a channel you trust (phone, Signal)\n"+
		"and have them pass it to --join. It is one-time and carries your identity,\n"+
		"so they pin YOUR key from it; treat it as a secret:\n")
	secret.RevealUntilKey(blob)
	fmt.Fprintln(os.Stderr, "Invite hidden — now waiting for your buddy to join...")
}
