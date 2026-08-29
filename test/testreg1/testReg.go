package main

import (
	"context"
	_ "embed"
	"github.com/GhostTroops/scan4all/lib/util"
)

// test whether the regular expression is correct
func main() {
	// stop all fuzz for the current target midway
	_, stop := context.WithCancel(util.Ctx_global)
	stop()
	stop()
	stop()
	stop()

}
