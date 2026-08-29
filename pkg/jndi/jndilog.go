package jndi

import (
	"encoding/hex"
	"github.com/GhostTroops/scan4all/lib/util"
)

// jndi log check
func Jndilogchek(randomstr string) bool {
	if JndiLog == nil {
		return false
	}
	for _, log := range JndiLog {
		HexRandomstr := hex.EncodeToString([]byte(randomstr))
		if util.StrContains(log, HexRandomstr) {
			return true
		}
	}
	return false
}
