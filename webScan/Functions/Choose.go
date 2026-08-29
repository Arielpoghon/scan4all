package Funcs

import (
	Configs "github.com/GhostTroops/scan4all/webScan/config"
)

type extras struct {
	timeout_count map[string]int
	replace       string
}

var Extra extras

func Choose(urllist *[]string) {
	//timeout_count := make(map[string]int)
	Extra.timeout_count = make(map[string]int) // used to track whether a url has exceeded five timeouts or failures; skip the url if it exceeds five

	if Configs.UserObject.AllJson == true {
		final_ALLurl_ALLJson(urllist)
	}
}
