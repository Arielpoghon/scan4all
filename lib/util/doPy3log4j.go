package util

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
)

var log4jsv sync.Map

// 1. if $HOME/MyWork/log4j-scan exists, run the python3 version of the log4j detection
// 2. run only once per target, based on an in-memory cache
// 3. only supports: https://github.com/hktalent/log4j-scan version
func DoLog4j(szUrl string) {
	if 5 > len(szUrl) || !FileExists(UserHomeDir+"/MyWork/log4j-scan") {
		//fmt.Println("DoLog4j: ", 5 > len(szUrl), !FileExists(UserHomeDir+"/MyWork/log4j-scan"))
		return
	}
	DoSyncFunc(func() {
		if "" == EsUrl {
			EsUrl = GetValByDefault("esUrl", "http://127.0.0.1:9200/%s_index/_doc/%s")
		}
		// avoid parse errors
		szEsUrl := fmt.Sprintf(EsUrl, "log4j", "xx01")
		oUrl, err := url.Parse(strings.TrimSpace(szEsUrl))
		if nil == err {
			p1, err := os.Getwd()
			if nil == err {
				// the url where the log4j result is reported
				szU1 := oUrl.Scheme + "://" + oUrl.Host
				if _, ok := log4jsv.Load(szU1); !ok {
					log4jsv.Store(szU1, true)
					if "http" != strings.ToLower(szUrl[0:4]) {
						szUrl = "http://" + szUrl
					}
					DoCmd(p1+"/config/doPy3log4j.sh", szUrl, szU1)
				}
			}
		}
	})
}
