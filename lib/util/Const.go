package util

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
)

// global thread control
var Wg *sync.WaitGroup = &sync.WaitGroup{}

var Version string

// global control
var RootContext = context.Background()

// globally stop all threads
var Ctx_global, StopAll = context.WithCancel(RootContext)

// used many times; compiling once is more efficient
var DeleteMe = regexp.MustCompile("rememberMe=deleteMe")

// custom http headers
var CustomHeaders []string

/*
X-Forwarded-Host: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
*/
// get custom headers in raw mode
func GetCustomHeadersRaw() string {
	if 0 < len(CustomHeaders) {
		return "\r\n" + strings.Join(CustomHeaders, "\r\n")
	}
	return ""
}

// globally set headers
func SetHeader(m *http.Header) {
	if 0 < len(CustomHeaders) && nil != m {
		for _, i := range CustomHeaders {
			n := strings.Index(i, ":")
			m.Set(strings.TrimSpace(i[:n]), strings.TrimSpace(i[n+1:]))
		}
	}
}

// set headers in map format
func SetHeader4Map(m *map[string]string) {
	if 0 < len(CustomHeaders) && nil != m {
		for _, i := range CustomHeaders {
			n := strings.Index(i, ":")
			(*m)[strings.TrimSpace(i[:n])] = strings.TrimSpace(i[n+1:])
		}
	}
}

// Async execution wrapper, only suitable for methods with no return value or returning via channels
// the program's main waits as a whole
func DoSyncFunc(cbk func()) {
	Wg.Add(1)
	go func() {
		defer Wg.Done()
		for {
			select {
			case <-Ctx_global.Done():
				fmt.Println("Received global exit event")
				return

			default:
				cbk()
				return
			}
		}
	}()
}

// check cookie
// Shiro CVE_2016_4437 cookie
// unified check entry for the other POC cookies
func CheckShiroCookie(header *http.Header) int {
	var SetCookieAll string
	if nil != header {
		for i := range (*header)["Set-Cookie"] {
			SetCookieAll += (*header)["Set-Cookie"][i]
		}
		return len(DeleteMe.FindAllStringIndex(SetCookieAll, -1))
	}
	return 0
}

// Match whether the www-Authenticate header in the response indicates an authentication requirement
var BaseReg = regexp.MustCompile("(?i)Basic\\s*realm\\s*=\\s*")

// used for channel communication
type PocCheck struct {
	Wappalyzertechnologies *[]string
	URL                    string
	FinalURL               string
	Checklog4j             bool
}

// go POC detection channel, avoids circular imports
var PocCheck_pipe = make(chan *PocCheck, 64)

// unified header check, and invoke the appropriate go poc for further exploitation/detection
//
//  1. requires authentication
//  2. shiro
func CheckHeader(header *http.Header, szUrl string) {
	DoSyncFunc(func() {
		if nil != header {
			a1 := []string{}
			if v := (*header)["www-Authenticate"]; 0 < len(v) {
				if 0 < len(BaseReg.FindAll([]byte(v[0]), -1)) {
					a1 = append(a1, "basic")
				}
			}
			if 0 < CheckShiroCookie(header) {
				a1 = append(a1, "shiro")
			}
			if 0 < len(a1) && os.Getenv("NoPOC") != "true" {
				if !TestRepeat(a1, szUrl, szUrl, "header") {
					PocCheck_pipe <- &PocCheck{Wappalyzertechnologies: &a1, URL: szUrl, FinalURL: szUrl, Checklog4j: false}
				}
			}
		}
	})
}
