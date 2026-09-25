package go_utils

import (
	"net/http"
	"regexp"
	"strings"
)

// Extract supply-chain information.
var SupplyChainReg *regexp.Regexp

var UrlMt []*regexp.Regexp = []*regexp.Regexp{
	regexp.MustCompile("^http[s]:\\/\\/[^\\/]+\\/?$"),
	regexp.MustCompile("^http[s]:\\/\\/[^\\/]+\\/[^\\/]+$")}

// Identify and process URL contexts.
// Ensure developer information is calculated only once per URL context.
func isCheck(szUrl string) bool {
	for _, x := range UrlMt {
		if x.MatchString(szUrl) {
			return true
		}
	}
	return false
}

// DoBody extracts developer information from the response body.
func DoBody(szUrl, szBody string, head *http.Header) {
	if ok := head.Get("Content-Type"); -1 < strings.Index(ok, "text/html") {
		a := SupplyChainReg.FindAllString(szBody, -1)
		if 0 < len(a) {
		}
	}
}

// Extract supply-chain information.
// Extract information only once for each successful context.
// Extract header information such as server and X* for each context.
func SupplyChain(szUrl, szBody string, head *http.Header) {
	szBody = strings.TrimSpace(szBody)
	if nil == head || "" == szBody || "" == szUrl || !isCheck(szUrl) {
		return
	}
	DoBody(szUrl, szBody, head)
}
