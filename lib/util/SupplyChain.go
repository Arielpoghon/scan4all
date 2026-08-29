package util

import (
	"net/http"
	"regexp"
	"strings"
)

// Extract supply chain info
var SupplyChainReg *regexp.Regexp

var UrlMt []*regexp.Regexp = []*regexp.Regexp{
	regexp.MustCompile("^http[s]:\\/\\/[^\\/]+\\/?$"),
	regexp.MustCompile("^http[s]:\\/\\/[^\\/]+\\/[^\\/]+$")}

// URL context recognition and processing
// Ensure each URL context only counts the vendor info once
func isCheck(szUrl string) bool {
	for _, x := range UrlMt {
		if x.MatchString(szUrl) {
			return true
		}
	}
	return false
}

// Extract vendor info from the body
func DoBody(szUrl, szBody string, head *http.Header) {
	if ok := head.Get("Content-Type"); -1 < strings.Index(ok, "text/html") {
		a := SupplyChainReg.FindAllString(szBody, -1)
		if 0 < len(a) {
		}
	}
}

// Extract supply chain info
// Same context, only extract once on success
// Extract header info: server, X*, extracted in different contexts
func SupplyChain(szUrl, szBody string, head *http.Header) {
	szBody = strings.TrimSpace(szBody)
	if nil == head || "" == szBody || "" == szUrl || !isCheck(szUrl) {
		return
	}
	DoBody(szUrl, szBody, head)
}
