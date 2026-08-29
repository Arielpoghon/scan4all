package util

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var EnableHoneyportDetection = true

// in-memory cache to avoid running multiple times for the same target
var hdCache sync.Map

var ipCIDS = regexp.MustCompile("^(\\d+\\.){3}\\d+\\/\\d+$")

// check the honeypot Server info
func CheckHoneyportDetection4HeaderServer(server, szUrl string) bool {
	if 50 < len(server) || 3 < len(strings.Split(server, ",")) {
		hdCache.Store(szUrl, true)
		SendLog(szUrl, string(Scan4all), "Honeypot found", "")
		return true
	}
	return false
}

// Add honeypot detection and automatically skip targets; default false skips honeypot detection
// consider the in-memory cached result
func HoneyportDetection(host string) bool {
	host = strings.TrimSpace(host)
	if !EnableHoneyportDetection || 5 > len(host) || ipCIDS.MatchString(host) {
		return false
	}
	if "http" != strings.ToLower(host[0:4]) {
		host = "http://" + host
	}
	oUrl, err := url.Parse(strings.TrimSpace(host))
	if err != err {
		return false
	}
	szK := oUrl.Scheme + "//" + oUrl.Hostname()

	if v, ok := hdCache.Load(szK); ok {
		return v.(bool)
	}
	if nil == err {
		timeout := time.Duration(8 * time.Second)
		var tr *http.Transport

		tr = &http.Transport{
			MaxIdleConnsPerHost: -1,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   true,
		}
		client := http.Client{
			Timeout:   timeout,
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse /* do not follow redirects */
			},
		}
		resp, err := client.Head(szK)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				if a, ok := resp.Header["Server"]; ok {
					if CheckHoneyportDetection4HeaderServer(a[0], szK) {
						return true
					}
				}
			}
		}
	}
	hdCache.Store(szK, false)

	return false
}
