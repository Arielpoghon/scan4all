package brute

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

// Optimization considerations
//
//	1、All results for the same target within a day are cached and only executed once
//	2、Multi-threaded concurrent execution should be considered
func Basic_brute(url string) (username string, password string) {
	if req, err := util.HttpRequsetBasic("asdasdascsacacs", "adcadcadcadcadcadc", url, "HEAD", "", false, nil); err == nil {
		// Hypertext Transfer Protocol (HTTP) 401 Unauthorized is a client error status response code indicating that the client request has not been completed because it lacks valid authentication credentials for the requested resource
		// https://www.shuzhiduo.com/A/1y345GonJN/
		if req.StatusCode == 401 {
			for useri := range basicusers {
				for passi := range top100pass {
					if req2, err2 := util.HttpRequsetBasic(basicusers[useri], top100pass[passi], url, "HEAD", "", false, nil); err2 == nil {
						// 403 Forbidden is an HTTP status code in the HTTP protocol. A 403 status code means the server successfully parsed the request but the client does not have permission to access the resource
						// Theoretically possible: https://www.netspotapp.com/blog/hosting/403-forbidden.html
						// 1、After a successful brute-force, the page redirects (3XX)
						// 2、402 Payment Required
						// 3、403 Forbidden
						// 4、404 Not Found
						// 5、405 Method Not Allowed
						// 6、406 Not Acceptable
						// 7、407 Proxy Authentication Required
						// 8、408 Request Timeout, 410 Gone, 409 Conflict
						// 9、400 Bad Request
						if req2.StatusCode != 401 && req2.StatusCode != 400 && req2.StatusCode != 408 && req2.StatusCode < 405 {
							//pkg.LogJson(rst.Result{PluginName: pkg.GetPluginName("Basic_brute"), StatusCode: req2.StatusCode, URL: url, Technologies: []string{fmt.Sprintf("Found vuln basic password|%s:%s|%s", basicusers[useri], top100pass[passi], url)}})
							return basicusers[useri], top100pass[passi]
						}
					}
				}
			}
		}
	}
	return "", ""
}
