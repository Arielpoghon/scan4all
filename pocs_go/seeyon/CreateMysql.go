package seeyon

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

//createMysql.jsp database sensitive information leak

func CreateMysql(u string) bool {
	var vuln = false
	if req, err := util.HttpRequset(u+"/yyoa/createMysql.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "root") {
			util.SendLog(req.RequestUrl, "seeyon", "Found vuln seeyon CreateMysql", "")
			vuln = true
		}
	}
	if req, err := util.HttpRequset(u+"/yyoa/ext/createMysql.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "root") {
			util.SendLog(req.RequestUrl, "seeyon", "Found vuln seeyon CreateMysql", "")
			vuln = true
		}
	}
	return vuln
}
