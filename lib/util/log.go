package util

import (
	"encoding/json"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/pkg/models"
	"log"
	"os"
	"runtime"
	"strings"
)

const Scan4all = "scan4all"

// out filename
var Output = ""

// // Use the calling method name as the plugin name
func GetPluginName(defaultVal string) string {
	pc, _, _, ok := runtime.Caller(1)
	details := runtime.FuncForPC(pc)
	if ok && details != nil {
		return details.Name()
	}
	return defaultVal
}

// 1. optimize the code, unify result output for easier maintenance
func SendLog(szUrl, szVulType, Msg, Payload string) {
	v := &SimpleVulResult{
		Url:     szUrl,
		VulKind: string(Scan4all),
		VulType: szVulType,
		Payload: Payload,
		Msg:     strings.TrimSpace(Msg) + " " + szVulType,
	}
	SendAnyData(v, Scan4all)
	Writeoutput(v)
}

func GetEsType(s int64) ESaveType {
	return Scan4all
}

// dedicated sender for results of the modified engine functions
func SendEngineLog(evt *models.EventData, nCurType int64, data ...interface{}) {
	if nil != data && 0 < len(data) {
		v := &SimpleVulResult{
			Url:      evt.Task.ScanWeb,
			VulKind:  string(Scan4all),
			ScanType: nCurType,
			ScanData: data,
		}
		s := GetEsType(nCurType)
		if "" != s {
			SendAnyData(v, GetEsType(nCurType))
			Writeoutput(v)
		} else {
			log.Printf("SendEngineLog can not find type %d\n", nCurType)
		}
	}
}

// dedicated sender for results of the modified engine functions
func SendEngineLog4Url(Url string, nCurType int64, data ...interface{}) {
	if nil != data && 0 < len(data) {
		v := &SimpleVulResult{
			Url:      Url,
			VulKind:  string(Scan4all),
			ScanType: nCurType,
			ScanData: data,
		}
		SendAnyData(v, Scan4all)
		Writeoutput(v)
	}
}

func Writeoutput(v interface{}) {
	if 1 > len(Output) {
		return
	}
	var szLog string
	if strings.HasSuffix(Output, ".csv") {
		data, _ := json.Marshal(v)
		szLog = string(data)
	} else {
		szLog = fmt.Sprintf("%+v", v)
	}
	f, err := os.OpenFile(Output, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Could not create output fiale '%s': %s\n", Output, err)
		return
	}
	defer f.Close() //nolint
	f.WriteString(szLog)

}
