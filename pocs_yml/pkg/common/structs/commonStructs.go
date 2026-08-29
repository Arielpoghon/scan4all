package structs

import (
	"github.com/GhostTroops/scan4all/pocs_yml/pkg/xray/structs"
	"net/http"
	"strings"
)

var (
	CeyeApi                  string
	CeyeDomain               string
	ReversePlatformType      structs.ReverseType
	DnslogCNGetDomainRequest *http.Request
	DnslogCNGetRecordRequest *http.Request
)

func InitReversePlatform(api, domain string) {
	if api != "" && domain != "" && strings.HasSuffix(domain, ".ceye.io") {
		CeyeApi = api
		CeyeDomain = domain
		ReversePlatformType = structs.ReverseType_Ceye
	} else {
		ReversePlatformType = structs.ReverseType_DnslogCN

		// Set request-related parameters
		DnslogCNGetDomainRequest, _ = http.NewRequest("GET", "http://dnslog.cn/getdomain.php", nil)
		DnslogCNGetRecordRequest, _ = http.NewRequest("GET", "http://dnslog.cn/getrecords.php", nil)

	}
}
