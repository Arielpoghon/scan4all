package models

import (
	"gorm.io/gorm"
)

// Stored to ES
type SubDomain struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Tags       string   `json:"tags,omitempty"` // marks which tag it belongs to, e.g. hackerone
}

//http://127.0.0.1:9200/domain_index/_search?q=domain:%20in%20*qianxin*
type Domain struct {
	Domain string   `json:"domain"`
	Ips    []string `json:"ips"`
}

/*
Partial document update: the following code uses go json's omitempty so that when serializing
the update data object to json, only non-zero fields are serialized, implementing partial
updates. When using this approach in real projects, note that if the zero value of a field
has business meaning, a corresponding pointer type can be used instead.
*/
type SubDomainItem struct {
	gorm.Model
	Domain    string `json:"domain" gorm:"type:varchar(100);"`
	SubDomain string `json:"subDomain" gorm:"type:varchar(100);"`
	ToolName  uint64 `json:"toolName,omitempty" gorm:"type:varchar(100);"` // supports multiple tools
	Tags      string `json:"tags,omitempty" gorm:"type:varchar(200);"`     // marks which tag it belongs to, e.g. hackerone
}

// domain to ips
// ip to Domain
type Domain2Ips struct {
	gorm.Model
	Domain   string `json:"domain" gorm:"type:varchar(100);"`
	Ip       string `json:"ip" gorm:"type:varchar(50);"`
	ToolName uint64 `json:"toolName,omitempty" gorm:"type:varchar(200);"` // supports multiple tools
}

// Port scan and port vulnerability scan
type Ip2Ports struct {
	gorm.Model
	MyId          string `json:"myId,omitempty" gorm:"type:varchar(100);"` // corresponds to the ES domain id, may be empty
	Ip            string `json:"ip" gorm:"type:varchar(50);"`
	Port          int    `json:"port"`
	Des           string `json:"des,omitempty" gorm:"type:varchar(500);"`
	ToolName      uint64 `json:"toolName,omitempty" gorm:"type:varchar(200);"` // supports multiple tools
	VulsCheckFlag uint64 `json:"vulsCheckFlag,omitempty"`                      // each bit represents a tool, so up to 64 tools/plugins can scan this port
	VulsCheckRst  string `json:"vulsCheckRst,omitempty" gorm:"type:varchar(1000);"`
}

// ip geolocation info
// curl -H 'User-Agent:curl/1.0' http://ip-api.com/json/107.182.191.202|jq
type IpInfo struct {
	gorm.Model
	Continent     string  `json:"continent" gorm:"type:varchar(200);"`
	ContinentCode string  `json:"continentCode" gorm:"type:varchar(200);"`
	Country       string  `json:"country" gorm:"type:varchar(50);"`
	CountryCode   string  `json:"countryCode" gorm:"type:varchar(50);"`
	Region        string  `json:"region" gorm:"type:varchar(50);"`
	RegionName    string  `json:"regionName" gorm:"type:varchar(100);"`
	City          string  `json:"city" gorm:"type:varchar(100);"`
	District      string  `json:"district" gorm:"type:varchar(100);"`
	Zip           string  `json:"zip" gorm:"type:varchar(30);"`
	Lat           float64 `json:"lat"`
	Lon           float64 `json:"lon"`
	Timezone      string  `json:"timezone"  gorm:"type:varchar(30);"`
	Offset        string  `json:"offset"  gorm:"type:varchar(30);"`
	Currency      string  `json:"currency"  gorm:"type:varchar(30);"`
	Isp           string  `json:"isp"  gorm:"type:varchar(30);"`
	Org           string  `json:"org" gorm:"type:varchar(30);"`
	As            string  `json:"as" gorm:"type:varchar(30);"`
	Asname        string  `json:"asname" gorm:"type:varchar(30);"`
	Mobile        string  `json:"mobile" gorm:"type:varchar(30);"`
	Proxy         string  `json:"proxy" gorm:"type:varchar(30);"`
	Hosting       string  `json:"hosting" gorm:"type:varchar(100);"`
	Ip            string  `json:"query" gorm:"type:varchar(50);unique_index"` // IP
}

//// Execute the task
//type Task struct {
//	gorm.Model
//	Target   string `json:"target" gorm:"type:varchar(1000);"`
//	TaskType uint64 `json:"taskType"`
//	PluginId string `json:"pluginId" gorm:"type:varchar(100);"`
//	Status   uint64 `json:"status"` // status: pending, running, completed
//}
