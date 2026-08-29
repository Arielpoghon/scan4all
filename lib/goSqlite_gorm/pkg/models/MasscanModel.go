package models

import (
	"encoding/xml"
	"github.com/asaskevich/govalidator"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"log"
	"net/url"
	"regexp"
)

// Scan target, not stored, used with channels
type Target4Chan struct {
	TaskId     string `json:"task_id"`     // task id
	ScanWeb    string `json:"scan_web"`    // after base64 decoding
	ScanType   int64  `json:"scan_type"`   // scan type
	ScanConfig string `json:"scan_config"` // various detailed configs of this task, in json string format
}

// Address
type Address struct {
	Addr     string `xml:"addr,attr" json:"addr" gorm:"primaryKey;type:varchar(60)"`
	AddrType string `xml:"addrtype,attr" json:"addr_type" gorm:"type:varchar(20)"`
}

// State
type State struct {
	State     string `xml:"state,attr" json:"state" gorm:"type:varchar(20)"`
	Reason    string `xml:"reason,attr" json:"reason" gorm:"type:varchar(20)"`
	ReasonTTL string `xml:"reason_ttl,attr" json:"reason_ttl" gorm:"type:varchar(20)"`
}

// nmap mode
type Nmaprun struct {
	XMLName    xml.Name `xml:"nmaprun"`
	StartTime  string   `xml:"start,attr"`
	Scanner    string   `xml:"scanner,attr"`
	Version    string   `xml:"version,attr"`
	XmlVersion string   `xml:"xmloutputversion,attr"`
}

// Host info
//  foreignKey should name the model-local key field that joins to the foreign entity.
//  references should name the foreign entity's primary or unique key.
type Host struct {
	Address Address `json:"address" xml:"address" gorm:"embedded;"`
	// association_autoupdate:true;association_autocreate:true;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;
	Ports []Ports `json:"Ports" xml:"Ports>port" gorm:"foreignKey:addr;References:addr;"` // association_autocreate:true; // many2many:Host_Ports;foreignKey:ID;References:ID;
}

// `xml:",innerxml"`
//func (cm Host) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
//	if cm.Address != nil {
//		err := e.EncodeToken(cm.comment)
//		if err != nil {
//			return err
//		}
//	}
//	return e.Encode(cm.Member)
//}

// Port info
type Ports struct {
	Addr     string  `json:"addr" gorm:"type:varchar(60);unique_index:addr,protocol,port_id"`
	Protocol string  `xml:"protocol,attr" json:"protocol" gorm:"type:varchar(10);"`
	PortId   string  `xml:"portid,attr" json:"port_id"  gorm:"type:varchar(10);"`
	State    State   `json:"state" xml:"state" gorm:"embedded;"`
	Service  Service `json:"service" xml:"service"  gorm:"embedded;"`
}

// Service info
type Service struct {
	Name   string `xml:"name,attr" json:"name"  gorm:"type:varchar(20);"`
	Banner string `xml:"banner,attr" json:"banner"  gorm:"type:varchar(800);"`
}

// Event data
type EventData struct {
	EventType int64         // type: masscan, nmap
	EventData []interface{} // func, params
	Task      *Target4Chan  // the current task data
	//Ips            []string                                         // ip related to the current task
	//SubDomains2Ips *map[string]map[string]map[int]map[string]string // all subdomains -> ip -> port -> port info
}

var (
	dnsclient *dnsx.DNSX
)

func init() {
	dnsOptions := dnsx.DefaultOptions
	dnsOptions.MaxRetries = 3
	dnsOptions.Hostsfile = true
	var err error
	dnsclient, err = dnsx.New(dnsOptions)
	if nil != err {
		log.Println("dnsx.New(dnsOptions) ", err)
	}
}

// target: url, dns (domain), ip
// resolve and output ip
func (r *EventData) Target2Ip() []string {
	var a []string
	t := r.Task.ScanWeb
	if govalidator.IsCIDR(t) {
		a = append(a, t)
	} else if govalidator.IsIP(t) {
		a = append(a, t)
	} else if govalidator.IsDNSName(t) {
		if nil != dnsclient {
			if ips, err := dnsclient.Lookup(t); nil == err {
				a = append(a, ips...)
			}
		}
	} else if govalidator.IsURL(t) {
		if oU1, err := url.Parse(r.Task.ScanWeb); nil == err && nil != oU1 {
			t = oU1.Hostname()
			if "" == t {
				t = r.Task.ScanWeb
			}
			if nil != dnsclient {
				if ips, err := dnsclient.Lookup(t); nil == err {
					a = append(a, ips...)
				}
			}
		}
	}

	return a
}

// regex for extracting ip
var GetIpPort = regexp.MustCompile("Discovered open port (\\d+)\\/tcp on ((\\d+\\.){3}\\d+)")
var GetBanner = regexp.MustCompile("Banner on port (\\d+)/tcp on ((\\d+\\.){3}\\d+): \\[([^\\]]+)\\] ([^\\ ]+)( ([^=]+)=((\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})|[^ ]+))*")
