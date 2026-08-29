package models

import (
	util "github.com/hktalent/go-utils"
	"gorm.io/gorm"
)

// Task data
type Task struct {
	gorm.Model
	Target4Chan `json:",inline"`
	IpInfo      []*ScanIpInfo `json:"mass_scan_ips" gorm:"foreignkey:ID;references:ID"`
	Domains     []*Domains    `json:"domains" gorm:"foreignkey:ID;references:ID"`
	ScanStatus  int           `json:"scan_status"` // status; each bit indicates whether the corresponding scan type is done, 0 = not done, 1 = done
}

// Domain info
type Domains struct {
	gorm.Model
	Dns        string        `json:"dns" gorm:"type:varchar(100)"`
	IpInfo     []*ScanIpInfo `json:"mass_scan_ips" gorm:"many2many:Domains_IpInfo"`
	ScanStatus int           `json:"scan_status"` // status; each bit indicates whether the corresponding scan type is done, 0 = not done, 1 = done
}

// IP list of the scan task
type ScanIpInfo struct {
	gorm.Model
	Ip         string      `json:"ip" gorm:"unique_index;type:varchar(60)"`
	ScanStatus int         `json:"scan_status"` // status; each bit indicates whether the corresponding scan type is done, 0 = not done, 1 = done
	PortInfos  []*PortInfo `json:"port_infos" gorm:"foreignkey:ID;references:ID"`
}

// Port info
type PortInfo struct {
	ID         uint   `gorm:"primarykey"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol" gorm:"type:varchar(20)"` // protocol
	ShortName  string `json:"short_name" gorm:"type:varchar(30)"`
	Des        string `json:"des" gorm:"type:varchar(500)"`
	ScanStatus int    `json:"scan_status"` // status; each bit indicates whether the corresponding scan type is done, 0 = not done, 1 = done
}

func init() {
	util.RegInitFunc(func() {
		util.InitModle(&PortInfo{}, &ScanIpInfo{}, &Domains{}, &Task{})
	})
}
