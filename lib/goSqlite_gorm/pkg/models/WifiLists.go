package models

import (
	"gorm.io/gorm"
	"time"
)

// Current location Wi-fi list
//  SSID BSSID             RSSI CHANNEL HT CC SECURITY (auth/unicast/group)
type WifiInfo struct {
	gorm.Model
	SSID     string `json:"ssid" jsonschema:"title=The unique ID of the AP,description=The name you gave to your wireless network"`
	BSSID    string `json:"bssid" gorm:"column:bssid;unique_index:bssid" jsonschema:"Basic Service Set,description=A binary identifier with a length of 6 bytes (48 bits)"`
	RSSI     string `json:"rssi" jsonschema:"Received Signal Strength Indicator, indicates the received signal strength"`
	CHANNEL  string `json:"channel"`
	HT       string `json:"ht"`
	CC       string `json:"cc"`
	SECURITY string `json:"security"` //  (auth/unicast/group)
}

type WifiLists struct {
	gorm.Model
	Latitude  string     `json:"latitude" gorm:"column:latitude;unique_index:lat_alo"`
	Longitude string     `json:"longitude" gorm:"column:longitude;unique_index:lat_alo"`
	Accuracy  string     `json:"accuracy"`
	Date      time.Time  `json:"date"`
	WifiInfos []WifiInfo `json:"wifiInfos" gorm:"many2many:WifiLists_WifiInfo;"`
}
