package lib

import (
	"encoding/json"
	util "github.com/hktalent/go-utils"
	"log"
)

// Server configuration
type ConfigServer struct {
	UseMysql      bool   `json:"usemysql"`
	DbUrl         string `json:"dburl"`
	DebugDbUrl    string `json:"debugdburl"`
	Debug         bool   `json:"debug"`
	MaxOpenConns  int    `json:"maxopenconns"`
	AutoRmOldData bool   `json:"autormolddata"` // Automatically delete data older than 10 hours
	OnClient      bool   `json:"onclient"`      // api server runtime control flag
}

// global configuration on the server side
var GConfigServer = ConfigServer{MaxOpenConns: 200, UseMysql: true}

// Initialize the config file info; this must run first
func init() {
	util.RegInitFunc(func() {
		x := util.GetAllConfigData()
		if data, err := json.Marshal(x); nil == err {
			if err = json.Unmarshal(data, &GConfigServer); nil != err {
				log.Println(err)
			}
		} else {
			log.Println(err)
		}
	})
	//pwd, _ := os.Getwd()
	//var ConfigName = pwd + "/config/config.json"
	//config := viper.New()
	////config.AddConfigPath("./")
	////config.AddConfigPath("./config/")
	////config.AddConfigPath("$HOME")
	////config.AddConfigPath("/etc/")
	//config.SetConfigType("json")
	//config.SetConfigFile(ConfigName)
	//err := config.ReadInConfig() // find and read the config file
	//if err != nil {              // handle errors while reading the config file
	//	log.Println("config.ReadInConfig ", err)
	//	return
	//}
	//// Save the read configuration info to the global variable Conf
	//if err := config.Unmarshal(&GConfigServer); err != nil {
	//	log.Println("config.Unmarshal ", err)
	//	return
	//}
	//var mData = map[string]interface{}{}
	//config.Unmarshal(&mData)
	//viper.Set("Verbose", false)

}
