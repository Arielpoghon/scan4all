package portScan

import (
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/lib/scan/Const"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/pkg/models"
	"github.com/GhostTroops/scan4all/lib/util"
	"log"
	"strings"
)

/*
On Windows or from a virtual machine, it can execute 300,000 packets per second.
On Linux (without virtualization), it will execute 1.6 million packets per second. This is enough to melt most networks.

By default, masscan first loads the configuration file /etc/masscan/masscan.conf
Any subsequent configuration parameters will override the content of this default configuration file

Binary: this is the format built into masscan. It produces much smaller files, so when I scan the internet, my disk won't fill up.
However, they need to be parsed. The command line option --readscan will read the binary scan file. Using --readscan together with the -oX option will generate an XML version of the result file.
masscan -c myscan.conf

# My Scan
rate =  100000.00
output-format = xml
output-status = all
output-filename = scan.xml
Ports = 0-65535
range = 0.0.0.0-255.255.255.255
excludefile = exclude.txt
*/
func init() {
	util.RegInitFunc(func() {
		// Scans the entire internet in about 10 hours per port (minus exclusion values) (655,360 hours if all ports are scanned)
		// nmap compatible "stealth" options: -sS -Pn -n --randomize-hosts --send-eth
		util.EngineFuncFactory(Const.ScanType_Masscan, func(evt *models.EventData, args ...interface{}) {
			ip := strings.Join(evt.Target2Ip(), ",")
			if "" == ip {
				return
			}
			//s1 := fmt.Sprintf("%x", ip)
			ms := New()
			ms.Evt = evt
			ms.Target = TargetStr(ip)
			ms.Rate = "5000"
			ms.Ports = "0-65535" // -p-  , "-p-"
			ms.Args = []string{
				//"--banners",
				//"-oX", s1 + ".xml",
				"--max-rate", string(ms.Rate),
			}
			util.MergeParms2Obj(&ms, args...)
			var hosts []models.Host
			err := ms.Run(func(host *models.Host) {
				hosts = append(hosts, *host)
			})
			if nil != err {
				log.Println("ms.Run is error ", err)
			}
			util.SendEngineLog(evt, Const.ScanType_Masscan, hosts)
		})

	})
}
