package hydra

import (
	"encoding/json"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/logrusorgru/aurora"
	"log"
	"strconv"
	"strings"
)

func init() {
	util.RegInitFunc(func() {
		InitDefaultAuthMap()
		var a1, a2 []string
		HydraUser := util.GetVal4File("HydraUser", "")
		if "" != HydraUser {
			a1 = strings.Split(HydraUser, "\n")
		}

		HydraPass := util.GetVal4File("HydraPass", "")
		if "" != HydraPass {
			a2 = strings.Split(HydraPass, "\n")
		}
		//Load custom dictionary
		InitCustomAuthMap(a1, a2)
	})
}

// Password cracking
func Start(IPAddr string, Port int, Protocol string) {
	authInfo := NewAuthInfo(IPAddr, Port, Protocol)
	nT, err := strconv.Atoi(util.GetVal4File("hydrathread", "64"))
	if nil != err {
		nT = 64
	}
	crack := NewCracker(authInfo, true, nT)
	fmt.Printf("\n[hydra]->Start brute force on %v:%v [ %v ], dictionary length: %d\n", IPAddr, Port, Protocol, crack.Length())
	go crack.Run()
	//Crack result acquisition
	var out AuthInfo
	for info := range crack.Out {
		out = info
		if nil != &out && "" != out.Protocol && out.IPAddr != "" && "" != out.Auth.Username {
			util.SendAData[AuthInfo](fmt.Sprintf("%s:%d", out.IPAddr, out.Port), []AuthInfo{out}, util.Hydra)
			data, _ := json.Marshal(out)
			fmt.Println("Successful password cracking:", aurora.BrightRed(string(data)))
		}
	}
	log.Printf("\n[hydra]-> %v:%v [ %v ] Brute force Finish\n", IPAddr, Port, Protocol)
	//crack.Pool.Wait()
}
