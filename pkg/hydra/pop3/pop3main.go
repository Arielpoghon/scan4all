package pop3

import (
	"github.com/GhostTroops/scan4all/lib/util"
	"log"
	"strings"
)

func getConn(address string) *Conn {
	o := util.GetCache(address, true)
	if nil != o {
		return o.(*Conn)
	}
	x1 := Opt{
		Host:       address,
		Port:       995,
		TLSEnabled: true,
	}
	if strings.HasSuffix(address, ":110") {
		x1.TLSEnabled = false
		x1.Port = 110
	}
	p := New(x1)
	c, err := p.NewConn()
	if err != nil {
		log.Printf("%v", err)
		return nil
	}
	util.RegDelayCbk(address, func() {
		c.Quit()
	}, func() interface{} {
		return c
	}, 0, 20)
	return c
}

// pop3 password cracking
//
//	Optimize pop3, pop3s password cracking algorithm
//	For the same target and same port, multiple password cracks reuse one network connection, improving cracking efficiency
//	After 20 seconds, if there is any password cracking action, automatically close the connection
func DoPop3(address, user, pass string) bool {
	c := getConn(address)
	// Authenticate.
	if err := c.Auth(user, pass); err != nil {
		return false
	}
	//util.DoNow(address)// Do not close, let the system close automatically
	return true
}
