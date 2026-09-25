package go_utils

import (
	"log"
	"net"
)

// 127.0.0.1:0 selects a dynamic port to avoid conflicts with ports in use.
// :0 also works.
func GetAddr(s, szType string) string {
	if "udp" == szType {
		udpAddr, err := net.ResolveUDPAddr("udp4", s)
		if err != nil {
			log.Fatal(err)
		}
		if l, err := net.ListenUDP("udp", udpAddr); nil == err {
			l.Close()
			return l.LocalAddr().String()
		}
		return ""
	}
	l, err := net.Listen(szType, s)
	if err != nil {
		log.Printf("err: %v\n", err)
		return ""
	}
	defer l.Close()
	x1 := l.Addr().(*net.TCPAddr)
	return x1.String()
}
