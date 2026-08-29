package socket

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type CheckCbkFuc func(data byte) bool

type CheckTarget struct {
	Target        string         `json:"target"`        // target
	Port          int            `json:"port"`          // port
	ConnState     bool           `json:"connState"`     // connection state
	ConnType      string         `json:"connType"`      // connection type: tcp
	ReadTimeout   int            `json:"readTimeout"`   // read data timeout
	CheckCbkLists []*CheckCbkFuc `json:"checkCbkLists"` // callback interface
	Conn          net.Conn       `json:"conn"`          // connection object
	//ConnTLS       *tls.Conn      `json:"conn"`          // ssl connection object
	MacReadSize      uint32 `json:"macReadSize"` // max allowed read data size to avoid memory attacks, default: 200k
	HostName         string `json:"hostName"`    // http header host
	UrlPath          string `json:"urlPath"`     // url path in http
	UrlRaw           string `json:"urlRaw"`      // full url
	IsTLS            bool   `json:"isTLS"`       // https
	CustomHeadersRaw string `json:"customHeadersRaw"`
}

// Prepare the target to be detected/connected
// the ssl case needs to be considered
func NewCheckTarget(szUrl, SzType string, readWriteTimeout int) *CheckTarget {
	u, err := url.Parse(strings.TrimSpace(szUrl))

	if "" == SzType {
		SzType = "tcp"
	}
	if 0 >= readWriteTimeout {
		readWriteTimeout = 20
	}
	r11 := &CheckTarget{UrlRaw: szUrl, UrlPath: "/", MacReadSize: 200 * 1024 * 1024, ConnType: SzType, ReadTimeout: readWriteTimeout, CheckCbkLists: []*CheckCbkFuc{}}
	if err == nil {
		r11.Target = u.Hostname()
		r11.Port = 80
		// https://eli.thegreenplace.net/2021/go-socket-servers-with-tls/
		r11.IsTLS = strings.HasPrefix(strings.ToLower(u.Scheme), "https")
		if "" == u.Port() && r11.IsTLS {
			r11.Port = 443
		} else if n, err := strconv.Atoi(u.Port()); nil == err {
			r11.Port = n
		}
		if "" != u.Path {
			r11.UrlPath = u.Path
		}

	}
	r11.CustomHeadersRaw = util.GetCustomHeadersRaw()
	return r11
}

// add a check function
// if the check function returns true, don't close the connection and keep sending follow-up data packets
func (r *CheckTarget) AddCheck(fnCbk CheckCbkFuc, aN ...int) *CheckTarget {
	r.CheckCbkLists = append(r.CheckCbkLists, &fnCbk)
	return r
}

// send one payload and close
func (r *CheckTarget) SendOnePayload(str, szPath, szHost string, nTimes int) string {
	_, err := r.ConnTarget()
	defer r.Close()
	if nil == err && r.ConnState {
		for i := 0; i < nTimes; i++ {
			r.WriteWithFlush(fmt.Sprintf(str, szPath, szHost, r.CustomHeadersRaw))
		}
		s1 := *r.ReadAll2Str()
		if "" != s1 {
			return s1
		}
	}
	return ""
}

func (r *CheckTarget) SendPayload(data []byte, nTimes int) string {
	_, err := r.ConnTarget()
	defer r.Close()
	if nil == err && r.ConnState {
		for i := 0; i < nTimes; i++ {
			r.WriteWithFlushByte(data)
		}
		s1 := *r.ReadAll2Str()
		if "" != s1 {
			return s1
		}
	}
	return ""
}

func (r *CheckTarget) WriteWithFlushByte(s []byte) (nn int, err error) {
	bw := r.GetBufWriter()
	if nil == bw {
		return -1, errors.New("WriteWithFlush can not get GetBufWriter")
	}
	//log.Printf("Payload: %s\n%s", r.UrlRaw, s)
	nn, err = bw.Write(s)
	bw.Flush()
	return
}

// get the operation io
func (r *CheckTarget) WriteWithFlush(s string) (nn int, err error) {
	bw := r.GetBufWriter()
	if nil == bw {
		return -1, errors.New("WriteWithFlush can not get GetBufWriter")
	}
	//log.Printf("Payload: %s\n%s", r.UrlRaw, s)
	nn, err = bw.Write([]byte(s))
	bw.Flush()
	return
}

// get the operation io
func (r *CheckTarget) GetBufReader() *bufio.Reader {
	return bufio.NewReader(r.Conn)
}

func (r *CheckTarget) ReadAll2Bytes() *[]byte {
	buf := r.GetBufReader()
	var a []byte
	data := make([]byte, 1024)
	var nCnt uint32 = 0
	n, err := buf.Read(data)
	for nil == err {
		if 0 < n {
			nCnt += uint32(n)
			a = append(a, data[0:n]...)
			// limit
			if nCnt >= r.MacReadSize {
				break
			}
		}
		n, err = buf.Read(data)
	}
	return &a
}

// read all text
func (r *CheckTarget) ReadAll2Str() *string {
	a := r.ReadAll2Bytes()
	s1 := string(*a)
	return &s1
}

func (r *CheckTarget) GetBufWriter() *bufio.Writer {
	return bufio.NewWriter(r.Conn)
}

// close the connection
func (r *CheckTarget) Close() {
	if r.ConnState {
		r.ConnState = false
		if nil != r.Conn {
			r.Conn.Close()
			r.Conn = nil
		}
	}
}

func (r *CheckTarget) Log(s string) {
	//log.Println(s)
}

var ipReg = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)

// connect to the target
// sysctl -w net.ipv4.tcp_keepalive_time=300
// sysctl -w net.ipv4.tcp_keepalive_intvl=30
// sysctl -w net.ipv4.tcp_keepalive_probes=5
func (r *CheckTarget) ConnTarget() (*CheckTarget, error) {
	var err error
	szErr := fmt.Sprintf("can not connect to: %s", r.UrlRaw)
	if r.IsTLS {
		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		ServerName := strings.Split(r.Target, ":")[0]
		if !ipReg.Match([]byte(ServerName)) {
			conf.ServerName = ServerName
		}
		r.Conn, err = tls.Dial(r.ConnType, fmt.Sprintf("%s:%d", r.Target, r.Port), conf)
	} else {
		r.Conn, err = net.DialTimeout(r.ConnType, fmt.Sprintf("%s:%d", r.Target, r.Port), time.Duration(r.ReadTimeout)*time.Second)
	}
	if err == nil {
		//defer r.Close()
		//r.Conn.SetKeepAlive(true)
		// set the read timeout
		err = r.Conn.SetReadDeadline(time.Now().Add(time.Duration(r.ReadTimeout) * time.Second))
		if err != nil {
			r.Log(szErr)
			return r, err
		}
		r.ConnState = true
	}
	return r, nil
}
