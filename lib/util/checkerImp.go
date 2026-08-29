package util

import (
	"io"
	"log"
	"net/http"
	"strings"
)

const (
	RespHeader string = "RespHeader"
	RespBody   string = "RespBody"
	ReqHeader  string = "ReqHeader"
)

var (
	// ,RespJs,RespCss,RespTitle
	keys []string = strings.Split("RespHeader,RespBody,ReqHeader", ",")
)

// Checker design: decoupled, standardized, unified; each kind focuses on its own implementation
//
//  1. allow building different checkers for header, body, js, css, etc.
//  2. every checker has a cache
//  3. avoid repeated checks
//  4. has an automatic cache-release mechanism, automatically consumed when the program exits (memory cache)
type CheckerTools struct {
	Name      string                                `json:"name"`       // RespHeader,RespBody,RespJs,RespCss,RespTitle,ReqHeader
	checkFunc []func(*CheckerTools, ...interface{}) `json:"check_func"` // registered checker
}

func GetInstance(name string) *CheckerTools {
	return GetObjFromNoRpt[*CheckerTools](name)
}

// register body processing
func RegResponsCheckFunc(cbk ...func(*CheckerTools, ...interface{})) {
	GetInstance(RespBody).RegCheckFunc(cbk...)
}

// register body processing
func RegHeaderCheckFunc(cbk ...func(*CheckerTools, ...interface{})) {
	GetInstance(ReqHeader).RegCheckFunc(cbk...)
}

// build a checker
func New(name string) *CheckerTools {
	ct := GetObjFromNoRpt[*CheckerTools](name)
	if nil == ct {
		ct = &CheckerTools{Name: name}
		SetNoRpt(name, ct)
	}
	return ct
}

// register a handler
func (r *CheckerTools) RegCheckFunc(fnChk ...func(*CheckerTools, ...interface{})) {
	r.checkFunc = append(r.checkFunc, fnChk...)
}

// get the size-limited body data
func (r *CheckerTools) GetBodyStr(a ...interface{}) string {
	if nil == a || 0 == len(a) || nil == a[0] {
		return ""
	}
	if s1, ok := a[0].(string); ok {
		return s1
	} else if s1, ok := a[0].([]byte); ok {
		return string(s1)
	} else if s1, ok := a[0].(io.ReadCloser); ok {
		if data, err := io.ReadAll(s1); err == nil {
			s1.Close()
			return string(data)
		}
	}
	return ""
}

// check
func (r *CheckerTools) Check(parm ...interface{}) {
	for _, f := range r.checkFunc {
		if nil != f {
			log.Printf("Check %+v\n", parm)
			f(r, parm...)
		}
	}
}

// get a header value
func (r *CheckerTools) GetHead(p interface{}, key string) []string {
	if nil == p {
		return []string{}
	}
	if x1, ok := p.(map[string]string); ok {
		if x, ok := x1[key]; ok {
			return []string{x}
		}
	} else if x1, ok := p.(map[string][]string); ok {
		if x, ok := x1[key]; ok {
			return x
		}
	} else if x1, ok := p.(*http.Header); ok {
		if x := x1.Get(key); "" != x {
			return []string{x}
		}
	}
	return []string{}
}

// header check; pass in headers of different forms, the function processes as needed
func CheckRespHeader(parm ...interface{}) {
	if x1 := GetInstance(RespHeader); nil != x1 {
		x1.Check(parm...)
	}
}

// check the response object
//
//  1. includes header checks
//  2. includes body checks
func CheckResp(szU string, resp ...*http.Response) {
	if nil != resp && 0 < len(resp) {
		for _, r := range resp {
			CheckRespHeader(&r.Header, szU)
			GetInstance(RespBody).Check(&r, szU)
		}
	}
}

func init() {
	RegInitFunc(func() {
		for _, k := range keys {
			New(k)
		}
	})
}
