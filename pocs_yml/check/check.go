package check

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GhostTroops/scan4all/pocs_yml/pkg/xray/cel"
	"github.com/GhostTroops/scan4all/pocs_yml/pkg/xray/requests"
	xray_structs "github.com/GhostTroops/scan4all/pocs_yml/pkg/xray/structs"
	"github.com/google/cel-go/checker/decls"
	"gopkg.in/yaml.v2"
)

var (
	BodyBufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 1024)
		},
	}
	BodyPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 4096)
		},
	}
	VariableMapPool = sync.Pool{
		New: func() interface{} {
			return make(map[string]interface{})
		},
	}
)

type RequestFuncType func(ruleName string, rule xray_structs.Rule) error

func Start(target string, pocs []*xray_structs.Poc) []string {
	var Vullist []string
	for _, poc := range pocs {
		// Optimization needed: for performance, share the state and results of requests already sent by other POCs
		if req, err := http.NewRequest("GET", target, nil); err == nil {
			isVul, err := executeXrayPoc(req, target, poc)
			if err != nil {
				gologger.Error().Msgf("Execute Poc (%v) error: %v", poc.Name, err.Error())
			}
			if isVul {
				util.SendLog(target, poc.Name, "", poc.Name)
				Vullist = append(Vullist, poc.Name)
			}
		}
	}
	return Vullist
}

func executeXrayPoc(oReq *http.Request, target string, poc *xray_structs.Poc) (isVul bool, err error) {
	isVul = false

	var (
		milliseconds int64
		tcpudpType   = ""

		request       *http.Request
		response      *http.Response
		oProtoRequest *xray_structs.Request
		protoRequest  *xray_structs.Request
		protoResponse *xray_structs.Response
		variableMap   = VariableMapPool.Get().(map[string]interface{})
		requestFunc   cel.RequestFuncType
	)

	// Exception handling
	defer func() {
		if r := recover(); r != nil {
			err = errors.Wrapf(r.(error), "Run Xray Poc[%s] error", poc.Name)
			isVul = false
		}
	}()
	// Recycle resources
	defer func() {
		if protoRequest != nil {
			requests.PutUrlType(protoRequest.Url)
			requests.PutRequest(protoRequest)

		}
		if oProtoRequest != nil {
			requests.PutUrlType(oProtoRequest.Url)
			requests.PutRequest(oProtoRequest)

		}
		if protoResponse != nil {
			requests.PutUrlType(protoResponse.Url)
			if protoResponse.Conn != nil {
				requests.PutAddrType(protoResponse.Conn.Source)
				requests.PutAddrType(protoResponse.Conn.Destination)
				requests.PutConnectInfo(protoResponse.Conn)
			}
			requests.PutResponse(protoResponse)
		}

		for _, v := range variableMap {
			switch v.(type) {
			case *xray_structs.Reverse:
				cel.PutReverse(v)
			}
		}
		VariableMapPool.Put(variableMap)
	}()

	// Initial assignment
	// Set the original request variable
	oProtoRequest, _ = requests.ParseHttpRequest(oReq)
	variableMap["request"] = oProtoRequest

	// Determine the transport; skip if it is not valid
	transport := poc.Transport
	if transport == "tcp" || transport == "udp" {
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			return
		}
	} else {
		_, err = url.ParseRequestURI(strings.TrimSpace(target))
		if err != nil {
			return
		}
	}

	// Initialize the cel-go environment and recycle it when the function returns
	c := cel.NewEnvOption()
	defer cel.PutCustomLib(c)

	env, err := cel.NewEnv(&c)
	if err != nil {
		return false, err
	}

	// Global variables in the request

	// Define the render function
	render := func(v string) string {
		for k1, v1 := range variableMap {
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			v1Value := fmt.Sprintf("%v", v1)
			t := "{{" + k1 + "}}"
			if !strings.Contains(v, t) {
				continue
			}
			v = strings.ReplaceAll(v, t, v1Value)
		}
		return v
	}
	ReCreateEnv := func() error {
		env, err = cel.NewEnv(&c)
		if err != nil {
			return err
		}
		return nil
	}

	// Define evaluateUpdateVariableMap
	evaluateUpdateVariableMap := func(set yaml.MapSlice) {
		for _, item := range set {
			k, expression := item.Key.(string), item.Value.(string)
			// ? The environment needs to be regenerated; otherwise previously added variable definitions won't take effect
			if err := ReCreateEnv(); err != nil {

			}

			out, err := cel.Evaluate(env, expression, variableMap)
			if err != nil {
				continue
			}

			// Set the variableMap and update CompileOption
			switch value := out.Value().(type) {
			case *xray_structs.UrlType:
				variableMap[k] = cel.UrlTypeToString(value)
				c.UpdateCompileOption(k, cel.UrlTypeType)
			case *xray_structs.Reverse:
				variableMap[k] = value
				c.UpdateCompileOption(k, cel.ReverseType)
			case int64:
				variableMap[k] = int(value)
				c.UpdateCompileOption(k, decls.Int)
			case map[string]string:
				variableMap[k] = value
				c.UpdateCompileOption(k, cel.StrStrMapType)
			default:
				variableMap[k] = value
				c.UpdateCompileOption(k, decls.String)
			}
		}
		// ? Regenerate the environment once more; otherwise previously added variable definitions won't take effect
		if err := ReCreateEnv(); err != nil {

		}
	}

	// Handle set
	evaluateUpdateVariableMap(poc.Set)

	// Handle payload
	for _, setMapVal := range poc.Payloads.Payloads {
		setMap := setMapVal.Value.(yaml.MapSlice)
		evaluateUpdateVariableMap(setMap)
	}
	// Render detail
	detail := &poc.Detail
	detail.Author = render(detail.Author)
	for k, v := range poc.Detail.Links {
		detail.Links[k] = render(v)
	}
	fingerPrint := &detail.FingerPrint
	for _, info := range fingerPrint.Infos {
		info.ID = render(info.ID)
		info.Name = render(info.Name)
		info.Version = render(info.Version)
		info.Type = render(info.Type)
	}
	fingerPrint.HostInfo.Hostname = render(fingerPrint.HostInfo.Hostname)
	vulnerability := &detail.Vulnerability
	vulnerability.ID = render(vulnerability.ID)
	vulnerability.Match = render(vulnerability.Match)

	// transport=http: request handling
	HttpRequestInvoke := func(rule xray_structs.Rule) error {
		var (
			ok               bool
			err              error
			ruleReq          = rule.Request
			rawHeaderBuilder strings.Builder
		)

		// Render the request headers, request path, and request body
		for k, v := range ruleReq.Headers {
			ruleReq.Headers[k] = render(v)
		}
		ruleReq.Path = render(strings.TrimSpace(ruleReq.Path))
		ruleReq.Body = render(strings.TrimSpace(ruleReq.Body))

		// Try to get the cache
		if request, protoRequest, protoResponse, ok = requests.XrayGetHttpRequestCache(&ruleReq); !ok || !rule.Request.Cache {
			// Get protoRequest
			protoRequest, err = requests.ParseHttpRequest(oReq)
			if err != nil {
				return err
			}

			// Handle the path
			if strings.HasPrefix(ruleReq.Path, "/") {
				protoRequest.Url.Path = strings.Trim(oReq.URL.Path, "/") + "/" + ruleReq.Path[1:]
			} else if strings.HasPrefix(ruleReq.Path, "^") {
				protoRequest.Url.Path = "/" + ruleReq.Path[1:]
			}

			if !strings.HasPrefix(protoRequest.Url.Path, "/") {
				protoRequest.Url.Path = "/" + protoRequest.Url.Path
			}

			// Some POCs don't distinguish between path and query; handle it accordingly
			protoRequest.Url.Path = strings.ReplaceAll(protoRequest.Url.Path, " ", "%20")
			protoRequest.Url.Path = strings.ReplaceAll(protoRequest.Url.Path, "+", "%20")

			// Clone the request object
			request, err = http.NewRequest(ruleReq.Method, fmt.Sprintf("%s://%s%s", protoRequest.Url.Scheme, protoRequest.Url.Host, protoRequest.Url.Path), strings.NewReader(ruleReq.Body))
			if err != nil {
				return err
			}

			// Handle the request headers
			request.Header = oReq.Header.Clone()
			for k, v := range ruleReq.Headers {
				request.Header.Set(k, v)
				rawHeaderBuilder.WriteString(k)
				rawHeaderBuilder.WriteString(": ")
				rawHeaderBuilder.WriteString(v)
				rawHeaderBuilder.WriteString("\n")
			}

			protoRequest.RawHeader = []byte(strings.Trim(rawHeaderBuilder.String(), "\n"))

			// Additional handling of protoRequest.Raw
			protoRequest.Raw, _ = httputil.DumpRequestOut(request, true)

			// Send the request
			response, milliseconds, err = requests.DoRequest(request, ruleReq.FollowRedirects)
			if err != nil {
				return err
			}

			// Get protoResponse
			protoResponse, err = requests.ParseHttpResponse(response, milliseconds)
			if err != nil {
				return err
			}

			// Set the cache
			requests.XraySetHttpRequestCache(&ruleReq, request, protoRequest, protoResponse)

		} else {
		}

		return nil
	}

	// transport=tcp/udp: request handling
	TCPUDPRequestInvoke := func(rule xray_structs.Rule) error {
		var (
			buffer = BodyBufPool.Get().([]byte)

			content      = rule.Request.Content
			connectionID = rule.Request.ConnectionID
			conn         net.Conn
			connCache    *net.Conn
			responseRaw  []byte
			readTimeout  int

			ok  bool
			err error
		)
		defer BodyBufPool.Put(buffer)

		// Get the response cache
		if responseRaw, protoResponse, ok = requests.XrayGetTcpUdpResponseCache(rule.Request.Content); !ok || !rule.Request.Cache {
			responseRaw = BodyPool.Get().([]byte)
			defer BodyPool.Put(responseRaw)

			// Get the connectionID cache
			if connCache, ok = requests.XrayGetTcpUdpConnectionCache(connectionID); !ok {
				// Handle the timeout
				readTimeout, err = strconv.Atoi(rule.Request.ReadTimeout)
				if err != nil {
					return err
				}

				// Establish the connection
				conn, err = net.Dial(tcpudpType, target)
				if err != nil {
					return err
				}

				// Set the read timeout
				err := conn.SetReadDeadline(time.Now().Add(time.Duration(readTimeout) * time.Second))
				if err != nil {
					return err
				}

				// Set the connection cache
				requests.XraySetTcpUdpConnectionCache(connectionID, &conn)
			} else {
				conn = *connCache
			}

			// Get protoRequest
			protoRequest, _ = requests.ParseTCPUDPRequest([]byte(content))

			// Send data
			_, err = conn.Write([]byte(content))
			if err != nil {
				return err
			}

			// Receive data
			for {
				n, err := conn.Read(buffer)
				if err != nil {
					if err == io.EOF {
					} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					} else {
						return err
					}
					break
				}
				responseRaw = append(responseRaw, buffer[:n]...)
			}

			// Get protoResponse
			protoResponse, _ = requests.ParseTCPUDPResponse(responseRaw, &conn, tcpudpType)

			// Set the response cache
			requests.XraySetTcpUdpResponseCache(content, responseRaw, protoResponse)

		}
		return nil
	}

	// Overall request handling
	RequestInvoke := func(requestFunc cel.RequestFuncType, ruleName string, rule xray_structs.Rule) (bool, error) {
		var (
			flag bool
			ok   bool
			err  error
		)
		err = requestFunc(rule)
		if err != nil {
			return false, err
		}

		variableMap["request"] = protoRequest
		variableMap["response"] = protoResponse

		// Execute the expression
		out, err := cel.Evaluate(env, rule.Expression, variableMap)

		if err != nil {
			return false, err
		}

		// Determine the expression result
		flag, ok = out.Value().(bool)
		if !ok {
			flag = false
		}

		// Handle output
		evaluateUpdateVariableMap(rule.Output)

		return flag, nil
	}

	// Determine the transport type and set requestInvoke
	if poc.Transport == "tcp" {
		tcpudpType = "tcp"
		requestFunc = TCPUDPRequestInvoke
	} else if poc.Transport == "udp" {
		tcpudpType = "udp"
		requestFunc = TCPUDPRequestInvoke
	} else {
		requestFunc = HttpRequestInvoke
	}

	ruleSlice := poc.Rules
	// Define the function named ruleName in advance
	for _, ruleItem := range ruleSlice {
		c.DefineRuleFunction(requestFunc, ruleItem.Key, ruleItem.Value, RequestInvoke)
	}

	// ? Regenerate the environment once more; otherwise previously added variable definitions won't take effect
	if err := ReCreateEnv(); err != nil {

	}

	// Execute the rule and determine the overall POC expression result
	successVal, err := cel.Evaluate(env, poc.Expression, variableMap)
	if err != nil {
		return false, err
	}

	isVul, ok := successVal.Value().(bool)
	if !ok {
		isVul = false
	}

	return isVul, nil
}
