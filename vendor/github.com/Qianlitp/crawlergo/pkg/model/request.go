package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Qianlitp/crawlergo/pkg/config"
	"github.com/Qianlitp/crawlergo/pkg/tools"
)

type Filter struct {
	MarkedQueryMap    map[string]interface{}
	QueryKeysId       string
	QueryMapId        string
	MarkedPostDataMap map[string]interface{}
	PostDataId        string
	MarkedPath        string
	FragmentID        string
	PathId            string
	UniqueId          string
}

type Options struct {
	Headers  map[string]interface{}
	PostData string
}

type Request struct {
	URL             *URL
	Method          string
	Headers         map[string]interface{}
	PostData        string
	Filter          Filter
	Source          string
	RedirectionFlag bool
	Proxy           string
}

var supportContentType = []string{config.JSON, config.URLENCODED}

/*
*
Create a Request object.
Headers and PostData can optionally be set.
*/
func GetRequest(method string, URL *URL, options ...Options) Request {
	var req Request
	req.URL = URL
	req.Method = strings.ToUpper(method)
	if len(options) != 0 {
		option := options[0]
		if option.Headers != nil {
			req.Headers = option.Headers
		}

		if option.PostData != "" {
			req.PostData = option.PostData
		}
	} else {
		req.Headers = map[string]interface{}{}
	}

	return req
}

/*
*
Print the fully formatted request
*/
func (req *Request) FormatPrint() {
	var tempStr = req.Method
	tempStr += " " + req.URL.String() + " HTTP/1.1\r\n"
	for k, v := range req.Headers {
		tempStr += k + ": " + v.(string) + "\r\n"
	}
	tempStr += "\r\n"
	if req.Method == config.POST {
		tempStr += req.PostData
	}
	fmt.Println(tempStr)
}

/*
*
Print a concise representation
*/
func (req *Request) SimplePrint() {
	var tempStr = req.Method
	tempStr += " " + req.URL.String() + " "
	if req.Method == config.POST {
		tempStr += req.PostData
	}
	fmt.Println(tempStr)
}

func (req *Request) SimpleFormat() string {
	var tempStr = req.Method
	tempStr += " " + req.URL.String() + " "
	if req.Method == config.POST {
		tempStr += req.PostData
	}
	return tempStr
}

/*
*
Return a request ID that excludes headers
*/
func (req *Request) NoHeaderId() string {
	return tools.StrMd5(req.Method + req.URL.String() + req.PostData)
}

func (req *Request) UniqueId() string {
	if req.RedirectionFlag {
		return tools.StrMd5(req.NoHeaderId() + "Redirection")
	} else {
		return req.NoHeaderId()
	}
}

/*
*
Return the parsed POST data as a map.

Supports application/x-www-form-urlencoded and application/json.

If parsing fails, returns a map with the key "key" and the raw POST data as its value.
*/
func (req *Request) PostDataMap() map[string]interface{} {
	contentType, err := req.getContentType()
	if err != nil {
		return map[string]interface{}{
			"key": req.PostData,
		}
	}

	if strings.HasPrefix(contentType, config.JSON) {
		var result map[string]interface{}
		err = json.Unmarshal([]byte(req.PostData), &result)
		if err != nil {
			return map[string]interface{}{
				"key": req.PostData,
			}
		} else {
			return result
		}
	} else if strings.HasPrefix(contentType, config.URLENCODED) {
		var result = map[string]interface{}{}
		r, err := url.ParseQuery(req.PostData)
		if err != nil {
			return map[string]interface{}{
				"key": req.PostData,
			}
		} else {
			for key, value := range r {
				if len(value) == 1 {
					result[key] = value[0]
				} else {
					result[key] = value
				}
			}
			return result
		}
	} else {
		return map[string]interface{}{
			"key": req.PostData,
		}
	}
}

/*
*
Return the parsed GET parameters as a map
*/
func (req *Request) QueryMap() map[string][]string {
	return req.URL.Query()
}

/*
*
Get the Content-Type
*/
func (req *Request) getContentType() (string, error) {
	headers := req.Headers
	var contentType string
	if ct, ok := headers["Content-Type"]; ok {
		contentType = ct.(string)
	} else if ct, ok := headers["Content-type"]; ok {
		contentType = ct.(string)
	} else if ct, ok := headers["content-type"]; ok {
		contentType = ct.(string)
	} else {
		return "", errors.New("no content-type")
	}

	for _, ct := range supportContentType {
		if strings.HasPrefix(contentType, ct) {
			return contentType, nil
		}
	}
	return "", errors.New("dont support such content-type:" + contentType)
}
