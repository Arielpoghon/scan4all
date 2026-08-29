package util

import "net/http"

// Encapsulation of the fuzz response object
type Response struct {
	Status        string
	StatusCode    int
	Body          string
	Header        *http.Header // no need to own the object; use a reference to save memory
	ContentLength int          `json:"content_length"`
	RequestUrl    string       `json:"request_url"`
	Location      string       `json:"location"`
	Protocol      string       `json:"protocol"`
}

// The result returned by a fuzz request
// Use pointers where possible to save memory
type Page struct {
	IsBackUpPath bool         // the request url for backup/sensitive file leakage detection
	IsBackUpPage bool         // found backup/sensitive leaked files
	Title        *string      // title
	LocationUrl  *string      // redirect page
	Is302        bool         // is a 302 page
	Is403        bool         // 403 page
	Url          *string      // used as a local persistent cache key to improve efficiency
	BodyStr      *string      // body = trim() + ToLower
	BodyLen      int          // body length
	Header       *http.Header // pointer-based to save memory
	StatusCode   int          // status code
	Resqonse     *Response    // pointer-based to save memory
}
