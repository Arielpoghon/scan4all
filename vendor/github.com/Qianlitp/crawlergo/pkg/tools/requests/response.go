package requests

import (
	"io/ioutil"
	"net/http"

	"github.com/Qianlitp/crawlergo/pkg/logger"
)

// Response extends the standard HTTP response with its raw text.
type Response struct {
	http.Response
	// raw text Response
	Text string
}

func getTextFromResp(r *http.Response) string {
	// TODO: Convert the character encoding.
	if r.ContentLength == 0 {
		return ""
	}
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Logger.Debug("get response body err ", err)
	}
	_ = r.Body.Close()
	return string(b)
}

func NewResponse(r *http.Response) *Response {
	return &Response{
		Response: *r,
		Text:     getTextFromResp(r),
	}
}
