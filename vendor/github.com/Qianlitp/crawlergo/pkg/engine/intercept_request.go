package engine

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Qianlitp/crawlergo/pkg/config"
	"github.com/Qianlitp/crawlergo/pkg/logger"
	model2 "github.com/Qianlitp/crawlergo/pkg/model"
	"github.com/Qianlitp/crawlergo/pkg/tools"
	"github.com/Qianlitp/crawlergo/pkg/tools/requests"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
)

/*
*
Handle each HTTP request
*/
func (tab *Tab) InterceptRequest(v *fetch.EventRequestPaused) {
	defer tab.WG.Done()
	ctx := tab.GetExecutor()
	_req := v.Request
	// The intercepted URL is always well formed, so do not handle parse errors
	url, err := model2.GetUrl(_req.URL, *tab.NavigateReq.URL)
	if err != nil {
		logger.Logger.Debug("InterceptRequest parse url failed: ", err)
		_ = fetch.ContinueRequest(v.RequestID).Do(ctx)
		return
	}
	_option := model2.Options{
		Headers:  _req.Headers,
		PostData: _req.PostData,
	}
	req := model2.GetRequest(_req.Method, url, _option)

	if IsIgnoredByKeywordMatch(req, tab.config.IgnoreKeywords) {
		_ = fetch.FailRequest(v.RequestID, network.ErrorReasonBlockedByClient).Do(ctx)
		req.Source = config.FromXHR
		tab.AddResultRequest(req)
		return
	}

	tab.HandleHostBinding(&req)

	// Block all static resources
	// https://github.com/Qianlitp/crawlergo/issues/106
	if config.StaticSuffixSet.Contains(url.FileExt()) {
		_ = fetch.FailRequest(v.RequestID, network.ErrorReasonBlockedByClient).Do(ctx)
		req.Source = config.FromStaticRes
		tab.AddResultRequest(req)
		return
	}

	// Handle navigation requests
	if tab.IsNavigatorRequest(v.NetworkID.String()) {
		tab.NavNetworkID = v.NetworkID.String()
		tab.HandleNavigationReq(&req, v)
		req.Source = config.FromNavigation
		tab.AddResultRequest(req)
		return
	}

	req.Source = config.FromXHR
	tab.AddResultRequest(req)
	_ = fetch.ContinueRequest(v.RequestID).Do(ctx)
}

/*
*
// Report whether this is a navigation request
*/
func (tab *Tab) IsNavigatorRequest(networkID string) bool {
	return networkID == tab.LoaderID
}

/*
*
// Handle 401 and 407 authentication prompts
*/
func (tab *Tab) HandleAuthRequired(req *fetch.EventAuthRequired) {
	defer tab.WG.Done()
	logger.Logger.Debug("auth required found, auto auth.")
	ctx := tab.GetExecutor()
	authRes := fetch.AuthChallengeResponse{
		Response: fetch.AuthChallengeResponseResponseProvideCredentials,
		Username: "Crawlergo",
		Password: "Crawlergo",
	}
	// Cancel authentication
	_ = fetch.ContinueWithAuth(req.RequestID, &authRes).Do(ctx)
}

/*
*
Handle navigation requests
*/
func (tab *Tab) HandleNavigationReq(req *model2.Request, v *fetch.EventRequestPaused) {
	navReq := tab.NavigateReq
	ctx := tab.GetExecutor()
	tCtx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	overrideReq := fetch.ContinueRequest(v.RequestID).WithURL(req.URL.String())

	// Handle a backend redirection request
	if tab.FoundRedirection && tab.IsTopFrame(v.FrameID.String()) {
		logger.Logger.Debug("redirect navigation req: " + req.URL.String())
		//_ = fetch.FailRequest(v.RequestID, network.ErrorReasonConnectionAborted).Do(ctx)
		body := base64.StdEncoding.EncodeToString([]byte(`<html><body>Crawlergo</body></html>`))
		param := fetch.FulfillRequest(v.RequestID, 200).WithBody(body)
		err := param.Do(ctx)
		if err != nil {
			logger.Logger.Debug(err)
		}
		navReq.RedirectionFlag = true
		navReq.Source = config.FromNavigation
		tab.AddResultRequest(navReq)
		// Handle the redirection flag
	} else if navReq.RedirectionFlag && tab.IsTopFrame(v.FrameID.String()) {
		navReq.RedirectionFlag = false
		logger.Logger.Debug("has redirection_flag: " + req.URL.String())
		headers := tools.ConvertHeaders(req.Headers)
		headers["Range"] = "bytes=0-1048576"
		res, err := requests.Request(req.Method, req.URL.String(), headers, []byte(req.PostData), &requests.ReqOptions{
			AllowRedirect: false, Proxy: tab.config.Proxy})
		if err != nil {
			logger.Logger.Debug(err)
			_ = fetch.FailRequest(v.RequestID, network.ErrorReasonConnectionAborted).Do(ctx)
			return
		}
		body := base64.StdEncoding.EncodeToString([]byte(res.Text))
		param := fetch.FulfillRequest(v.RequestID, 200).WithResponseHeaders(ConvertHeadersNoLocation(res.Header)).WithBody(body)
		errR := param.Do(ctx)
		if errR != nil {
			logger.Logger.Debug(errR)
		}
		// Main navigation request
	} else if tab.IsTopFrame(v.FrameID.String()) && req.URL.NavigationUrl() == navReq.URL.NavigationUrl() {
		logger.Logger.Debug("main navigation req: " + navReq.URL.String())
		// Set the POST data manually
		if navReq.Method == config.POST || navReq.Method == config.PUT {
			overrideReq = overrideReq.WithPostData(navReq.PostData)
		}
		overrideReq = overrideReq.WithMethod(navReq.Method)
		overrideReq = overrideReq.WithHeaders(MergeHeaders(navReq.Headers, req.Headers))
		_ = overrideReq.Do(tCtx)
		// Child-frame navigation
	} else if !tab.IsTopFrame(v.FrameID.String()) {
		_ = overrideReq.Do(tCtx)
		// Frontend navigation; return 204
	} else {
		_ = fetch.FulfillRequest(v.RequestID, 204).Do(ctx)
	}
}

/*
*
// Handle Host header rebinding
*/
func (tab *Tab) HandleHostBinding(req *model2.Request) {
	url := req.URL
	navUrl := tab.NavigateReq.URL
	// If the navigation and bound host domains differ, and the current request domain matches the navigation Host header, replace the current domain and bind the Host header
	if host, ok := tab.NavigateReq.Headers["Host"]; ok {
		if navUrl.Hostname() != host && url.Host == host {
			urlObj, _ := model2.GetUrl(strings.Replace(req.URL.String(), "://"+url.Hostname(), "://"+navUrl.Hostname(), -1), *navUrl)
			req.URL = urlObj
			req.Headers["Host"] = host

		} else if navUrl.Hostname() != host && url.Host == navUrl.Host {
			req.Headers["Host"] = host
		}
		// Correct Origin
		if _, ok := req.Headers["Origin"]; ok {
			req.Headers["Origin"] = strings.Replace(req.Headers["Origin"].(string), navUrl.Host, host.(string), 1)
		}
		// Correct Referer
		if _, ok := req.Headers["Referer"]; ok {
			req.Headers["Referer"] = strings.Replace(req.Headers["Referer"].(string), navUrl.Host, host.(string), 1)
		} else {
			req.Headers["Referer"] = strings.Replace(navUrl.String(), navUrl.Host, host.(string), 1)
		}
	}
}

func (tab *Tab) IsTopFrame(FrameID string) bool {
	return FrameID == tab.TopFrameId
}

/*
*
// Extract URLs from response content using regular expressions
*/
func (tab *Tab) ParseResponseURL(v *network.EventResponseReceived) {
	defer tab.WG.Done()
	ctx := tab.GetExecutor()
	res, err := network.GetResponseBody(v.RequestID).Do(ctx)
	if err != nil {
		logger.Logger.Debug("ParseResponseURL ", err)
		return
	}
	resStr := string(res)

	urlRegex := regexp.MustCompile(config.SuspectURLRegex)
	urlList := urlRegex.FindAllString(resStr, -1)
	for _, url := range urlList {

		url = url[1 : len(url)-1]
		url_lower := strings.ToLower(url)
		if strings.HasPrefix(url_lower, "image/x-icon") || strings.HasPrefix(url_lower, "text/css") || strings.HasPrefix(url_lower, "text/javascript") {
			continue
		}

		tab.AddResultUrl(config.GET, url, config.FromJSFile)
	}
}

func (tab *Tab) HandleRedirectionResp(v *network.EventResponseReceivedExtraInfo) {
	defer tab.WG.Done()
	statusCode := tab.GetStatusCode(v.HeadersText)
	// Navigation request that returned a redirect
	if 300 <= statusCode && statusCode < 400 {
		logger.Logger.Debug("set redirect flag.")
		tab.FoundRedirection = true
	}
}

func (tab *Tab) GetContentCharset(v *network.EventResponseReceived) {
	defer tab.WG.Done()
	var getCharsetRegex = regexp.MustCompile("charset=(.+)$")
	for key, value := range v.Response.Headers {
		if key == "Content-Type" {
			value := value.(string)
			if strings.Contains(value, "charset") {
				value = getCharsetRegex.FindString(value)
				value = strings.ToUpper(strings.Replace(value, "charset=", "", -1))
				tab.PageCharset = value
				tab.PageCharset = strings.TrimSpace(tab.PageCharset)
			}
		}
	}
}

func (tab *Tab) GetStatusCode(headerText string) int {
	rspInput := strings.NewReader(headerText)
	rspBuf := bufio.NewReader(rspInput)
	tp := textproto.NewReader(rspBuf)
	line, err := tp.ReadLine()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return 0
	}
	parts := strings.Split(line, " ")
	if len(parts) < 3 {
		return 0
	}
	code, _ := strconv.Atoi(parts[1])
	return code
}

func MergeHeaders(navHeaders map[string]interface{}, headers map[string]interface{}) []*fetch.HeaderEntry {
	var mergedHeaders []*fetch.HeaderEntry
	for key, value := range navHeaders {
		if _, ok := headers[key]; !ok {
			var header fetch.HeaderEntry
			header.Name = key
			header.Value = value.(string)
			mergedHeaders = append(mergedHeaders, &header)
		}
	}

	for key, value := range headers {
		var header fetch.HeaderEntry
		header.Name = key
		header.Value = value.(string)
		mergedHeaders = append(mergedHeaders, &header)
	}
	return mergedHeaders
}

func ConvertHeadersNoLocation(h map[string][]string) []*fetch.HeaderEntry {
	var headers []*fetch.HeaderEntry
	for key, value := range h {
		if key == "Location" {
			continue
		}
		var header fetch.HeaderEntry
		header.Name = key
		header.Value = value[0]
		headers = append(headers, &header)
	}
	return headers
}
