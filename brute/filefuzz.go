package brute

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/lib/scan/Const"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/pkg/models"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pkg/fingerprint"
	"github.com/antlabs/strsim"
	"log"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Backup and sensitive file suffixes
//
//go:embed dicts/bakSuffix.txt
var bakSuffix string

// Backup/sensitive file HTTP header Content-Type detection
//
//go:embed dicts/fuzzContentType1.txt
var fuzzct string

// Sensitive file prefixes
//
//go:embed dicts/prefix.txt
var szPrefix string

var (
	ret            = []string{} // sensitive information file dictionary
	prefix, suffix []string     // sensitive information dictionary: prefix, suffix
)

// Generate sensitive information dictionary
func InitGeneral() int {
	szPrefix = util.GetVal4File("prefix", szPrefix)
	prefix = strings.Split(strings.TrimSpace(szPrefix), "\n")
	suffix = strings.Split(strings.TrimSpace(bakSuffix), "\n")

	for i := 0; i < len(prefix); i++ {
		for j := 0; j < len(suffix); j++ {
			ret = append(ret, "/"+prefix[i]+suffix[j])
		}
	}
	disabledFileFuzz = !util.GetValAsBool("enableFileFuzz")
	return len(ret)
}

// Request url and return a custom object
func reqPage(u string) (*util.Page, *util.Response, error) {
	page := &util.Page{Url: &u}
	var method = "GET"
	for _, ext := range suffix {
		if strings.HasSuffix(u, ext) {
			page.IsBackUpPath = true
			method = "HEAD" // saves request time
		}
	}
	header := make(map[string]string)
	header["Accept"] = "*/*"
	header["upgrade-insecure-requests"] = "1"
	//header["Connection"] = "close"
	//header["Pragma"] = "no-cache"
	// by WAF
	header = *ByWafHd(&header)

	// fuzz check Shiro CVE_2016_4437
	header["Cookie"] = "JSESSIONID=" + RandStr4Cookie + ";rememberMe=123"
	if req, err := util.HttpRequset(u, method, "", false, header); err == nil && nil != req && nil != req.Header {
		//if pkg.IntInSlice(req.StatusCode, []int{301, 302, 307, 308}) {
		// Simple and crude, high efficiency
		if 300 <= req.StatusCode && req.StatusCode < 400 {
			page.Is302 = true
		}
		page.StatusCode = req.StatusCode
		page.Resqonse = req
		page.Header = req.Header
		page.BodyLen = len(req.Body)
		page.Title = Gettitle(req.Body)
		page.LocationUrl = &req.Location
		//  Sensitive file header information detection
		page.IsBackUpPage = CheckBakPage(req)
		// https://en.wikipedia.org/wiki/HTTP_403
		// 403 Forbidden is an HTTP status code in the HTTP protocol. A 403 status code means the server successfully parsed the request but the client does not have permission to access the resource
		page.Is403 = req.StatusCode == 403
		return page, req, err
	} else {
		return page, nil, err
	}
}

// Sensitive file header information detection:
//
//	Detect whether the header contains sensitive file, backup file, stream file, and other sensitive information
func CheckBakPage(req *util.Response) bool {
	if x0, ok := (*req.Header)["Content-Type"]; ok && 0 < len(x0) {
		x0B := []byte(x0[0])
		for _, reg := range regs {
			// Find the corresponding regex
			if r1, ok := regsMap[reg]; ok {
				if r1.Match(x0B) {
					return true
				}
			}
		}
	}
	return false
}

// Backup/sensitive file HTTP header Content-Type detection, regex
var regs []string

var (
	regsMap          = make(map[string]*regexp.Regexp) // fuzz regex library
	disabledFileFuzz = false                           // whether fuzz is enabled
	NoDoPath         sync.Map
	NoDoPathInit     = false
)

func DoInitMap() {
	if NoDoPathInit == false && "" != fingerprint.FgDictFile {
		NoDoPathInit = true
		if data, err := os.ReadFile(fingerprint.FgDictFile); nil == err {
			a := strings.Split(strings.TrimSpace(string(data)), "\n")
			for _, k := range a {
				NoDoPath.Store(k, true)
			}
		}
	}
}

// Initialize dictionaries, arrays, etc.
func init() {
	util.RegInitFunc(func() {
		bakSuffix = util.GetVal4File("bakSuffix", bakSuffix)
		fuzzct = util.GetVal4File("fuzzct", fuzzct)

		InitGeneral()
		regs = strings.Split(strings.TrimSpace(fuzzct), "\n")
		var err error
		// Compile all at once during initialization, otherwise it affects efficiency
		for _, reg := range regs {
			regsMap[reg], err = regexp.Compile(reg)
			if nil != err {
				log.Println(reg, " regexp.Compile error: ", err)
			}
		}
		//regs = append(regs, ret...)
		// Build based on factory method
		util.EngineFuncFactory(Const.ScanType_WebDirScan, func(evt *models.EventData, args ...interface{}) {
			filePaths, fileFuzzTechnologies := FileFuzz(evt.Task.ScanWeb, 200, 100, "")
			util.SendEngineLog(evt, Const.ScanType_WebDirScan, filePaths, fileFuzzTechnologies)
		})

		// Register one
	})
}

// Absolute 404 request file prefix
//var file_not_support = "file_not_support"

// Absolute 404 request file
//var RandStr = file_not_support + "_scan4all"

// Random 10-character string
var RandStr4Cookie = util.RandStringRunes(10)

type FuzzData struct {
	Path *[]string
	Req  *util.Page
}

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types
var (
	r001 = regexp.MustCompile(`\.(aac)|(abw)|(arc)|(avif)|(avi)|(azw)|(bin)|(bmp)|(bz)|(bz2)|(cda)|(csh)|(css)|(csv)|(doc)|(docx)|(eot)|(epub)|(gz)|(gif)|(ico)|(ics)|(jar)|(jpeg)|(jpg)|(js)|(json)|(jsonld)|(mid)|(midi)|(mjs)|(mp3)|(mp4)|(mpeg)|(mpkg)|(odp)|(ods)|(odt)|(oga)|(ogv)|(ogx)|(opus)|(otf)|(png)|(pdf)|(php)|(ppt)|(pptx)|(rar)|(rtf)|(sh)|(svg)|(tar)|(tif)|(tiff)|(ts)|(ttf)|(txt)|(vsd)|(wav)|(weba)|(webm)|(webp)|(woff)|(woff2)|(xhtml)|(xls)|(xlsx)|(xml)|(xul)|(zip)|(3gp)|(3g2)|(7z)$`)
	cT1  = make(chan struct{}, 1) // only allow 1 url fuzz at a time
)

// Rewritten fuzz: optimized flow, optimized algorithm, fixed thread-safety bug, added intelligent features
//
//	Calling ioutil.ReadAll(resp.Body) twice, the second read returns an EOF error
//	Remove the fingerprint request path to avoid duplication
func FileFuzz(u string, indexStatusCode int, indexContentLength int, indexbody string) ([]string, []string) {
	if util.TestRepeat(u) {
		return []string{}, []string{}
	}
	cT1 <- struct{}{}
	defer func() {
		<-cT1
	}()
	if disabledFileFuzz {
		return []string{}, []string{}
	}
	DoInitMap()
	u01, err := url.Parse(strings.TrimSpace(u))
	if nil == err {
		u = u01.Scheme + "://" + u01.Host + "/"
	}
	// Use host to ensure only one protocol (https or http) is used
	if disabledFileFuzz || util.TestRepeat(u01.Host, "FileFuzz") {
		return []string{}, []string{}
	}
	//log.Println("start file fuzz", u)
	var (
		//path404               = RandStr // absolute 404 page path
		errorTimes   int32    = 0 // error counter, exit fuzz if > 20
		technologies []string     // fingerprint data
		path         []string     // successful page paths
	)
	url404, url404req, err, ok := util.TestIs404Page(u) //reqPage(u + path404)
	if err == nil && ok && nil != url404req {
		// Upgrade protocol
		if "" != url404req.Protocol && !strings.Contains(url404req.Protocol, "HTTP/1.") {
			u = "https://" + u01.Host + "/"
		}
		go util.CheckHeader(url404req.Header, u)
		// Skip all fuzz for the current target; all subsequent fuzz is meaningless
		if 200 == url404.StatusCode || 301 == url404.StatusCode || 302 == url404.StatusCode {
			return []string{}, []string{}
		}
		// In fact, regardless of the status code here, it is all 404
		// All error pages > 400 > 500 are fuzzed for error page fingerprints
		// To improve precision, only 404 needs to be considered
		//if url404req.StatusCode > 400 {
		if url404req.StatusCode == 404 {
			technologies = Addfingerprints404(technologies, url404req, url404) // Add fingerprint based on 404 page file scan
			StudyErrPageAI(url404req, url404, "")                              // Error page learning
		} else {
			return []string{}, []string{}
		}
	} else {
		return []string{}, []string{}
	}
	var wg sync.WaitGroup
	// Control to close all fuzz for the current target mid-way
	// Terminate the fuzz task
	ctx, stop := context.WithCancel(util.Ctx_global)
	// Terminate the result receiving task
	ctx2, stop2 := context.WithCancel(util.Ctx_global)
	// Control the number of fuzz threads
	var ch = make(chan struct{}, util.Fuzzthreads)
	// Asynchronously receive results
	var async_data = make(chan *FuzzData, util.Fuzzthreads*2)
	var async_technologies = make(chan []string, util.Fuzzthreads*2)
	// Errors at 30% of the dictionary length
	var MaxErrorTimes int32 = int32(util.GetValAsInt("MaxErrorTimes", 50)) //int32(float32(len(filedic)) * 0.005)
	if strings.HasPrefix(url404req.Protocol, "HTTP/2") || strings.HasPrefix(url404req.Protocol, "HTTP/3") {
		MaxErrorTimes = int32(len(filedic))
	}
	//var MaxErrorTimes int32 = 100
	if c1 := util.GetClient(u, map[string]interface{}{"Timeout": 15 * time.Second, "ErrLimit": MaxErrorTimes}); nil != c1 {
		util.PutClientCc(u, c1)
	}
	//defer func() {
	//	close(ch)
	//	close(async_data)
	//	close(async_technologies)
	//}()
	//log.Printf("start fuzz: %s for", u)
	nStop := 400
	var lst200 *util.Response
	t001 := time.NewTicker(3 * time.Second)
	var nCnt int32 = 0
	// Asynchronously receive fuzz results
	go func() {
		defer stop()
		for {
			select {
			case <-ctx2.Done():
				return
			case <-t001.C:
				fmt.Printf("file fuzz(ok/total:%5d/%5d) (errs/limitErr:%3d/%3d) %s\r", nCnt, len(filedic), errorTimes, MaxErrorTimes, u)
				if errorTimes >= MaxErrorTimes {
					stop()
				}
			case x1, ok := <-async_data:
				if ok {
					if lst200 == nil || x1.Req.Resqonse.Body != lst200.Body {
						path = append(path, (*x1.Path)...)
					}
					lst200 = x1.Req.Resqonse
					if len(path) > nStop {
						stop() // Send stop command
						atomic.AddInt32(&errorTimes, MaxErrorTimes)
						return
					}
				} else {
					return
				}
			case x2, ok := <-async_technologies:
				if ok {
					technologies = append(technologies, x2...)
				} else {
					return
				}
				// <-time.After(time.Duration(100) * time.Millisecond)
			}
		}
	}()
	log.Printf("wait for file fuzz(dicts:%d) %s \r", len(filedic), u)

BreakAll:
	for _, payload := range filedic {
		payload = strings.TrimSpace(payload)
		// Paths already run by httpx are not re-run here
		if _, ok := NoDoPath.Load(payload); ok {
			continue
		}
		// Stop signal received
		if errorTimes >= MaxErrorTimes {
			stop()
			break
		}
		select {
		case <-ctx.Done():
			break BreakAll
		default:
			{
				endP := u[len(u)-1:] == "/"
				ch <- struct{}{}
				wg.Add(1)
				go func(payload string) {
					payload = strings.TrimSpace(payload)
					defer func() {
						<-ch // concurrency control
						wg.Done()
					}()
					atomic.AddInt32(&nCnt, 1)
					select {
					case <-ctx.Done(): // 00-Capture all thread close signals and exit, close for all
						atomic.AddInt32(&errorTimes, MaxErrorTimes)
						return
					default:
						//if _, ok := noRpt.Load(szKey001Over); ok {
						//	stop()
						//	return
						//}
						// 01-if errors > 20, close all fuzz
						if errorTimes >= MaxErrorTimes {
							stop() // Send stop command
							return
						}
						// Fix url; by default assume payload does not contain /
						szUrl := u + payload
						if strings.HasPrefix(payload, "/") && endP {
							szUrl = u + payload[1:]
						}
						//log.Printf("start fuzz: [%s]", szUrl)
						if fuzzPage, req, err := reqPage(szUrl); err == nil && nil != req && 0 < len(req.Body) {
							if 200 == req.StatusCode {
								if nil == lst200 {
									lst200 = req
								} else if lst200.Body == req.Body { // meaningless 200
									return
								}
								if oU1, err := url.Parse(szUrl); nil == err {
									a50 := r001.FindStringSubmatch(oU1.Path)
									if 0 < len(a50) {
										s2 := mime.TypeByExtension(filepath.Ext(a50[0]))
										ct := (*req).Header.Get("Content-Type")
										if "" != ct && "" != s2 && strings.Contains(ct, s2) {
											return
										}
									}
								}
								//log.Printf("%d : %s \n", req.StatusCode, szUrl)
								if IsLoginPage(szUrl, req.Body, req.StatusCode) {
									technologies = append(technologies, "loginpage")
								}
							}
							go util.CheckHeader(req.Header, u)
							// 02-Same status code as req1 and similarity > 9.5, close all fuzz
							fXsd := strsim.Compare(url404req.Body, req.Body)
							bBig95 := 0.95 < fXsd
							//if "/bea_wls_internal/classes/mejb@/org/omg/stub/javax/management/j2ee/_ManagementHome_Stub.class" == payload {
							//	log.Println("start debug")
							//}
							if url404.StatusCode == fuzzPage.StatusCode && bBig95 {
								stop() // Send stop command
								atomic.AddInt32(&errorTimes, MaxErrorTimes)
								return
							}
							var path1, technologies1 = []string{}, []string{}
							// 03-Error page (>400) or similarity matches 404
							if fuzzPage.StatusCode >= 400 || bBig95 || fuzzPage.StatusCode != 200 {
								// 03.01-Error page fingerprint matching
								technologies = Addfingerprints404(technologies, req, fuzzPage) // Add fingerprint based on 404 page file scan
								// 03.02-Similarity to absolute 404 below 0.8, add body 404 body list
								// 03.03-Add 404 title list
								if 0.8 > fXsd && fuzzPage.StatusCode != 200 && fuzzPage.StatusCode != url404.StatusCode {
									StudyErrPageAI(req, fuzzPage, "") // Error page learning
								}
								// 04-403: 403 bypass
								if fuzzPage.Is403 && !url404.Is403 {
									a11 := ByPass403(&u, &payload, &wg)
									// Means ByPass403 succeeded; output the result to console?
									if 0 < len(a11) {
										async_data <- &FuzzData{Path: &a11, Req: fuzzPage}
									}
								}
								return
							}
							// Current and absolute 404 are not 404, subsequent comparisons are meaningless; all equal to [200, 301, 302], all meaningless, all indicate fuzz failed
							if url404.StatusCode != 404 && url404.StatusCode == fuzzPage.StatusCode {
								return
							}

							// 05-Redirect detection; even if redirected, if different from absolute 404, detection succeeded
							//if CheckDirckt(fuzzPage, req) && url404.StatusCode != fuzzPage.StatusCode {
							//	return
							//}
							// 1、Status code same as absolute 404 2、Computed via smart recognition
							is404Page := url404.StatusCode == fuzzPage.StatusCode || CheckIsErrPageAI(req, fuzzPage)
							// 06-Successful page, not an error page
							if !is404Page || 200 == fuzzPage.StatusCode && url404.StatusCode != fuzzPage.StatusCode {
								// 1、Fingerprint matching
								technologies1 = Addfingerprintsnormal(payload, technologies1, req, fuzzPage) // Add fingerprint based on 200 page file scan
								// 2、Add successful fuzz path results
								path1 = append(path1, *fuzzPage.Url)
							}
							if 0 < len(path1) {
								async_data <- &FuzzData{Path: &path1, Req: fuzzPage}
							}
							if 0 < len(technologies1) {
								async_technologies <- technologies1
							}
					} else { // this should be an atomic operation
						if nil != err {
								//if nil != client && strings.Contains(err.Error(), " connect: connection reset by peer") {
								//	client.Client = client.GetClient(nil)
								//}
								//log.Printf("file fuzz %s is err %v\n", szUrl, err)
							}
							atomic.AddInt32(&errorTimes, 1)
						}
						return
					}
				}(payload)
			}
		}
	}
	// By default wait for all to finish
	wg.Wait()
	if 0 < len(path) {
		util.SendLog(u, "brute", strings.Join(path, "\n"), "")

		log.Printf("fuzz is over: %s found:\n%s\n", u, strings.Join(path, "\n"))
		path = util.SliceRemoveDuplicates(path)
	}
	technologies = util.SliceRemoveDuplicates(technologies)
	if 0 < len(technologies) {
		util.SendLog(u, "brute", strings.Join(technologies, "\n"), "")
	}

	stop() // Send stop command
	<-time.After(time.Second * 2)
	stop2()
	return path, technologies
}

// html redirect
var reg1 = regexp.MustCompile("(?i)<meta.*http-equiv\\s*=\\s*\"refresh\".*content\\s*=\\s*\"5;\\s*url=")

// js redirect
var reg2 = regexp.MustCompile("(window|self|top)\\.location\\.href\\s*=")

// Redirect detection
//
//	1、Status code redirect: 301 means Permanently Moved; 302 redirect means Temporarily Moved
//	2、html refresh redirect
//	3、js redirect
func CheckDirckt(fuzzPage *util.Page, req *util.Response) bool {
	if nil == fuzzPage || nil == req {
		return false
	}
	data := []byte(req.Body)
	// 01 redirect:
	if 302 == req.StatusCode || 301 == req.StatusCode {
		return true
	} else if 0 < len(data) && (0 < len(reg1.Find(data)) || 0 < len(reg2.Find(data))) { // html refresh redirect; js redirect
		return true
	}
	return false
}
