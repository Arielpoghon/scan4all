package brute

import (
	_ "embed"
	"encoding/json"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pkg"
	"github.com/GhostTroops/scan4all/pkg/fingerprint"
	"github.com/antlabs/strsim"
	"gorm.io/gorm"
	"net/url"
	"regexp"
	"strings"
)

// Error page database
type ErrPage struct {
	gorm.Model
	FingerprintsTag string `json:"fingerprintsTag"` // fingerprint tag; tagged data is fingerprint data, not error data
	Title           string `json:"title"`           // title
	Body            string `json:"body"`            // body
	BodyLen         int    `json:"bodyLen"`         // body length
	BodyHash        string `json:"bodyHash"`        // body hash, Favicohash4key
	BodyMd5         string `json:"bodyMd5"`         // body md5
	HitCnt          uint32 `json:"hitCnt"`          // hit statistics
}

var (
	page404Title []string // 404 title library, body library
	asz404Url    []string // 404 urls, smart learning
)

// Store error, 404, 500, 505 titles and contents in the information database
//  Regex is allowed
//go:embed dicts/fuzz404.txt
var fuzz404 string

// Common 404 url list, smart learning
//go:embed dicts/404url.txt
var sz404Url string

var asz404UrlKey = "asz404Url"

// Initialize dictionaries into the database and prevent duplicates
func init() {
	util.RegInitFunc(func() {
		fuzz404 = util.GetVal4File("fuzz404", fuzz404)
		sz404Url = util.GetVal4File("404url", sz404Url)
		page404Title = strings.Split(strings.TrimSpace(fuzz404), "\n")
		asz404Url = strings.Split(strings.TrimSpace(sz404Url), "\n")
		data, err := util.NewKvDbOp().Get(asz404UrlKey)
		if nil == err && 0 < len(data) {
			aT1 := asz404Url
			if nil != json.Unmarshal(data, &asz404Url) {
				asz404Url = aT1 // fault tolerance
			}
		}
		util.InitDb(&ErrPage{})
	})
}

// Smart learning: non-normal pages are recorded in the database for permanent use; pages handled by this method
// are either error pages or need fingerprint learning, with a tag
//  0、Skip urls already learned
//  1、Learn body
//  2、Learn title
//  3、Deduplicate url records
func StudyErrPageAI(req *util.Response, page *util.Page, fingerprintsTag string) {
	if nil == req || nil == page || "" == req.Body {
		return
	}
	util.DoSyncFunc(func() {
		var data = &ErrPage{}
		body := []byte(req.Body)
		szHs, szMd5 := fingerprint.GetHahsMd5(body)
		// Optimize later based on other queries
		r1 := util.GetOne[ErrPage](data, "bodyHash=? and bodyMd5=?", szHs, szMd5)
		if nil != r1 {
			data = r1
		} else {
			data = &ErrPage{Title: *page.Title, Body: req.Body, BodyLen: len(body), FingerprintsTag: ""}
			data.BodyHash = szHs
			data.BodyMd5 = szMd5
			if "" != fingerprintsTag {
				data.FingerprintsTag = fingerprintsTag
			}
			// Learn matching, do not record duplicates
			if bRst, _ := CheckRepeat(data); !bRst {
				util.Create[ErrPage](*data)
			}
		}
	})
}

// Similarity precision
var fXsdPrecision float64 = 0.96

// Check whether it already exists in the database
func CheckRepeat(data *ErrPage) (bool, *ErrPage) {
	var aRst []ErrPage
	aRst1 := util.GetSubQueryLists[ErrPage, ErrPage](*data, "", aRst, 10000, 0)
	if nil != aRst1 {
		aRst = *aRst1
		for _, x := range aRst {
			if 0 == len(x.FingerprintsTag) && x.BodyLen == data.BodyLen && (x.BodyHash == data.BodyHash || x.BodyMd5 == data.BodyMd5) {
				return true, &x
			}
			if strsim.Compare(x.Body, data.Body) >= fXsdPrecision {
				return true, &x
			}
		}
	}
	return false, nil
}

// Detect whether it is an error page, including status code detection
func CheckIsErrPageAI(req *util.Response, page *util.Page) bool {
	body := []byte(req.Body)
	szHs, szMd5 := fingerprint.GetHahsMd5(body)
	var data = &ErrPage{Title: *page.Title, Body: req.Body, BodyLen: len(body)}
	data.BodyHash = szHs
	data.BodyMd5 = szMd5
	bRst, _ := CheckRepeat(data)
	if false == bRst && (0 < len(data.Title) || 0 < len(data.Body)) {
		for _, x := range page404Title {
			// Error page title detection succeeded
			if 0 < len(data.Title) && (util.StrContains(x, data.Title) || util.StrContains(data.Title, x)) || 0 < len(data.Body) && util.StrContains(data.Body, x) {
				util.Create[ErrPage](*data)
				return true
			}
			u01, err := url.Parse(strings.TrimSpace(*page.Url))
			if nil == err && 2 < len(u01.Path) {
				// Add 404 url detection
				if pkg.Contains4sub[string](asz404Url, u01.Path) {
					return true
				}
				// Add to asz404Url, save to the database
				if 404 == req.StatusCode {
					go func() {
						asz404Url = append(asz404Url, u01.Path)
						util.PutAny[[]string](asz404UrlKey, asz404Url) // Cache 404 path for permanent reuse
					}()
				}
			}
		}
	}
	return bRst
}

// Get title
func Gettitle(body string) *string {
	body = strings.ToLower(body)
	title := ""
	domainreg2 := regexp.MustCompile(`<title>([^<]*)</title>`)
	titlelist := domainreg2.FindStringSubmatch(body)
	if len(titlelist) > 1 {
		title = strings.ToLower(strings.TrimSpace(titlelist[1]))
		return &title
	}
	return &title
}
