package fingerprint

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"log"
	"net/url"
	"strings"
	"sync"
)

var EholeFinpx *Packjson
var LocalFinpx *Packjson

func New() error {
	err := LoadWebfingerprintEhole()
	if err != nil {
		return err
	}
	EholeFinpx = GetWebfingerprintEhole()

	err = LoadWebfingerprintLocal()
	if err != nil {
		return err
	}
	LocalFinpx = GetWebfingerprintLocal()
	return nil
}

func mapToJson(param map[string][]string) string {
	dataType, _ := json.Marshal(param)
	dataString := string(dataType)
	return dataString
}

func headerToString(param map[string][]string) string {
	var a []string
	for k, v := range param {
		a = append(a, k+": "+strings.Join(v, ";"))
	}
	return strings.Join(a, "\n")
}

// Merge all the links that fingerprints need to request, namely merge all requests, the same is requested only once
// It will be called multiple times, so the intermediate results need to be cached
func PreprocessingFingerScan(url string) []string {
	// Implement it when there is time
	return []string{}
}

// Same url, cms hit twice no longer matches
var Max_Count = 10

// The icon is identified only once for each target
var Mfavhash *sync.Map = new(sync.Map)

// How many component ids a url is associated with
var MFid *sync.Map = new(sync.Map)

// Clear data
func ClearData() {
	Mfavhash = nil
	EholeFinpx = nil
	LocalFinpx = nil
	DelTmpFgFile()
}

func SvUrl2Id(szUrl string, finp *Fingerprint, rMz string) {
	if 0 < finp.Id {
		if v, ok := MFid.Load(szUrl); ok {
			if d, ok := v.(map[int]map[string]int); ok {
				if n, ok := d[finp.Id][rMz]; ok {
					d[finp.Id][rMz] = n + 1
				} else {
					d[finp.Id] = map[string]int{rMz: 1}
				}
				MFid.Store(szUrl, d)
			}
		} else {
			MFid.Store(szUrl, map[int]map[string]int{finp.Id: map[string]int{rMz: 1}})
		}
	}
}

func CaseMethod(szUrl, method, bodyString, favhash, md5Body, hexBody string, finp *Fingerprint) []string {
	cms := []string{}
	u01, _ := url.Parse(strings.TrimSpace(szUrl))
	if 0 == len(finp.Keyword) {
		//log.Printf("%+v", finp)
		return cms
	}

	if _, ok := Mfavhash.Load(u01.Host + favhash); ok {
		return cms
	}

	switch method {
	case "keyword":
		if ok, rMz := iskeyword(bodyString, finp.Keyword, finp.KeywordMathOr); ok {
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp, rMz)
		}
		break
	case "faviconhash": // Execute only once for the same target
		if ok, rMz := iskeyword(favhash, finp.Keyword, finp.KeywordMathOr); ok {
			Mfavhash.Store(u01.Host+favhash, 1)
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp, rMz)
		}
		break
	case "regular":
		if ok, rMz := isregular(bodyString, finp.Keyword, finp.KeywordMathOr); ok {
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp, rMz)
		}
		break
	case "md5": // supports md5
		if ok, rMz := iskeyword(md5Body, finp.Keyword, finp.KeywordMathOr); ok {
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp, rMz)
		}
		break
	case "base64": // supports base64
		if ok, rMz := iskeyword(bodyString, finp.Keyword, finp.KeywordMathOr); ok {
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp, rMz)
		}
		break
	case "hex":
		if ok, rMz := iskeyword(hexBody, finp.Keyword, finp.KeywordMathOr); ok {
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp, rMz)
		}
		break
	}
	//if 0 < len(cms) {
	//	log.Println(szUrl, " ", finp.Cms, " method: ", method, " can detect ")
	//	log.Printf("%+v\n", cms)
	//}
	return cms
}

var enableFingerTitleHeaderMd5Hex = util.GetValAsBool("enableFingerTitleHeaderMd5Hex")

func CheckHoneyport(a []string) (bool, []string) {
	bRst := util.EnableHoneyportDetection && 10 < len(a)
	if bRst {
		a = []string{}
	}
	return bRst, a
}

// Same url, component (product), >= 2 fingerprints matched, then other fingerprint matches of that component will be skipped
func FingerScan(headers map[string][]string, body []byte, title string, szUrl string, status_code string) ([]string, []string) {
	if nil == body || 0 == len(body) {
		//log.Println(szUrl, " abnormal, body is nil")
		return []string{}, nil
	}
	//log.Println("FgDictFile = ", FgDictFile)
	bodyString := string(body)
	headersjson := mapToJson(headers) + "\n" + headerToString(headers)
	favhash, _ := getfavicon(bodyString, szUrl)

	md5Body := FavicohashMd5(0, nil, body, nil)
	hexBody := hex.EncodeToString(body)

	hexTitle := ""
	md5Title := ""
	hexHeader := ""
	md5Header := ""
	if enableFingerTitleHeaderMd5Hex {
		hexTitle = hex.EncodeToString([]byte(title))
		md5Title = FavicohashMd5(0, nil, []byte(title), nil)
		hexHeader = hex.EncodeToString([]byte(headersjson))
		md5Header = FavicohashMd5(0, nil, []byte(headersjson), nil)
	}

	var cms []string
	var fgIds []string
	u01, _ := url.Parse(strings.TrimSpace(szUrl))
	for _, x1 := range []*Packjson{EholeFinpx, LocalFinpx} {
		for _, finp := range x1.Fingerprint {
			// Move to the very front of the loop to improve efficiency, finp.Id > 0 is compatible with our own fingerprints, non-own ones continue
			if finp.Id > 0 && u01.Path != finp.UrlPath {
				continue
			}
			n1 := len(cms)
			if finp.UrlPath == "" || strings.HasSuffix(szUrl, finp.UrlPath) {
				//if -1 < strings.Index(szUrl, "/favicon.ico") && finp.Cms == "SpringBoot" {
				//	log.Println(szUrl)
				//}
				if finp.Location == "all" {
					cms = append(cms, CaseMethod(szUrl, finp.Method, headersjson+bodyString, favhash, md5Body, hexBody, finp)...)
				} else if finp.Location == "body" { // identification area; body
					cms = append(cms, CaseMethod(szUrl, finp.Method, bodyString, favhash, md5Body, hexBody, finp)...)
				} else if finp.Location == "header" { // identification area: header
					cms = append(cms, CaseMethod(szUrl, finp.Method, headersjson, favhash, md5Header, hexHeader, finp)...)
				} else if finp.Location == "title" { // identification area: title
					cms = append(cms, CaseMethod(szUrl, finp.Method, title, favhash, md5Title, hexTitle, finp)...)
				} else if finp.Location == "status_code" { // identification area: status_code
					if ok, rMz := iskeyword(status_code, finp.Keyword, finp.KeywordMathOr); ok {
						cms = append(cms, finp.Cms)
						SvUrl2Id(szUrl, finp, rMz)
					}
				}
			}
			// Fingerprint found
			if len(cms) > n1 {
				fgIds = append(fgIds, fmt.Sprintf("%v", finp.Id))
				log.Printf("%d\n", finp.Id)
				n1 = len(cms)
			}
			// Honeypot detection, abandon (discard) results
			if ok, a := CheckHoneyport(cms); ok {
				cms = a
				break
			}
			if len(cms) >= Max_Count {
				break
			}
		}

	}
	return cms, fgIds
}
