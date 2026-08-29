package spider

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/antchfx/htmlquery"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/text/encoding/simplifiedchinese"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type PocWebAppData struct {
	Title          string `json:"title"`           //Website title
	Link           string `json:"link"`            //Website link
	StatusCode     string `json:"status_code"`     //Status code
	Ip             string `json:"ip"`              //IP
	Port           string `json:"port"`            //Port
	Keywords       string `json:"keywords"`        //Keywords
	Description    string `json:"description"`     //Website description
	Classification string `json:"classification"`  //Content classification
	SensitiveWords string `json:"sensitive_words"` //Sensitive words
	Framework      string `json:"framework"`       //Website framework
	Header         string `json:"header"`          //Header information
	SecondaryLinks string `json:"secondary_links"` //Secondary links
	LargeImage     string `json:"large_image"`     //Website screenshot (large)
	SmallImage     string `json:"small_image"`     //Website screenshot (cover)
	Tls            string `json:"tls"`             //TLS certificate
}

type Org struct {
	Country            string `json:"country"`             // Country or region
	Province           string `json:"province"`            // Province/City/Autonomous region
	Locality           string `json:"locality"`            // Locality
	OrganizationalUnit string `json:"organizational_unit"` // Organizational unit
	Organization       string `json:"organization"`        // Organization
	CommonName         string `json:"common_name"`         // Common name
	StreetAddress      string `json:"street_address"`      // Street address
	PostalCode         string `json:"postal_code"`         // Postal code
}

type TLS struct {
	Proto                 string      `json:"proto"`                   // Protocol
	Subject               Org         `json:"subject"`                 // Subject name
	Issuer                Org         `json:"issuer"`                  // Issuer name
	DNSNames              []string    `json:"dns_names"`               // DNS server names
	CRLDistributionPoints string      `json:"crl_distribution_points"` // CRL distribution point URI
	OCSPServer            string      `json:"ocsp_server"`             // Online Certificate Status Protocol URI
	IssuingCertificateURL string      `json:"issuing_certificate_url"` // CA issuer URI
	SubjectKeyId          []uint8     `json:"subject_key_id"`          // Subject key identifier
	AuthorityKeyId        []uint8     `json:"authority_key_id"`        // Authority key identifier
	SignatureAlgorithm    string      `json:"signature_algorithm"`     // Signature algorithm
	PublicKeyAlgorithm    string      `json:"public_key_algorithm"`    // Public key algorithm
	Signature             []uint8     `json:"signature"`               // Signature
	PublicKey             interface{} `json:"public_key"`              // Public key
	NotBefore             time.Time   `json:"not_before"`              // Validity start
	NotAfter              time.Time   `json:"not_after"`               // Validity end
	SerialNumber          *big.Int    `json:"serial_number"`           // Serial number
	Version               int         `json:"version"`                 // Version
}

const (
	MaxWidth  = 1920
	MinHeight = 1080
)

/*Generate UUID*/
func GenerateUUID() string {
	return uuid.NewV4().String()
}

/*
Execute screenshot
--remote-debugging-port=9222
Reference: https://github.com/chromedp/chromedp/issues/1131

chromedp.Evaluate(js, &height), returns the result of the last JS statement
*/
func DoFullScreenshot(url, path string) bool {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("headless", false),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("disable-extensions", true), //Enable plugin support
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-gpu", true), //Enable GPU rendering
		chromedp.Flag("hide-scrollbars", true),
		chromedp.Flag("mute-audio", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.NoFirstRun, //Set the website as not first run
		chromedp.WindowSize(MaxWidth, MinHeight),
		chromedp.Flag("blink-settings", "imagesEnabled=true"),
		chromedp.Flag("enable-automation", false),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36"),
	)
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	// Create a Chrome instance
	ctx, cancel := chromedp.NewContext(
		allocCtx,
		chromedp.WithLogf(log.Printf),
	)
	defer cancel()

	// Create a timeout
	ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Cache object
	var buf []byte

	// Run the screenshot
	if err := chromedp.Run(ctx, fullScreenshot(url, 100, &buf)); err != nil {
		return false
	}

	// Save the file
	if "" != path {
		if err := ioutil.WriteFile(path, buf, 0644); err != nil {
			return false
		}
	}

	return true
}

/*Full-screen screenshot*/
func fullScreenshot(url string, quality int64, res *[]byte) chromedp.Tasks {
	return chromedp.Tasks{
		chromedp.Navigate(url),
		chromedp.ActionFunc(func(ctx context.Context) (err error) {
			*res, err = page.CaptureScreenshot().WithQuality(quality).WithClip(&page.Viewport{
				X:      0,
				Y:      0,
				Width:  MaxWidth,
				Height: MinHeight,
				Scale:  1,
			}).Do(ctx)
			if err != nil {
				return err
			}
			return nil
		}),
	}
}

func (a TLS) IsEmpty() bool {
	return reflect.DeepEqual(a, TLS{})
}

// Convert charset
func ConvertCharset(dataByte []byte) string {
	sourceCode := string(dataByte)
	if !utf8.Valid(dataByte) {
		data, _ := simplifiedchinese.GBK.NewDecoder().Bytes(dataByte)
		sourceCode = string(data)
	}
	return sourceCode
}

func CatchHTTP(url, ip string, port int, timeOut time.Duration) (site PocWebAppData) {

	// Construct a GET request
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return site
	}
	request.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36")
	// Skip HTTPS verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: timeOut}
	resp, err := client.Do(request)
	if err != nil {
		return site
	}

	defer resp.Body.Close()

	if resp == nil {
		return site
	}

	if resp.TLS == nil {
		site.Tls = ""
	} else {
		if len(resp.TLS.PeerCertificates) == 0 {
			site.Tls = ""
		} else {
			certInfo := resp.TLS.PeerCertificates[0]
			if certInfo == nil {
				site.Tls = ""
			} else {
				tls := TLS{
					Proto: resp.Proto,
					Subject: Org{
						Country:            strings.Join(certInfo.Subject.Country, ","),
						Province:           strings.Join(certInfo.Subject.Province, ","),
						Locality:           strings.Join(certInfo.Subject.Locality, ","),
						OrganizationalUnit: strings.Join(certInfo.Subject.OrganizationalUnit, ","),
						Organization:       strings.Join(certInfo.Subject.Organization, ","),
						CommonName:         certInfo.Subject.CommonName,
						StreetAddress:      strings.Join(certInfo.Subject.StreetAddress, ","),
						PostalCode:         strings.Join(certInfo.Subject.PostalCode, ","),
					},
					Issuer: Org{
						Country:            strings.Join(certInfo.Issuer.Country, ","),
						Province:           strings.Join(certInfo.Issuer.Province, ","),
						Locality:           strings.Join(certInfo.Issuer.Locality, ","),
						OrganizationalUnit: strings.Join(certInfo.Issuer.OrganizationalUnit, ","),
						Organization:       strings.Join(certInfo.Issuer.Organization, ","),
						CommonName:         certInfo.Issuer.CommonName,
						StreetAddress:      strings.Join(certInfo.Issuer.StreetAddress, ","),
						PostalCode:         strings.Join(certInfo.Issuer.PostalCode, ","),
					},
					DNSNames:              certInfo.DNSNames,
					CRLDistributionPoints: strings.Join(certInfo.CRLDistributionPoints, ","),
					OCSPServer:            strings.Join(certInfo.OCSPServer, ","),
					IssuingCertificateURL: strings.Join(certInfo.IssuingCertificateURL, ","),
					SubjectKeyId:          certInfo.SubjectKeyId,
					AuthorityKeyId:        certInfo.AuthorityKeyId,
					SignatureAlgorithm:    certInfo.SignatureAlgorithm.String(),
					PublicKeyAlgorithm:    certInfo.PublicKeyAlgorithm.String(),
					Signature:             certInfo.Signature,
					PublicKey:             certInfo.PublicKey,
					NotBefore:             certInfo.NotBefore,
					NotAfter:              certInfo.NotAfter,
					SerialNumber:          certInfo.SerialNumber,
					Version:               certInfo.Version,
				}
				tlsStr, err := json.Marshal(tls)
				if err == nil {
					site.Tls = string(tlsStr)
				} else {
					site.Tls = ""
				}
			}
		}
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	htmlData := strings.NewReader(ConvertCharset(data))

	doc, err := htmlquery.Parse(htmlData)
	if err != nil {
		fmt.Println(err)
		return
	}

	titleNode := htmlquery.FindOne(doc, `//title`)
	if titleNode != nil {
		site.Title = htmlquery.InnerText(titleNode)
	}

	descriptionNode := htmlquery.FindOne(doc, `//meta[@name="description"]`)
	if descriptionNode != nil {
		site.Description = htmlquery.SelectAttr(descriptionNode, "content")
	}

	keywordsNode := htmlquery.FindOne(doc, `//meta[@name="keywords"]`)
	if keywordsNode != nil {
		site.Keywords = htmlquery.SelectAttr(keywordsNode, "content")
	}

	header, _ := json.Marshal(resp.Header)
	site.Header = string(header)
	site.Port = strconv.Itoa(port)
	site.Ip = ip
	site.Classification = ""
	site.Framework = ""
	site.StatusCode = strconv.Itoa(resp.StatusCode)
	site.LargeImage = ""
	site.SmallImage = ""
	site.SensitiveWords = ""
	site.Link = url

	var links []map[string]string

	for _, node := range htmlquery.Find(doc, `//a`) {
		if node != nil {
			_link, _text := "", ""
			nodeLink := htmlquery.FindOne(node, "/@href")
			if nodeLink != nil {
				_link = htmlquery.SelectAttr(nodeLink, "href")
			}
			_text = htmlquery.InnerText(node)
			if _link != "" && _text != "" && _link != "#" {
				links = append(links, map[string]string{
					"link": _link,
					"text": _text,
				})
			}
		}
	}

	linksStr, _ := json.Marshal(links)
	site.SecondaryLinks = string(linksStr)

	siteImageName := fmt.Sprintf(`%s.png`, GenerateUUID())
	status := DoFullScreenshot(url, fmt.Sprintf("./static/%s", siteImageName))
	if status {
		site.SmallImage = siteImageName
		site.LargeImage = siteImageName
	}

	return site
}
