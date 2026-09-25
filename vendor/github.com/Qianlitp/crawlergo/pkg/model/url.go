package model

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/Qianlitp/crawlergo/pkg/tools/requests"
)

type URL struct {
	url.URL
}

func GetUrl(_url string, parentUrls ...URL) (*URL, error) {
	// Parse the URL and convert it to a complete form
	var u URL
	_url, err := u.parse(_url, parentUrls...)
	if err != nil {
		return nil, err
	}

	if len(parentUrls) == 0 {
		_u, err := requests.UrlParse(_url)
		if err != nil {
			return nil, err
		}
		u = URL{*_u}
		if u.Path == "" {
			u.Path = "/"
		}
	} else {
		pUrl := parentUrls[0]
		_u, err := pUrl.Parse(_url)
		if err != nil {
			return nil, err
		}
		u = URL{*_u}
		if u.Path == "" {
			u.Path = "/"
		}
		//fmt.Println(_url, pUrl.String(), u.String())
	}

	fixPath := regexp.MustCompile("^/{2,}")

	if fixPath.MatchString(u.Path) {
		u.Path = fixPath.ReplaceAllString(u.Path, "/")
	}

	return &u, nil
}

/*
*
Repair an incomplete URL
*/
func (u *URL) parse(_url string, parentUrls ...URL) (string, error) {
	_url = strings.Trim(_url, " ")

	if len(_url) == 0 {
		return "", errors.New("invalid url, length 0")
	}
	// Replace consecutive # characters
	if strings.Count(_url, "#") > 1 {
		_url = regexp.MustCompile(`#+`).ReplaceAllString(_url, "#")
	}

	// Return immediately when there is no parent URL
	if len(parentUrls) == 0 {
		return _url, nil
	}

	if strings.HasPrefix(_url, "http://") || strings.HasPrefix(_url, "https://") {
		return _url, nil
	} else if strings.HasPrefix(_url, "javascript:") {
		return "", errors.New("invalid url, javascript protocol")
	} else if strings.HasPrefix(_url, "mailto:") {
		return "", errors.New("invalid url, mailto protocol")
	}
	return _url, nil
}

func (u *URL) QueryMap() map[string]interface{} {
	queryMap := map[string]interface{}{}
	for key, value := range u.Query() {
		if len(value) == 1 {
			queryMap[key] = value[0]
		} else {
			queryMap[key] = value
		}
	}
	return queryMap
}

/*
*
Return the URL without query parameters
*/
func (u *URL) NoQueryUrl() string {
	return fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
}

/*
*
Return the URL without its fragment
*/
func (u *URL) NoFragmentUrl() string {
	return strings.Replace(u.String(), u.Fragment, "", -1)
}

func (u *URL) NoSchemeFragmentUrl() string {
	return fmt.Sprintf("://%s%s", u.Host, u.Path)
}

func (u *URL) NavigationUrl() string {
	return u.NoSchemeFragmentUrl()
}

/*
*
Return the root domain.

For example, a.b.c.360.cn returns 360.cn.
*/
func (u *URL) RootDomain() string {
	domain := u.Hostname()
	suffix, icann := publicsuffix.PublicSuffix(strings.ToLower(domain))
	// Return an empty string for domains not managed by ICANN
	if !icann {
		return ""
	}
	i := len(domain) - len(suffix) - 1
	// Return an empty string for an invalid domain
	if i <= 0 {
		return ""
	}
	if domain[i] != '.' {
		return ""
	}
	return domain[1+strings.LastIndex(domain[:i], "."):]
}

/*
*
Return the file extension.
*/
func (u *URL) FileName() string {
	parts := strings.Split(u.Path, `/`)
	lastPart := parts[len(parts)-1]
	if strings.Contains(lastPart, ".") {
		return lastPart
	} else {
		return ""
	}
}

/*
*
Return the file extension.
*/
func (u *URL) FileExt() string {
	parts := path.Ext(u.Path)
	// The first character includes the dot
	if len(parts) > 0 {
		return strings.ToLower(parts[1:])
	}
	return parts
}

/*
*
Return the parent path, or an empty string when this is the root path
*/
func (u *URL) ParentPath() string {
	if u.Path == "/" {
		return ""
	} else if strings.HasSuffix(u.Path, "/") {
		if strings.Count(u.Path, "/") == 2 {
			return "/"
		}
		parts := strings.Split(u.Path, "/")
		parts = parts[:len(parts)-2]
		return strings.Join(parts, "/")
	} else {
		if strings.Count(u.Path, "/") == 1 {
			return "/"
		}
		parts := strings.Split(u.Path, "/")
		parts = parts[:len(parts)-1]
		return strings.Join(parts, "/")
	}
}
