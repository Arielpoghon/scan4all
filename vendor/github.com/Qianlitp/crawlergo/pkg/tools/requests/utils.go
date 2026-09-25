package requests

import (
	"github.com/pkg/errors"
	"net/url"
	"strings"
)

// UrlParse calls url.Parse and adds handling for % characters.
func UrlParse(sourceUrl string) (*url.URL, error) {
	u, err := url.Parse(sourceUrl)
	if err != nil {
		u, err = url.Parse(escapePercentSign(sourceUrl))
	}
	if err != nil {
		return nil, errors.Wrap(err, "parse url error")
	}
	return u, nil
}

// escapePercentSign replaces % characters in a URL with %25.
func escapePercentSign(raw string) string {
	return strings.ReplaceAll(raw, "%", "%25")
}
