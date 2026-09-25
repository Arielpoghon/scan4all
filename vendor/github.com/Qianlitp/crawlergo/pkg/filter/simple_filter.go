package filter

import (
	"strings"

	"github.com/Qianlitp/crawlergo/pkg/config"
	"github.com/Qianlitp/crawlergo/pkg/model"
	mapset "github.com/deckarep/golang-set"
)

type SimpleFilter struct {
	UniqueSet mapset.Set
	HostLimit string
}

var (
	staticSuffixSet = config.StaticSuffixSet.Clone()
)

func init() {
	for _, suffix := range []string{"js", "css", "json"} {
		staticSuffixSet.Add(suffix)
	}
}

// Returns true if the request should be filtered.
func (s *SimpleFilter) DoFilter(req *model.Request) bool {
	if s.UniqueSet == nil {
		s.UniqueSet = mapset.NewSet()
	}
	// First check whether the domain should be filtered.
	if s.HostLimit != "" && s.DomainFilter(req) {
		return true
	}
	// Filter duplicate requests.
	if s.UniqueFilter(req) {
		return true
	}
	// Filter static resources.
	if s.StaticFilter(req) {
		return true
	}
	return false
}

// Filters duplicate requests.
func (s *SimpleFilter) UniqueFilter(req *model.Request) bool {
	if s.UniqueSet == nil {
		s.UniqueSet = mapset.NewSet()
	}
	if s.UniqueSet.Contains(req.UniqueId()) {
		return true
	} else {
		s.UniqueSet.Add(req.UniqueId())
		return false
	}
}

// Filters static resources.
func (s *SimpleFilter) StaticFilter(req *model.Request) bool {
	if s.UniqueSet == nil {
		s.UniqueSet = mapset.NewSet()
	}
	// First convert the slice to a map.

	if req.URL.FileExt() == "" {
		return false
	}
	if staticSuffixSet.Contains(req.URL.FileExt()) {
		return true
	}
	return false
}

// Keeps only links belonging to the specified domain.
func (s *SimpleFilter) DomainFilter(req *model.Request) bool {
	if s.UniqueSet == nil {
		s.UniqueSet = mapset.NewSet()
	}
	if req.URL.Host == s.HostLimit || req.URL.Hostname() == s.HostLimit {
		return false
	}
	if strings.HasSuffix(s.HostLimit, ":80") && req.URL.Port() == "" && req.URL.Scheme == "http" {
		if req.URL.Hostname()+":80" == s.HostLimit {
			return false
		}
	}
	if strings.HasSuffix(s.HostLimit, ":443") && req.URL.Port() == "" && req.URL.Scheme == "https" {
		if req.URL.Hostname()+":443" == s.HostLimit {
			return false
		}
	}
	return true
}
