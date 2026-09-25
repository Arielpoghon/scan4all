package pkg

import "time"

type TaskConfig struct {
	MaxCrawlCount           int    // Maximum number of requests to crawl
	FilterMode              string // simple, smart, or strict
	ExtraHeaders            map[string]interface{}
	ExtraHeadersString      string
	AllDomainReturn         bool // Collect all domains
	SubDomainReturn         bool // Collect subdomains
	NoHeadless              bool // Headless mode
	DomContentLoadedTimeout time.Duration
	TabRunTimeout           time.Duration     // Timeout for a single tab
	PathByFuzz              bool              // Fuzz paths with a dictionary
	FuzzDictPath            string            // Path-fuzzing dictionary
	PathFromRobots          bool              // Parse the robots file to discover paths
	MaxTabsCount            int               // Maximum number of tabs to open, equal to the number of concurrent crawls
	ChromiumPath            string            // Path to the Chromium executable, for example `/home/zhusiyu1/chrome-linux/chrome`
	EventTriggerMode        string            // Event trigger mode: asynchronous or sequential
	EventTriggerInterval    time.Duration     // Interval between event triggers
	BeforeExitDelay         time.Duration     // Delay before exit to allow DOM rendering and XHR capture
	EncodeURLWithCharset    bool              // Encode URLs using the detected character set
	IgnoreKeywords          []string          // Keywords to ignore; matching requests are not crawled or sent
	Proxy                   string            // Request proxy
	CustomFormValues        map[string]string // Custom form values
	CustomFormKeywordValues map[string]string // Custom values for form keywords
}

type TaskConfigOptFunc func(*TaskConfig)

func NewTaskConfig(optFuncs ...TaskConfigOptFunc) *TaskConfig {
	conf := &TaskConfig{}
	for _, fn := range optFuncs {
		fn(conf)
	}
	return conf
}

func WithMaxCrawlCount(maxCrawlCount int) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.MaxCrawlCount == 0 {
			tc.MaxCrawlCount = maxCrawlCount
		}
	}
}

func WithFilterMode(gen string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.FilterMode == "" {
			tc.FilterMode = gen
		}
	}
}

func WithExtraHeaders(gen map[string]interface{}) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.ExtraHeaders == nil {
			tc.ExtraHeaders = gen
		}
	}
}

func WithExtraHeadersString(gen string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.ExtraHeadersString == "" {
			tc.ExtraHeadersString = gen
		}
	}
}

func WithAllDomainReturn(gen bool) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if !tc.AllDomainReturn {
			tc.AllDomainReturn = gen
		}
	}
}
func WithSubDomainReturn(gen bool) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if !tc.SubDomainReturn {
			tc.SubDomainReturn = gen
		}
	}
}

func WithNoHeadless(gen bool) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if !tc.NoHeadless {
			tc.NoHeadless = gen
		}
	}
}

func WithDomContentLoadedTimeout(gen time.Duration) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.DomContentLoadedTimeout == 0 {
			tc.DomContentLoadedTimeout = gen
		}
	}
}

func WithTabRunTimeout(gen time.Duration) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.TabRunTimeout == 0 {
			tc.TabRunTimeout = gen
		}
	}
}
func WithPathByFuzz(gen bool) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if !tc.PathByFuzz {
			tc.PathByFuzz = gen
		}
	}
}
func WithFuzzDictPath(gen string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.FuzzDictPath == "" {
			tc.FuzzDictPath = gen
		}
	}
}
func WithPathFromRobots(gen bool) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if !tc.PathFromRobots {
			tc.PathFromRobots = gen
		}
	}
}
func WithMaxTabsCount(gen int) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.MaxTabsCount == 0 {
			tc.MaxTabsCount = gen
		}
	}
}
func WithChromiumPath(gen string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.ChromiumPath == "" {
			tc.ChromiumPath = gen
		}
	}
}
func WithEventTriggerMode(gen string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.EventTriggerMode == "" {
			tc.EventTriggerMode = gen
		}
	}
}
func WithEventTriggerInterval(gen time.Duration) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.EventTriggerInterval == 0 {
			tc.EventTriggerInterval = gen
		}
	}
}
func WithBeforeExitDelay(gen time.Duration) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.BeforeExitDelay == 0 {
			tc.BeforeExitDelay = gen
		}
	}
}
func WithEncodeURLWithCharset(gen bool) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if !tc.EncodeURLWithCharset {
			tc.EncodeURLWithCharset = gen
		}
	}
}
func WithIgnoreKeywords(gen []string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.IgnoreKeywords == nil || len(tc.IgnoreKeywords) == 0 {
			tc.IgnoreKeywords = gen
		}
	}
}
func WithProxy(gen string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.Proxy == "" {
			tc.Proxy = gen
		}
	}
}
func WithCustomFormValues(gen map[string]string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.CustomFormValues == nil || len(tc.CustomFormValues) == 0 {
			tc.CustomFormValues = gen
		}
	}
}
func WithCustomFormKeywordValues(gen map[string]string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.CustomFormKeywordValues == nil || len(tc.CustomFormKeywordValues) == 0 {
			tc.CustomFormKeywordValues = gen
		}
	}
}
