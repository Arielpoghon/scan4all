package go_utils

// These constants represent states in a scan task.
// Once defined and data has been generated, never insert a type in the middle; add new types only at the end.
const (
	ScanType_SSLInfo         = uint64(1 << iota) // 01- Analyze SSL information, collect domain information, and continue to the next stage
	ScanType_SubDomain                           // 02- Brute-force subdomains; new domains return to: 1 <-- -> 2 for deduplication
	ScanType_MergeIps                            // 03- Automatically merge IPs by default and record IP-to-domain relationships. When sending payloads, send the same payload separately for the same IP with different domains; merge IPs for the same target across multiple domains to avoid duplicate scans
	ScanType_WeakPassword                        // 04- Crack passwords; includes port scanning (05-masscan + 06-nmap)
	ScanType_Masscan                             // 05- Perform a fast port scan of merged IPs; port scanning tool: masscan 19.1k, https://github.com/robertdavidgraham/masscan
	ScanType_Nmap                                // 06- Precise port fingerprints, excluding fingerprints already identified by masscan; port scanning tool: Nmap, https://github.com/vulnersCom/nmap-vulners
	ScanType_IpInfo                              // 07- Get IP information
	ScanType_GoPoc                               // 08- Run go-poc detection; includes port scanning (05-masscan + 06-nmap)
	ScanType_PortsWeb                            // 09- Identify web ports with Naabu, detect HTTPS and live web ports, then continue to the next stage
	ScanType_WebFingerprints                     // 10- Identify web fingerprints and detect and label honeypots
	ScanType_WebDetectWaf                        // 11- Detect the WAF
	ScanType_WebScrapy                           // 12- Crawler analysis, form identification, field-name recognition, and form action extraction;
	ScanType_WebInfo                             // 13- server, x-powerby, x***, URL, IP, and other sensitive information (name, phone number, address, ID number)
	ScanType_WebVulsScan                         // 14- Includes nuclei
	ScanType_WebDirScan                          // 14- Directory brute force with Gobuster
	ScanType_Naabu                               // 15- naabu; service and directory discovery: naabu 2.1k,https://github.com/projectdiscovery/naabu
	ScanType_Httpx                               // 16- httpx; service and directory discovery: httpx 3.2k,https://github.com/projectdiscovery/httpx
	ScanType_DNSx                                // 17- DNSX
	ScanType_SaveEs                              // 18- Save Es
	ScanType_Jaeles                              // 19 - jaeles
	ScanType_Uncover                             // Uncover
	ScanType_Ffuf                                // ffuf
	ScanType_Amass                               // amass; subdomains: amass 7.2k
	ScanType_Subfinder                           // subfinder; subdomains: Subfinder 5.6k,https://github.com/projectdiscovery/subfinder
	ScanType_Shuffledns                          // shuffledns
	ScanType_Tlsx                                // tlsx
	ScanType_Katana                              // katana
	ScanType_Nuclei                              // nuclei; vulnerability scanning: nuclei 8.4k，https://github.com/projectdiscovery/nuclei
	ScanType_Gobuster                            // Gobuster; service and directory discovery: gobuster 6k,https://github.com/OJ/gobuster// gobuster dns -d google.com -w ~/wordlists/subdomains.txt
	ScanType_RustScan                            // Port scanning tool: RustScan 6.3k,https://github.com/RustScan/RustScan
	ScanType_Wappalyzer                          // Fingerprint: wappalyzer 7.5k, https://github.com/wappalyzer/wappalyzer
	ScanType_Scan4all                            // all scan
)

const (
	ScanType_WebFinger = ScanType_WebFingerprints | ScanType_Wappalyzer
	ScanType_Ips       = ScanType_SSLInfo | ScanType_Tlsx | ScanType_Masscan | ScanType_Nmap | ScanType_IpInfo | ScanType_Uncover | ScanType_GoPoc
	ScanType_Webs      = ScanType_SSLInfo | ScanType_Tlsx | ScanType_GoPoc | ScanType_WebFingerprints | ScanType_WebDetectWaf | ScanType_WebVulsScan | ScanType_Nuclei | ScanType_Gobuster | ScanType_Uncover | ScanType_Httpx | ScanType_WebDirScan
)

const (
// Task type
//TaskType_Subdomain   = uint64(1 << iota) // Task type: subdomain
//TaskType_PortScan                        // Task type: port scanning
//TaskType_UrlScan                         // Task type: URL scanning
//TaskType_Fingerprint                     // Task type: fingerprint identification
//TaskType_VulsScan                        // Task type: vulnerability scanning
//
//// Task status
//Task_Status_Pending     // Task status: pending
//Task_Status_InExecution // Task status: running
//Task_Status_Completed   // Task status: completed
//
//// Subdomain enumeration
//SubDomains_Sublist3r // Subdomain: Sublist3r 7.1k
//
//// Fingerprint
//ScanType_Fingerprint_Wappalyzer // Fingerprint: wappalyzer 7.5k, https://github.com/wappalyzer/wappalyzer
//ScanType_Fingerprint_WhatWeb    // Fingerprint: WhatWeb 3.8k,https://github.com/urbanadventurer/WhatWeb
//
//// Service and directory discovery
//ScanType_Discovery_Fscan // Service and directory discovery: fscan 3.6k,https://github.com/shadow1ng/fscan
////  Others
//// https://github.com/NVIDIA/NeMo
//// https://github.com/veo/vscan

)

// GetTypeName returns the name of a scan type.
func GetTypeName(n uint64) string {
	if s, ok := ScanType2Str[n]; ok {
		return s
	}
	return string(Scan4all)
}

func GetTypeNames(n uint64) []string {
	var a []string
	for k, v := range ScanType2Str {
		if n&k == k {
			a = append(a, v)
		}
	}
	return a
}

// GetType4Name gets the types in a, merges them into nSrc, and returns the result.
func GetType4Name(nSrc uint64, a ...string) uint64 {
	for _, x := range a {
		if t, ok := ScanType4Int[x]; ok {
			nSrc = nSrc | t
		}
	}
	return nSrc
}

var ScanType4Int = map[string]uint64{}

// Initialize the scan type lookup table.
func init() {
	RegInitFunc(func() {
		for k, v := range ScanType2Str {
			ScanType4Int[v] = k
		}
	})
}

var ScanType2Str = map[uint64]string{
	ScanType_SSLInfo:         "sslInfo",         // 01- Analyze SSL information, collect domain information, and continue to the next stage
	ScanType_SubDomain:       "subdomain",       // 02- Brute-force subdomains; new domains return to: 1 <-- -> 2 for deduplication
	ScanType_MergeIps:        "mergeIps",        // 03- Automatically merge IPs by default and record IP-to-domain relationships. When sending payloads, send the same payload separately for the same IP with different domains; merge IPs for the same target across multiple domains to avoid duplicate scans
	ScanType_WeakPassword:    "weakPassword",    // 04- Crack passwords; includes port scanning (05-masscan + 06-nmap)
	ScanType_Masscan:         "masscan",         // 05- Perform a fast port scan of merged IPs
	ScanType_Nmap:            "nmap",            // 06- Precise port fingerprints, excluding fingerprints already identified by masscan
	ScanType_IpInfo:          "ipInfo",          // 07- Get IP information
	ScanType_GoPoc:           "goPoc",           // 08- Run go-poc detection; includes port scanning (05-masscan + 06-nmap)
	ScanType_PortsWeb:        "portsWeb",        // 09- Identify web ports with Naabu, detect HTTPS and live web ports, then continue to the next stage
	ScanType_WebFingerprints: "webFingerprints", // 10- Identify web fingerprints and detect and label honeypots
	ScanType_WebDetectWaf:    "webDetectWaf",    // 11- Detect the WAF
	ScanType_WebScrapy:       "webScrapy",       // 12- Crawler analysis, form identification, field-name recognition, and form action extraction;
	ScanType_WebInfo:         "webInfo",         // 13- server, x-powerby, x***, URL, IP, and other sensitive information (name, phone number, address, ID number)
	ScanType_WebVulsScan:     "webVulsScan",     // 14- Includes nuclei
	ScanType_WebDirScan:      "webDirScan",      // 14- Directory brute force with Gobuster
	ScanType_Naabu:           "naabu",           // 15- naabu
	ScanType_Httpx:           "httpx",           // 16- httpx
	ScanType_DNSx:            "dnsx",            // 17- DNSX
	ScanType_SaveEs:          "saveEs",          // 18- Save Es
	ScanType_Jaeles:          "jaeles",          // 19 - jaeles
	ScanType_Uncover:         "uncover",         // Uncover
	ScanType_Ffuf:            "ffuf",            // ffuf
	ScanType_Amass:           "amass",           // amass
	ScanType_Subfinder:       "subfinder",       // subfinder
	ScanType_Shuffledns:      "shuffledns",      // shuffledns
	ScanType_Tlsx:            "tlsx",            // tlsx
	ScanType_Katana:          "katana",          // katana
	ScanType_Nuclei:          "nuclei",          // nuclei
	ScanType_Gobuster:        "gobuster",        // Gobuster
	ScanType_RustScan:        "rustscan",        //rustscan
	ScanType_Wappalyzer:      "wappalyzer",      // Wappalyzer; included in httpx
	ScanType_Scan4all:        "scan4all",        // all scan
}

// Target4Chan represents a scan target for channel use; it is not persisted.
type Target4Chan struct {
	TaskId     string `json:"task_id"`     // Task ID
	ScanWeb    string `json:"scan_web"`    // Base64-decoded value
	ScanType   uint64 `json:"scan_type"`   // Scan type; multiple ScanType values may be combined
	ScanConfig string `json:"scan_config"` // Detailed configuration for this task as a JSON-formatted string
}

// EventData contains event data.
type EventData struct {
	EventType uint64        // Type: masscan, nmap
	EventData []interface{} // func, parms
	Task      *Target4Chan  // Current task data
	//Ips            []string                                         // IPs associated with the current task
	//SubDomains2Ips *map[string]map[string]map[int]map[string]string // All subdomains -> IP -> port -> port information
}
