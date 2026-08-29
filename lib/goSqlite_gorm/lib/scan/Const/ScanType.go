package Const

// This covers scan task states, which are expressed as a set of statuses
// Once defined and data has been produced, never add new types in the middle; append them only at the end
const (
	ScanType_SSLInfo         = int64(1 << iota) // 01- SSL info analysis; collects domain info, then proceeds to the next step
	ScanType_SubDomain                          // 02- subdomain brute force; new domains return to: 1 <-- -> 2, for deduplication
	ScanType_MergeIps                           // 03- default auto-merge ips, records the mapping between ip and domain; when sending payloads consider: same ip different domains, the same payload is sent separately. Merge the ips of several domains of the same target to avoid duplicates during scanning
	ScanType_Pswd4hydra                         // 04- password cracking, which implicitly includes: port scan (05-masscan + 06-nmap)
	ScanType_Masscan                            // 05- fast port scan on the merged ips
	ScanType_Nmap                               // 06- precise port fingerprinting, excluding the fingerprints already identified by masscan
	ScanType_IpInfo                             // 07- get ip info
	ScanType_GoPoc                              // 08- go-poc detection, which implicitly includes: port scan (05-masscan + 06-nmap)
	ScanType_PortsWeb                           // 09- web port identification using Naabu; detect https, identify alive web ports, then proceed to the next step
	ScanType_WebFingerprints                    // 10- web fingerprinting; detect honeypots and flag them
	ScanType_WebDetectWaf                       // 11- detect WAF
	ScanType_WebScrapy                          // 12- crawler analysis; form detection, field name detection, form action extraction
	ScanType_WebInfo                            // 13- server, x-powered-by, x***; url, ip, and other sensitive info (name, phone, address, ID card)
	ScanType_WebVulsScan                        // 14- nuclei
	ScanType_WebDirScan                         // 14- directory brute force using Gobuster
	ScanType_Naabu                              // 15- naabu
	ScanType_Httpx                              // 16- httpx
	ScanType_DNSx                               // 17- DNSX
	ScanType_SaveEs                             // 18- Save Es
)

const (
// Task type
//TaskType_Subdomain   uint64 = 1 << iota // task type: subdomain
//TaskType_PortScan    uint64 = 1 << iota // task type: port scan
//TaskType_UrlScan     uint64 = 1 << iota // task type: url scan
//TaskType_Fingerprint uint64 = 1 << iota // task type: fingerprinting
//TaskType_VulsScan    uint64 = 1 << iota // task type: vulnerability scan
//
//// Task status
//Task_Status_Pending     uint64 = 1 << iota // task status: pending
//Task_Status_InExecution uint64 = 1 << iota // task status: running
//Task_Status_Completed   uint64 = 1 << iota // task status: completed
//
//// Subdomain enumeration
//SubDomains_Amass     uint64 = 1 << iota // subdomain: amass 7.2k
//SubDomains_Subfinder uint64 = 1 << iota // subdomain: Subfinder 5.6k,https://github.com/projectdiscovery/subfinder
//SubDomains_Sublist3r uint64 = 1 << iota // subdomain: Sublist3r 7.1k
//SubDomains_Gobuster  uint64 = 1 << iota // service/directory discovery: gobuster 6k,https://github.com/OJ/gobuster// gobuster dns -d google.com -w ~/wordlists/subdomains.txt
//
//// Port scan
//Ip2Ports_VulsCheckFlag_Masscan  uint64 = 1 << iota // port scan tool: masscan 19.1k, https://github.com/robertdavidgraham/masscan
//Ip2Ports_VulsCheckFlag_RustScan uint64 = 1 << iota // port scan tool: RustScan 6.3k,https://github.com/RustScan/RustScan
//Ip2Ports_VulsCheckFlag_Nmap     uint64 = 1 << iota // port scan tool: Nmap, https://github.com/vulnersCom/nmap-vulners
//
//// Fingerprinting
//ScanType_Fingerprint_Wappalyzer uint64 = 1 << iota // fingerprint: wappalyzer 7.5k, https://github.com/wappalyzer/wappalyzer
//ScanType_Fingerprint_WhatWeb    uint64 = 1 << iota // fingerprint: WhatWeb 3.8k,https://github.com/urbanadventurer/WhatWeb
//ScanType_Fingerprint_EHole      uint64 = 1 << iota // fingerprint: EHole 1.4k,https://github.com/EdgeSecurityTeam/EHole
//
//// Service/directory discovery
//ScanType_Discovery_Gobuster uint64 = 1 << iota // service/directory discovery: gobuster 6k,https://github.com/OJ/gobuster
//ScanType_Discovery_Fscan    uint64 = 1 << iota // service/directory discovery: fscan 3.6k,https://github.com/shadow1ng/fscan
//ScanType_Discovery_Httpx    uint64 = 1 << iota // service/directory discovery: httpx 3.2k,https://github.com/projectdiscovery/httpx
//ScanType_Discovery_Naabu    uint64 = 1 << iota // service/directory discovery: naabu 2.1k,https://github.com/projectdiscovery/naabu
////  Others
//// https://github.com/NVIDIA/NeMo
//// https://github.com/veo/vscan
//
//// Vulnerability scan
//ScanType_Nuclei uint64 = 1 << iota // vulnerability scan: nuclei 8.4k,https://github.com/projectdiscovery/nuclei
)
