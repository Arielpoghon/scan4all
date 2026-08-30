# Custom Scanner

## Adding POC via golang files:

1. Check or add fingerprint in ./pkg/fingerprint/localFingerData.go

2. Write a golang POC file, place it in the pocs_go folder, specify an entry function with defined input/output, and add the detection item in ./pocs_go/go_poc_check.go (during POC writing you can use the function pkg.HttpRequset from ./pkg/util.go)

For example:

CVE_2017_12615 POC:
```
func CVE_2017_12615(szUrl string) bool {
	if req, err := pkg.HttpRequset(szUrl+"/vtset.txt", "PUT", "test", false, nil); err == nil {
		if req.StatusCode == 204 || req.StatusCode == 201 {
			pkg.POClog(fmt.Sprintf("Found vuln Tomcat CVE_2017_12615|--\"%s/vtest.txt\"\n", szUrl))
			return true
		}
	}
	return false
}
```

CVE_2017_12615 POC Add detection item in ./pocs_go/go_poc_check.go:
```
case "Apache Tomcat":
   if tomcat.CVE_2017_12615(URL) {
		technologies = append(technologies, "exp-Tomcat|CVE_2017_12615")
    }
```
## Adding POC via yml files:
1. Check or add fingerprint in ./pkg/fingerprint/localFingerData.go

2. Refer to the writing style of xrayV2 yml, write it and place it in ./pocs_yml/ymlFiles/. The filename must start with the fingerprint name followed by a dash (e.g. thinkphp-cvexxxxxxxxx-aaa.yml)

## Background weak password scanning, middleware weak password scanning dictionaries

The background weak password detection has two built-in accounts admin/test, with the top100 password list. If the homepage login is successfully identified, it will be marked as LoginPage; if it is recognized as potentially a background login page, it will be marked as AdminLoginPage. Both will attempt to construct a login request and automatically detect weak passwords.

For example:

`http://127.0.0.1:8080 [302,200] [Login - Backend] [exp-shiro|key:Z3VucwAAAAAAAAAAAAAAAA==,Java,LoginPage,brute-admin|admin:123456] [http://127.0.0.1:8080/login]`

Includes weak password detection modules
1. Smart weak password detection for backgrounds that do not use captchas or frontend frameworks such as vue
2. basic weak password detection
3. tomcat weak password detection
4. weblogic weak password detection
5. jboss weak password detection

The dictionaries are built in ./brute/dicts/ and can be modified as needed


## Sensitive file scanning dictionary

Scans sensitive files such as backups, swagger-ui, spring actuator, upload interfaces, test files, etc.

The dictionaries are built in ./brute/dicts/ and can be modified as needed
