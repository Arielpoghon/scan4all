# Best Practices
This document uses mac os as an example

## Persistent result storage
* 1、Please install docker first (installation steps omitted)
* 2、mkdir ~/MyWork;cd ~/MyWork
  * 2.1 config directory and related config files
  Download the release program and run it. The first run will not automatically generate the config directory and related config files. Alternatively:  
  git clone http://github.com/hktalent/scan4all
  
* 3、cd ~/MyWork/scan4all
* 4、Run the code below, which automatically pulls the docker image and starts the docker service on port 9200
```bash
docker run --restart=always --ulimit nofile=65536:65536 -p 9200:9200 -p 9300:9300 -d --name es -v $PWD/logs:/usr/share/elasticsearch/logs -v $PWD/config/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml -v $PWD/config/jvm.options:/usr/share/elasticsearch/config/jvm.options  -v $PWD/data:/usr/share/elasticsearch/data  hktalent/elasticsearch:7.16.2
```
* 5、Run the initialization index command
```
~/MyWork/scan4all/config/initEs.sh
```
## Enable storing results to ES
Modify config/config.json, set to true to enable storing results
```
"enableEsSv": true,
```
If your ES has a password set, please modify
config/nuclei_esConfig.yaml
password; otherwise the password settings inside are meaningless

### Configuration description
Full version, see:config/config.json
```json
{
  "CacheName": ".DbCache", // speed up, optimize, avoid duplicates, cache directory
  "autoRmCache": "true",   // program automatically deletes the cache; if you want to keep it to speed up the next scan of the same target, you can keep it
  //////////various customizable dictionaries that need no explanation, you can configure the same file start///////////////
  "ssh_username": "pkg/hydra/dicts/ssh_user.txt",
  "ssh_pswd": "pkg/hydra/dicts/ssh_pswd.txt",
  "ssh_default": "pkg/hydra/dicts/ssh_default.txt",
  "ftpusername": "pkg/hydra/dicts/ftp_user.txt",
  "ftp_pswd": "pkg/hydra/dicts/ftp_pswd.txt",
  "ftp_default": "pkg/hydra/dicts/ftp_default.txt",
  "rdpusername": "pkg/hydra/dicts/rdp_user.txt",
  "rdp_pswd": "pkg/hydra/dicts/rdp_pswd.txt",
  "rdp_default": "pkg/hydra/dicts/rdp_default.txt",
  "mongodbusername": "pkg/hydra/dicts/mongodb_user.txt",
  "mongodb_pswd": "pkg/hydra/dicts/mongodb_pswd.txt",
  "mongodb_default": "pkg/hydra/dicts/mongodb_default.txt",
  "mssqlusername": "pkg/hydra/dicts/mssql_user.txt",
  "mssql_pswd": "pkg/hydra/dicts/mssql_pswd.txt",
  "mssql_default": "pkg/hydra/dicts/mssql_default.txt",
  "mysqlusername": "pkg/hydra/dicts/mysql_user.txt",
  "mysql_pswd": "pkg/hydra/dicts/mysql_pswd.txt",
  "mysql_default": "pkg/hydra/dicts/mysql_default.txt",
  "oracleusername": "pkg/hydra/dicts/oracle_user.txt",
  "oracle_pswd": "pkg/hydra/dicts/oracle_pswd.txt",
  "oracle_default": "pkg/hydra/dicts/oracle_default.txt",
  "postgresqlusername": "pkg/hydra/dicts/postgresql_user.txt",
  "postgresql_pswd": "pkg/hydra/dicts/postgresql_pswd.txt",
  "postgresql_default": "pkg/hydra/dicts/postgresql_default.txt",
  "redisusername": "pkg/hydra/dicts/redis_user.txt",
  "redis_pswd": "pkg/hydra/dicts/redis_pswd.txt",
  "redis_default": "pkg/hydra/dicts/redis_default.txt",
  "smbusername": "pkg/hydra/dicts/smb_user.txt",
  "smb_pswd": "pkg/hydra/dicts/smb_pswd.txt",
  "smb_default": "pkg/hydra/dicts/smb_default.txt",
  "telnetusername": "pkg/hydra/dicts/telnet_user.txt",
  "telnet_pswd": "pkg/hydra/dicts/telnet_pswd.txt",
  "telnet_default": "pkg/hydra/dicts/telnet_default.txt",
  "tomcatuserpass": "brute/dicts/tomcatuserpass.txt",
  "jbossuserpass": "brute/dicts/jbossuserpass.txt",
  "weblogicuserpass": "brute/dicts/weblogicuserpass.txt",
  "filedic": "brute/dicts/filedic.txt",
  "top100pass": "brute/dicts/top100pass.txt",
  "bakSuffix": "brute/dicts/bakSuffix.txt",
  "fuzzct": "brute/dicts/fuzzContentType1.txt",
  "fuzz404": "brute/dicts/fuzz404.txt",
  "page404Content1": "brute/dicts/page404Content.txt",
  "eHoleFinger": "pkg/fingerprint/dicts/eHoleFinger.json",
  "localFinger": "pkg/fingerprint/dicts/localFinger.json",
  "HydraUser": "",
  "HydraPass": "",
  "es_user": "pkg/hydra/dicts/es_user.txt",
  "es_pswd": "pkg/hydra/dicts/es_pswd.txt",
  "es_default": "pkg/hydra/dicts/es_default.txt",
  "snmp_user": "pkg/hydra/dicts/snmp_user.txt",
  "snmp_pswd": "pkg/hydra/dicts/snmp_pswd.txt",
  "snmp_default": "pkg/hydra/dicts/snmp_default.txt",
  //////////various customizable dictionaries that need no explanation, you can configure the same file end///////////////
  // after naabu scans the ports, it automatically calls nmap to run fingerprint detection, then automatically calls weak password detection; on windows it automatically adds .exe, you don't need to worry
  "nmap": "nmap -n --unique --resolve-all -Pn --min-hostgroup 64 --max-retries 0 --host-timeout 10m --script-timeout 3m -oX {filename} --version-intensity 9 --min-rate 10000 -T4 ",
  "UrlPrecise": true, // if the file list passed with -l contains http[s] context, precise scanning is enabled by default
  "ParseSSl": false,  // off by default for HW marking; recommended to set true for internet bug bounty targets
  "EnableSubfinder": false, // certificate subdomain enumeration in ssl is off by default; recommended to set true for internet bug bounty targets
  "naabu_dns": {},  // naabu tool dns configuration
  "naabu": {"TopPorts": "1000","ScanAllIPS": true}, // naabu configuration
  "nuclei": {}, // nuclei configuration, e.g. threads etc
  "httpx": {}   // httpx configuration,
  "enableEsSv": true,        // enable sending results to es
  "esthread": 8 // number of threads writing results to Elasticsearch
  "esUrl": "http://127.0.0.1:9200/%s_index/_doc/%s" // Elasticsearch szUrl
}
```

## Running scan tasks
Generally when not batch scanning, unless you want to see intermediate results, it is not recommended to enable -v -debug
```bash
enableEsSv=true ./scan4all -l list.txt
enableEsSv=true ./scan4all -host target.com
```

## Viewing results
See config/initEs.sh for more index types
```
http://127.0.0.1:9200/nmap_index/_doc/156.238.15.99
http://127.0.0.1:9200/nuclei_index/_doc/_search?q=host:%20in%20%221.2.215.18:1432%22
http://127.0.0.1:9200/naabu_index/_doc/_search
http://127.0.0.1:9200/vscan_index/_doc/_search
http://127.0.0.1:9200/hydra_index/_doc/_search
http://127.0.0.1:9200/httpx_index/_doc/_search
http://127.0.0.1:9200/httpx_index/_doc/_search?q=szUrl:in%20%221.28.15.18%22

```
