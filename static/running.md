# Usage Introduction

## Input

```shell    
scan4all -host 127.0.0.1
```
Will scan common http ports on 127.0.0.1, and after the port scan detects the port addresses

```shell    
scan4all -host http://127.0.0.1:7001
```
Will not perform a port scan on 127.0.0.1, but directly detect the http://127.0.0.1:7001 address

```shell    
scan4all -host 192.168.1.1/24
```
Will perform a port scan on the C class segment 192.168.1.1/24, and after the port scan detects the port addresses

```shell    
scan4all -l ips.txt
```
Will detect the ip/domain/C segment/url addresses in ips.txt line by line (if there are url addresses, port scanning will not be performed)


```shell    
echo 127.0.0.1|scan4all
```
You can use a pipeline for input and scanning

## Choosing the scan method

```shell    
scan4all -host 127.0.0.1 -s SYN
```
SYN scanning is faster but requires root privileges (without this parameter, SYN scanning is performed by default)


## Port selection

```shell    
scan4all -host 127.0.0.1 -p 7001,7002
```
Will detect the 7001 and 7002 ports on 127.0.0.1

```shell    
scan4all -host 127.0.0.1 -top-Ports 1000
scan4all -host 127.0.0.1 -top-Ports http
```
Will perform a NmapTop1000 port scan on 127.0.0.1 (without this parameter, common http port scanning is performed by default)




## Using the DNSLOG feature

```shell    
scan4all -host 127.0.0.1 -ceyeapi xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -ceyedomain xxxxxx.ceye.io
```
Using the DNSLOG feature allows better POC detection; some POCs require the DNSLOG feature for detection

## Output/Export feature

```shell    
scan4all -host 127.0.0.1 -json -o 1.json
```
Outputs results in json format and writes them to the 1.json file. Port scan results are saved in port.1.json


```shell    
scan4all -host 127.0.0.1 -csv -o 1.csv
```
Outputs results in csv format and writes them to the 1.csv file. Port scan results are saved in port.1.csv


## Only perform port scanning and fingerprint identification, no POC detection

```shell
scan4all -host 127.0.0.1 -np
```

## Disable color output

```shell    
scan4all -host 127.0.0.1 -no-color
```

## Set thread count and thread rate

```shell    
scan4all -host 127.0.0.1 -c 25 -rate 1000
```

## Proxy feature

```shell    
scan4all -host 127.0.0.1 -proxy socks5://127.0.0.1:1080
```

## Exclude CDN

```shell    
scan4all -host www.google.com -ec
```

## Directly use nmap scan results, skip internal port scanning

```shell    
scan4all -l nmapResult.xml -v
```

## Other

See [Usage](/static/usage.md)
