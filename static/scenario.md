
# Scenarios


## External network scenario

You need to collect the target's external network asset information yourself, including the asset's domains, C segments, related IPs, etc. Aggregate the assets, deduplicate, and save them locally, then use scan4all for rapid vulnerability scanning.

```shell
scan4all -l input.txt -ceyeapi xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -ceyedomain xxxxxx.ceye.io -csv -o output.csv
```
input.txt can contain multiple formats: URL, domain, C segment, IP (URL addresses will not undergo port scanning)

## Internal network scenario

Directly using scan4all to scan B segments is very slow (large amount of port scanning). It is recommended to first use [fscan](https://github.com/shadow1ng/fscan) to probe for live IPs on the internal B segment, then import the list of live IPs into scan4all for scanning

```shell
scan4all -l ips.txt -ceyeapi xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -ceyedomain xxxxxx.ceye.io -csv -o output.csv
```

## WAF scenario

If you encounter a WAF blocking your IP, it is recommended to first perform fingerprint identification on the assets, then perform POC detection on the url addresses.
This way you can at least obtain the asset's fingerprint list, rather than having no results at all

1.
```shell
scan4all -l input.txt -np -csv -o output.csv
```

2.
```shell
scan4all -l urls.txt -ceyeapi xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -ceyedomain xxxxxx.ceye.io -csv -o poc_output.csv
```
