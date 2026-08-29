package util

import (
	"fmt"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	systemNet "net"
	"strconv"
	"time"
)

// partition
type Part struct {
	Path        string  `json:"path"`
	FsType      string  `json:"fstype"`
	Total       float64 `json:"total"`
	Free        float64 `json:"free"`
	Used        float64 `json:"used"`
	UsedPercent int     `json:"usedPercent"`
}

// partition set
type Parts []Part

// CPU
type CpuSingle struct {
	Num     string `json:"num"`
	Percent int    `json:"percent"`
}

type CpuInfo struct {
	CpuAvg float64     `json:"cpuAvg"`
	CpuAll []CpuSingle `json:"cpuAll"`
}

const GB = 1024 * 1024 * 1024

func decimal(v string) float64 {
	value, _ := strconv.ParseFloat(v, 64)
	return value
}

// 1. host IP
func GetLocalIP() (ip string) {
	addresses, err := systemNet.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addresses {
		ipAddr, ok := addr.(*systemNet.IPNet)
		if !ok {
			continue
		}
		if ipAddr.IP.IsLoopback() {
			continue
		}
		if !ipAddr.IP.IsGlobalUnicast() {
			continue
		}
		return ipAddr.IP.String()
	}
	return ""
}

// 2. host info
func GetHostInfo() (result *host.InfoStat, err error) {
	result, err = host.Info()
	return result, err
}

// 3. disk info
func GetDiskInfo() (result Parts, err error) {
	parts, err := disk.Partitions(true)
	if err != nil {
		return result, err
	}
	for _, part := range parts {
		diskInfo, err := disk.Usage(part.Mountpoint)
		if err == nil {
			result = append(result, Part{
				Path:        diskInfo.Path,
				FsType:      diskInfo.Fstype,
				Total:       decimal(fmt.Sprintf("%.2f", float64(diskInfo.Total/GB))),
				Free:        decimal(fmt.Sprintf("%.2f", float64(diskInfo.Free/GB))),
				Used:        decimal(fmt.Sprintf("%.2f", float64(diskInfo.Used/GB))),
				UsedPercent: int(diskInfo.UsedPercent),
			})
		} else {
			return result, err
		}
	}
	return result, err
}

// 4. CPU usage
func GetCpuPercent() (result CpuInfo, err error) {
	infos, err := cpu.Percent(1*time.Second, true)
	if err != nil {
		return result, err
	}
	var total float64 = 0
	for index, value := range infos {
		result.CpuAll = append(result.CpuAll, CpuSingle{
			Num:     fmt.Sprintf("#%d", index+1),
			Percent: int(value),
		})
		total += value
	}
	result.CpuAvg = decimal(fmt.Sprintf("%.1f", total/float64(len(infos))))
	return result, err
}

// 5. memory info
func GetMemInfo() (float64, []map[string]interface{}) {
	info, err := mem.VirtualMemory()
	if err != nil {
		fmt.Println(err)
		return 0, nil
	}
	return decimal(fmt.Sprintf("%.1f", info.UsedPercent)), []map[string]interface{}{
		{"key": "Usage[%]", "value": decimal(fmt.Sprintf("%.1f", info.UsedPercent))},
		{"key": "Total[GB]", "value": int(info.Total / GB)},
		{"key": "Used[GB]", "value": int(info.Used / GB)},
		{"key": "Free[GB]", "value": int(info.Free / GB)},
	}
}

// 6. get network interface info
func GetNetInfo() (result []net.IOCountersStat, err error) {
	info, err := net.IOCounters(true)
	if err != nil {
		return result, err
	}
	return info, err
}

// 7. compute upload/download bandwidth
func GetNetSpeed() (speed map[string]map[string]uint64, err error) {
	speed = map[string]map[string]uint64{}
	info, err := net.IOCounters(true)
	if err != nil {
		return speed, err
	}
	for _, item := range info {
		if item.BytesSent != 0 {
			speed[item.Name] = map[string]uint64{
				"send": item.BytesSent,
				"recv": item.BytesRecv,
			}
		}
	}

	time.Sleep(1 * time.Second)

	info, err = net.IOCounters(true)
	if err != nil {
		return speed, err
	}
	for _, item := range info {
		if item.BytesSent != 0 {
			speed[item.Name] = map[string]uint64{
				"send": item.BytesSent - speed[item.Name]["send"],
				"recv": item.BytesRecv - speed[item.Name]["recv"],
			}
		}
	}
	return speed, nil
}
