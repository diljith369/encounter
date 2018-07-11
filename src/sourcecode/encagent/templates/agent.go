package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"github.com/PuerkitoBio/goquery"
)

//ENCSERVER connection string to the encounter server
const ENCSERVER = "IP:PORT"

func checkerr(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func httpconnect() {

	//	var osshell string
	/*trp := *&http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}*/
	//client := &http.Client{Transport: trp}

	//client.PostForm(encserver, url.Values{"cmd": {commands[i]}, "cmdres": {res}, "invcmd": {"fromagent"}})
	client := &http.Client{}

	for {
		resp, err := client.Get(ENCSERVER)
		checkerr(err)
		doc, err := goquery.NewDocumentFromResponse(resp)
		checkerr(err)
		cnt, _ := doc.Find("form input").Attr("value")
		huntid := strings.TrimSpace(cnt)
		var res string
		if huntid == "xit" {
			res = "Agent terminated"
			client.PostForm(ENCSERVER, url.Values{"cmdres": {res}, "huntid": {huntid}})
			os.Exit(0)
		} else if huntid == "1" {
			fmt.Println("Hunting for Autorun...")
			command := `C:\Windows\Temp\enc.exe`
			err := DownloadFile(command, ENCSERVER+`/bin/selected/autorunsc.exe`)
			checkerr(err)
			args := []string{`-vt`, `/accepteula`}
			res = runexehunt(command, args)
			client.PostForm(ENCSERVER, url.Values{"cmdres": {res}, "huntid": {huntid}})
			os.Remove(command)

		} else if huntid == "2" {
			fmt.Println("Hunting for Network data...")
			res = executehunt(`netstat -bon`)
			client.PostForm(ENCSERVER, url.Values{"cmdres": {res}, "huntid": {huntid}})

		} else if huntid == "3" {
			fmt.Println("Hunting for ScheduledTasks...")
			res = executehunt(`schtasks /query`)
			client.PostForm(ENCSERVER, url.Values{"cmdres": {res}, "huntid": {huntid}})
		} else if huntid == "4" {
			fmt.Println("Hunting for Tasklists and Services...")
			res = executehunt(`TASKLIST /SVC`)
			client.PostForm(ENCSERVER, url.Values{"cmdres": {res}, "huntid": {huntid}})
		} else if huntid == "5" {
			fmt.Println("Hunting for DNS Cache...")
			res = executehunt(`ipconfig /displaydns`)
			client.PostForm(ENCSERVER, url.Values{"cmdres": {res}, "huntid": {huntid}})
		} else if huntid == "6" {
			fmt.Println("Hunting for LoggonSessions...")
			command := `C:\Windows\Temp\enc.exe`
			err := DownloadFile(command, ENCSERVER+`/bin/selected/logonsessions.exe`)
			checkerr(err)
			args := []string{`/accepteula`}
			res = runexehunt(command, args)
			client.PostForm(ENCSERVER, url.Values{"cmdres": {res}, "huntid": {huntid}})
			os.Remove(command)

		}

	}

}

func runexehunt(command string, args []string) string {

	//execcmd := exec.Command("certutil", "-hashfile", fpath, "md5")
	//fmt.Println("executing command", command)
	execcmd := exec.Command(command, args...)
	if runtime.GOOS == "windows" {
		execcmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	}

	out, _ := execcmd.Output()
	//fmt.Println(string(out))
	return string(out)

}

func executehunt(command string) string {
	//fmt.Println(command)
	osshellargs := []string{"/C", command}
	var osshell string
	if runtime.GOOS == "windows" {
		osshell = "cmd"
	} else {
		osshell = "/bin/sh"
		osshellargs = []string{"-c", command}
	}
	execcmd := exec.Command(osshell, osshellargs...)
	if runtime.GOOS == "windows" {
		execcmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	}

	out, _ := execcmd.Output()
	return (string(out))
}

func DownloadFile(filepath, url string) error {

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	//fmt.Println(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func main() {

	httpconnect()
}
