package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/fatih/color"
	"github.com/gorilla/mux"
)

type EncCommand struct {
	Command    string
	Commandres string
	HuntId     string
}

type TaskList struct {
	ImageName   string
	PID         string
	ServiceName string
}
type ScheduleTask struct {
	TaskName    string
	NextRunTime string
	Status      string
}
type DnsCache struct {
	RecordName  string
	RecordType  string
	TimeToLive  string
	DataLength  string
	Section     string
	RecordType2 string
	MalwLink    string
}

type AutoRun struct {
	Regkey      string
	AppName     string
	ExecArgs    string
	Description string
	Signer      string
	Version     string
	Commandline string
	Time        string
	VtDetection string
	VtPermalink string
}
type NetWorkBinary struct {
	Protocol        string
	LocalIP         string
	LocalPort       string
	RemoteIP        string
	RemotePort      string
	ConnectionState string
	PID             string
	ExeName         string
	MalwLink        string
}

type LoginSession struct {
	Logonsession string
	UserName     string
	AuthPackage  string
	LogonType    string
	Session      string
	Sid          string
	LogonTime    string
	LogonServer  string
	DNSDomain    string
	UPN          string
}

var Loginval LoginSession
var Loginvals []LoginSession

var enccmdtopost EncCommand
var enctemplate, networkreport, autorunreport, schtasksreport, tasklistandservices, dnscache, logonsession *template.Template
var AutoRunVals []AutoRun
var autoRunval AutoRun
var NetWorkBinaryVals []NetWorkBinary
var networkbinaryval NetWorkBinary
var ScheduleTaskVal ScheduleTask
var ScheduleTaskVals []ScheduleTask
var TaskListVal TaskList
var TaskListVals []TaskList
var Dnsval DnsCache
var Dnsvals []DnsCache

func checkerr(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func init() {
	enccmdtopost = EncCommand{}
	enctemplate = template.Must(template.ParseFiles("templates/encounter.html"))
	networkreport = template.Must(template.ParseFiles("templates/network.html"))
	autorunreport = template.Must(template.ParseFiles("templates/autorun.html"))
	schtasksreport = template.Must(template.ParseFiles("templates/schtasks.html"))
	tasklistandservices = template.Must(template.ParseFiles("templates/tasklist.html"))
	dnscache = template.Must(template.ParseFiles("templates/dnscache.html"))
	logonsession = template.Must(template.ParseFiles("templates/loggon.html"))

	AutoRunVals = []AutoRun{}
	NetWorkBinaryVals = []NetWorkBinary{}
	ScheduleTaskVals = []ScheduleTask{}
	TaskListVals = []TaskList{}
	Dnsvals = []DnsCache{}
	Loginvals = []LoginSession{}

}

func parselogonsessions(rows string) {
	line := strings.Split(rows, "\n")
	fmt.Println(len(line))
	Loginval = LoginSession{}

	var alllines []string

	for j := range line {
		linesplit := strings.Split(line[j], ":")
		if len(linesplit) > 1 {
			alllines = append(alllines, line[j])
		}
	}
	fmt.Println(len(alllines))

	i := 0
	for {
		if i < len(alllines) {
			logonsession := alllines[i][20 : len(alllines[i])-2]

			Loginval.Logonsession = logonsession
			i = i + 1
			Loginval.UserName = strings.Split(alllines[i], ":")[1]
			i = i + 1
			Loginval.AuthPackage = strings.Split(alllines[i], ":")[1]
			i = i + 1
			Loginval.LogonType = strings.Split(alllines[i], ":")[1]
			i = i + 1
			Loginval.Session = strings.Split(alllines[i], ":")[1]
			i = i + 1
			Loginval.Sid = strings.Split(alllines[i], ":")[1]
			i = i + 1
			Loginval.LogonTime = strings.Split(alllines[i], ":")[1]
			i = i + 1
			Loginval.LogonServer = strings.Split(alllines[i], ":")[1]
			i = i + 1
			Loginval.DNSDomain = strings.Split(alllines[i], ":")[1]
			i = i + 1
			Loginval.UPN = strings.Split(alllines[i], ":")[1]
			i = i + 1
			if i%10 == 0 {
				Loginvals = append(Loginvals, Loginval)
				Loginval = LoginSession{}
			}
		} else {
			break
		}
	}
	/*for x := range Loginvals {
		fmt.Println("Logonsession", Loginvals[x].Logonsession)
		fmt.Println("LogonServer", Loginvals[x].LogonServer)

		fmt.Println("LogonTime", Loginvals[x].LogonTime)
		fmt.Println("LogonType", Loginvals[x].LogonType)
		fmt.Println(Loginvals[x].AuthPackage)
		fmt.Println(Loginvals[x].DNSDomain)
		fmt.Println(Loginvals[x].Session)
		fmt.Println(Loginvals[x].Sid)

		fmt.Println(Loginvals[x].UserName)

	}*/
}

func parsescheduletasks(result string) {
	ScheduleTaskVals = ScheduleTaskVals[:0]
	//var foldername string
	rows := strings.Split(result, "\n")
	//fmt.Println(len(rows))
	for i := 2; i < len(rows); i++ {

		if !strings.HasPrefix(rows[i], "Folder") && !strings.HasPrefix(rows[i], "=") && !strings.HasPrefix(rows[i], "TaskName") {
			nullremovedrow := removenullfromstring(rows[i])
			nullremovedrow = strings.Replace(nullremovedrow, `\r\n`, ``, -1)
			if strings.TrimSpace(nullremovedrow) != "" {
				ScheduleTaskVal = scheduletaskssplitter(rows[i])
				/*if strings.TrimSpace(foldername) != "" {
					ScheduleTaskVal.TaskName = "[" + foldername + "] " + ScheduleTaskVal.TaskName
				}*/
				if strings.TrimSpace(ScheduleTaskVal.TaskName) != "" {
					ScheduleTaskVals = append(ScheduleTaskVals, ScheduleTaskVal)
				}
			}

		}
	}

}

func scheduletaskssplitter(row string) ScheduleTask {

	var taskname = []string{}
	var nextruntme = []string{}
	var status = []string{}
	lastindex := 0
	redt := regexp.MustCompile(`\d{2}-\d{2}-\d{4}`)
	dt := redt.FindString(row)
	ScheduleTaskVal = ScheduleTask{}
	if strings.TrimSpace(dt) == "" {
		vals := strings.Split(row, `N/A`)
		if len(vals) > 1 {
			ScheduleTaskVal.TaskName = strings.TrimSpace(vals[0])
			ScheduleTaskVal.Status = strings.TrimSpace(vals[1])
			ScheduleTaskVal.NextRunTime = `N/A`
		} /*else {
			ScheduleTaskVal.TaskName = row
			ScheduleTaskVal.Status = ` `
			ScheduleTaskVal.NextRunTime = ` `
		}*/

	} else {
		index := strings.Index(row, dt)
		for i := 0; i < index; i++ {
			taskname = append(taskname, string(row[i]))
			lastindex = i
		}
		ScheduleTaskVal.TaskName = strings.TrimSpace(strings.Join(taskname, ""))
		for i := index; i < index+19; i++ {
			nextruntme = append(nextruntme, string(row[i]))
			lastindex = i
		}
		ScheduleTaskVal.NextRunTime = strings.TrimSpace(strings.Join(nextruntme, ""))

		for i := lastindex + 1; i < len(row); i++ {
			status = append(status, string(row[i]))
		}

		ScheduleTaskVal.Status = strings.TrimSpace(strings.Join(status, ""))
	}

	return ScheduleTaskVal

}

func parsenetstat(netstatcmd string) {
	NetWorkBinaryVals = NetWorkBinaryVals[:0]
	//regexpath := `[a-zA-Z0-9]:\\[\s_\-\(\)a-zA-Z0-9\\]*(\.[a-zA-Z0-9]+)`
	//repath := regexp.MustCompile(regexpath)

	//registry := `^HK([\w\\])+|([\w\-\\])+` //(HK[A-Z]+\\[a-zA-Z0-9-]+[\\]
	//registrypath := regexp.MustCompile(registry)
	res := netstatcmd

	//fmt.Println(res)
	parseit := strings.Split(res, "\n")
	//fmt.Println("total length", len(parseit))
	i := 4
	for {
		networkbinaryval = NetWorkBinary{}
		if i >= len(parseit) {
			break
		} else {
			row := strings.Fields(parseit[i])
			//fmt.Println("i val", i)
			if len(row) > 1 {
				networkbinaryval.Protocol = row[0]
				//fmt.Println(row[1])
				local := strings.Split(row[1], ":")
				//fmt.Println("local len", len(local))
				if len(strings.Split(row[1], ":")) > 1 {
					//fmt.Println(local[0])
					//fmt.Println(local[1])
					networkbinaryval.LocalIP = local[0]
					networkbinaryval.LocalPort = local[1]
				}
				remote := strings.Split(row[2], ":")
				//fmt.Println("remote len", len(remote))
				if len(remote) > 1 {
					//fmt.Println(remote[0])
					//fmt.Println(remote[1])
					networkbinaryval.RemoteIP = remote[0]
					if networkbinaryval.RemoteIP != `127.0.0.1` {
						networkbinaryval.MalwLink = `https://www.malwares.com/report/ip?ip=` + networkbinaryval.RemoteIP
					}
					networkbinaryval.RemotePort = remote[1]
				}
				networkbinaryval.ConnectionState = row[3]

				if strings.Compare(row[3], "ESTABLISHED") == 0 || strings.Compare(row[3], "CLOSE_WAIT") == 0 ||
					strings.Compare(row[3], "LISTENING") == 0 {
					if i < len(parseit) {
						i = i + 1
						exerow := strings.Fields(parseit[i])
						if (len(exerow)) == 1 {
							networkbinaryval.ExeName = parseit[i]
						}
						i = i + 1
						exerow = strings.Fields(parseit[i])
						if (len(exerow)) == 1 {
							networkbinaryval.ExeName = networkbinaryval.ExeName + parseit[i]
						} else {
							i = i - 1
						}

					}
				}

				NetWorkBinaryVals = append(NetWorkBinaryVals, networkbinaryval)
			}
			i = i + 1
		}

	}

}

func removenullfromstring(sourcestring string) string {
	removenulls := []byte(sourcestring)
	removenulls = bytes.Replace(removenulls, []byte("\x00"), []byte(""), -1)
	return string(removenulls)
}

func parseautoruns(autorunscres string) {
	AutoRunVals = AutoRunVals[:0]
	res := autorunscres
	//fmt.Println(res)

	parseit := strings.Split(res, "\n")
	var finalstr string
	i := 6
	for {

		if i < (len(parseit)) {

			finalstr = removenullfromstring(parseit[i])

			if strings.TrimSpace(finalstr) == "" {
				i = i + 1

			} else if strings.HasPrefix(finalstr, "HK") {
				autoRunval = AutoRun{}
				autoRunval.Regkey = removenullfromstring(parseit[i])
				i = i + 1

				autoRunval.AppName = removenullfromstring(parseit[i])
				i = i + 1
				autoRunval.ExecArgs = removenullfromstring(parseit[i])
				i = i + 1
				autoRunval.Description = removenullfromstring(parseit[i])
				i = i + 1
				autoRunval.Signer = removenullfromstring(parseit[i])
				i = i + 1
				autoRunval.Version = removenullfromstring(parseit[i])
				i = i + 1
				autoRunval.Commandline = removenullfromstring(parseit[i])
				i = i + 1
				autoRunval.Time = removenullfromstring(parseit[i])
				i = i + 1
				autoRunval.VtDetection = removenullfromstring(parseit[i])
				autoRunval.VtDetection = strings.TrimSpace(strings.Replace(autoRunval.VtDetection, "VT detection:", "", -1))
				i = i + 1
				autoRunval.VtPermalink = removenullfromstring(parseit[i])
				autoRunval.VtPermalink = strings.TrimSpace(strings.Replace(autoRunval.VtPermalink, "VT permalink:", "", -1))
				//autoRunval.VtPermalink = autoRunval.VtPermalink[20 : len(autoRunval.VtPermalink)-1]
				i = i + 1
				AutoRunVals = append(AutoRunVals, autoRunval)

			} else {
				autoRunval = AutoRun{}
				autoRunval.AppName = removenullfromstring(parseit[i])
				i = i + 1
				autoRunval.Description = removenullfromstring(parseit[i])
				i = i + 1
				autoRunval.ExecArgs = removenullfromstring(parseit[i])
				i = i + 1
				autoRunval.Signer = removenullfromstring(parseit[i])
				i = i + 1
				autoRunval.Version = removenullfromstring(parseit[i])
				i = i + 1
				autoRunval.Commandline = removenullfromstring(parseit[i])
				i = i + 1
				autoRunval.Time = removenullfromstring(parseit[i])
				i = i + 1
				autoRunval.VtDetection = removenullfromstring(parseit[i])
				autoRunval.VtDetection = strings.TrimSpace(strings.Replace(autoRunval.VtDetection, "VT detection:", "", -1))
				i = i + 1
				autoRunval.VtPermalink = removenullfromstring(parseit[i])
				autoRunval.VtPermalink = strings.TrimSpace(strings.Replace(autoRunval.VtPermalink, "VT permalink:", "", -1))
				i = i + 1
				AutoRunVals = append(AutoRunVals, autoRunval)
			}
		} else {
			break
		}

	}

}
func tasklistsplitter(row string) TaskList {

	var imagename = []string{}
	var pid = []string{}
	var servicename = []string{}
	lastindex := 0
	index := strings.LastIndex(row, ".exe")
	if index != -1 {
		for i := 0; i <= index+4; i++ {
			imagename = append(imagename, string(row[i]))
			lastindex = i
		}

		for i := lastindex; i < len(row); i++ {
			if row[i] >= 48 && row[i] <= 57 {
				pid = append(pid, string(row[i]))
				lastindex = i
			} else if row[i] != 32 {
				lastindex = i
				break
			}

		}

		for i := lastindex; i < len(row); i++ {
			servicename = append(servicename, string(row[i]))
		}
	}
	singlesvcname := strings.Join(servicename, "")
	singlesvcname = removenullfromstring(singlesvcname)
	singleimgname := strings.Join(imagename, "")
	singleimgname = removenullfromstring(singleimgname)
	singlepid := strings.Join(pid, "")
	singlepid = removenullfromstring(singlepid)
	TaskListVal = TaskList{}
	if strings.TrimSpace(singlesvcname) != `N/A` && strings.TrimSpace(singlepid) != "" {
		TaskListVal.ImageName = strings.TrimSpace(singleimgname)
		TaskListVal.PID = strings.TrimSpace(singlepid)
		TaskListVal.ServiceName = strings.TrimSpace(singlesvcname)
	}
	return TaskListVal

}

func parseTasklistandService(result string) {
	TaskListVals = TaskListVals[:0]
	rows := strings.Split(result, "\n")
	i := 3
	for {
		if i >= len(rows) {
			break
		} else {
			TaskListVal = tasklistsplitter(rows[i])
			if TaskListVal.ImageName != "" {
				TaskListVals = append(TaskListVals, TaskListVal)
			}
			i = i + 1

		}
	}

}

func main() {
	r := mux.NewRouter()
	// Routes consist of a path and a handler function.
	r.HandleFunc("/", index)
	r.HandleFunc("/network", network)
	r.HandleFunc("/autorun", autorun)
	r.HandleFunc("/schtasks", scheduledtasks)
	r.HandleFunc("/tasklist", tasklist)
	r.HandleFunc("/dns", dns)
	r.HandleFunc("/logonsessions", logon)
	r.PathPrefix("/bin/selected/").Handler(http.StripPrefix("/bin/selected/", http.FileServer(http.Dir("bin/selected/"))))

	srv := &http.Server{
		Handler: r,
		Addr:    "0.0.0.0:7777",
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 180 * time.Second,
		ReadTimeout:  180 * time.Second,
	}
	srv.ListenAndServe()
	//http.ListenAndServe(":7777", r)
	/*http.HandleFunc("/", index)
	http.HandleFunc("/network", network)
	http.HandleFunc("/autorun", autorun)
	http.HandleFunc("/schtasks", scheduledtasks)
	http.HandleFunc("/tasklist", tasklist)
	http.HandleFunc("/agent", createagent)

	http.Handle("/bin/selected/", http.StripPrefix("/bin/selected/", http.FileServer(http.Dir("bin/selected/"))))

		err := http.ListenAndServe(":7777", nil)
		checkerr(err)
	*/

}

func scheduledtasks(respwrt http.ResponseWriter, req *http.Request) {
	err := schtasksreport.Execute(respwrt, ScheduleTaskVals)
	checkerr(err)
}

func autorun(respwrt http.ResponseWriter, req *http.Request) {
	err := autorunreport.Execute(respwrt, AutoRunVals)
	checkerr(err)
}

func network(respwrt http.ResponseWriter, req *http.Request) {
	err := networkreport.Execute(respwrt, NetWorkBinaryVals)
	checkerr(err)
}
func tasklist(respwrt http.ResponseWriter, req *http.Request) {
	err := tasklistandservices.Execute(respwrt, TaskListVals)
	checkerr(err)
}

func dns(respwrt http.ResponseWriter, req *http.Request) {
	err := dnscache.Execute(respwrt, Dnsvals)
	checkerr(err)
}

func logon(respwrt http.ResponseWriter, req *http.Request) {
	err := logonsession.Execute(respwrt, Loginvals)
	checkerr(err)
}

func parsednscache(rows string) {
	Dnsvals = Dnsvals[:0]

	line := strings.Split(rows, "\n")
	//fmt.Println(len(line))

	var alllines []string

	for j := range line {
		linesplit := strings.Split(line[j], ":")
		if len(linesplit) > 1 {
			//dnsval = DnsCache{}
			alllines = append(alllines, line[j])
			//fmt.Printf("%s\t%s\n", linesplit[0], linesplit[1])
		}
	}
	validIP := regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	Dnsval = DnsCache{}
	//fmt.Println(len(alllines))
	i := 0
	for {
		if i < len(alllines) {
			Dnsval.RecordName = strings.Split(alllines[i], ":")[1]
			i = i + 1
			Dnsval.RecordType = strings.Split(alllines[i], ":")[1]
			i = i + 1
			Dnsval.TimeToLive = strings.Split(alllines[i], ":")[1]
			i = i + 1
			Dnsval.DataLength = strings.Split(alllines[i], ":")[1]
			i = i + 1
			Dnsval.Section = strings.Split(alllines[i], ":")[1]
			i = i + 1
			Dnsval.RecordType2 = "[" + strings.TrimSpace(strings.Replace(strings.Split(alllines[i], ":")[0], ".", "", -1)) + "]" + strings.Split(alllines[i], ":")[1]
			isIP := validIP.MatchString(strings.TrimSpace(strings.Split(Dnsval.RecordType2, "]")[1]))
			if isIP {
				Dnsval.MalwLink = `https://www.malwares.com/report/ip?ip=` + strings.TrimSpace(strings.Split(Dnsval.RecordType2, "]")[1])
			} else {
				Dnsval.MalwLink = `https://www.malwares.com/report/host?host=` + strings.TrimSpace(strings.Split(Dnsval.RecordType2, "]")[1])
			}
			i = i + 1
			if i%6 == 0 {
				Dnsvals = append(Dnsvals, Dnsval)
				Dnsval = DnsCache{}
			}
		} else {
			break
		}
	}

}

func index(respwrt http.ResponseWriter, req *http.Request) {
	redc := color.New(color.FgHiRed, color.Bold)
	yellownc := color.New(color.FgHiYellow, color.Bold)
	cyanc := color.New(color.FgCyan, color.Bold)
	if req.Method == "POST" {
		//fmt.Println("posted data")
		err := req.ParseForm()
		checkerr(err)

		//cmdtopost := req.Form.Get("cmd")

		cmdres := req.Form.Get("cmdres")
		//invcmd := req.Form.Get("invcmd")
		huntid := req.Form.Get("huntid")
		if huntid == "1" {
			enccmdtopost.Commandres = cmdres

			//greenc.Println(cmdtopost)
			parseautoruns(cmdres)
			yellownc.Println("\t\tReport is ready at : http://127.0.0.1:7777/autorun")
			redc.Println("\t\t____________________________________________")
			//redc.Println(res)

			/*for j := range AutoRunVals {
				redc.Println("Reg key ", AutoRunVals[j].Regkey)
				redc.Println("App Name", AutoRunVals[j].AppName)
				redc.Println("Signer", AutoRunVals[j].Signer)
				redc.Println("Description", AutoRunVals[j].Description)
				redc.Println("Time", AutoRunVals[j].Time)
				redc.Println("CommandLine", AutoRunVals[j].Commandline)
				redc.Println("Version", AutoRunVals[j].Version)
				AutoRunVals[j].VtDetection = strings.TrimSpace(strings.Replace(AutoRunVals[j].VtDetection, "VT detection:", "", -1))
				AutoRunVals[j].VtPermalink = strings.TrimSpace(strings.Replace(AutoRunVals[j].VtPermalink, "VT permalink:", "", -1))
				redc.Println("VT Detect", AutoRunVals[j].VtDetection)
				redc.Println("VT Permalink", AutoRunVals[j].VtPermalink)

			}*/
		} else if huntid == "2" {
			parsenetstat(cmdres)
			yellownc.Println("\t\tReport is ready at : http://127.0.0.1:7777/network")
			redc.Println("\t\t____________________________________________")
			/*for j := range NetWorkBinaryVals {

				fmt.Println(NetWorkBinaryVals[j].Protocol)
				fmt.Println(NetWorkBinaryVals[j].LocalIP)
				fmt.Println(NetWorkBinaryVals[j].LocalPort)
				fmt.Println(NetWorkBinaryVals[j].RemoteIP)
				if NetWorkBinaryVals[j].RemoteIP != `127.0.0.1` {
					NetWorkBinaryVals[j].MalwLink = `https://www.malwares.com/report/ip?ip=` + NetWorkBinaryVals[j].RemoteIP
				}
				fmt.Println(NetWorkBinaryVals[j].RemotePort)
				fmt.Println(NetWorkBinaryVals[j].ConnectionState)
				fmt.Println(NetWorkBinaryVals[j].ExeName)
				fmt.Println(NetWorkBinaryVals[j].MalwLink)
				redc.Println("____________________________________________")
			}*/

		} else if huntid == "3" {
			parsescheduletasks(cmdres)
			yellownc.Println("\t\tReport is ready at : http://127.0.0.1:7777/schtasks")
			redc.Println("\t\t_____________________________________________________________")
			/*for x := range ScheduleTaskVals {
				//ScheduleTaskVals[x].FolderName = strings.Replace(ScheduleTaskVals[x].FolderName, "\r\n", "", -1)
				//fmt.Println(ScheduleTaskVals[x].FolderName)
				fmt.Println(ScheduleTaskVals[x].TaskName)
				fmt.Println(ScheduleTaskVals[x].NextRunTime)
				fmt.Println(ScheduleTaskVals[x].Status)
			}
			*/
		} else if huntid == "4" {
			parseTasklistandService(cmdres)
			yellownc.Println("\t\tReport is ready at : http://127.0.0.1:7777/tasklist")

			/*for x := range TaskListVals {
				fmt.Println(TaskListVals[x].ImageName, TaskListVals[x].PID, TaskListVals[x].ServiceName)
			}*/
			redc.Println("_______________________________________________________")
		} else if huntid == "5" {
			parsednscache(cmdres)
			yellownc.Println("\t\tReport is ready at : http://127.0.0.1:7777/dns")
			yellownc.Println("\t\t___________________________________________________")
			/*for x := range Dnsvals {
				yellownc.Println("____________________________________________")
				fmt.Println("Record Name : " + Dnsvals[x].RecordName)
				fmt.Println("Record Type : " + Dnsvals[x].RecordType)
				fmt.Println(Dnsvals[x].RecordType2)
				fmt.Println(Dnsvals[x].DataLength)
				fmt.Println(Dnsvals[x].TimeToLive)
				fmt.Println(Dnsvals[x].Section)

			}*/
		} else if huntid == "6" {
			parselogonsessions(cmdres)
			yellownc.Println("\t\tReport is ready at : http://127.0.0.1:7777/logonsessions")
			yellownc.Println("\t\t___________________________________________________")

		} else if huntid == "xit" {
			fmt.Printf("Hunt over. Bye for now.")
			os.Exit(0)
		}
		//err = enctemplate.Execute(respwrt, enccmdtopost)
		//checkerr(err)

		//content, _ := ioutil.ReadAll(req.Body)
		//fmt.Println(string(content))
	} else {
		yellownc.Printf("\tSelect your hunt :\n")
		cyanc.Printf("\t\t1. AutoRun\n")
		cyanc.Printf("\t\t2. Network\n")
		cyanc.Printf("\t\t3. Scheduled Tasks\n")
		cyanc.Printf("\t\t4. TaskList and Services\n")
		cyanc.Printf("\t\t5. DNS Cache\n")
		cyanc.Printf("\t\t6. LoginSessions\n")
		cyanc.Printf("\t\t7. Whoami(User/Group/Privileges) [N/A]\n")
		cyanc.Printf("\t\t8. Drivers [N/A]\n")
		cyanc.Printf("\t\t9. Host Entries [N/A]\n")
		cyanc.Printf("\t\t10. Environment Variables [N/A]\n")
		cyanc.Printf("\t\t11. IPv4 Route [N/A]\n")
		cyanc.Printf("\t\t12. ARP Cache [N/A]\n")
		yellownc.Printf("\t\t>>>> ")
		reader := bufio.NewReader(os.Stdin)
		cmdtopost, _ := reader.ReadString('\n')
		if cmdtopost == "xit" {
			redc.Printf("\t\tYou have opted to Exit")
		} else {
			yellownc.Printf("\t\tYou have opted to hunt " + strings.TrimRight(cmdtopost, "\r\n\t\t"))
		}
		enccmdtopost.Command = cmdtopost
		err := enctemplate.Execute(respwrt, enccmdtopost)
		checkerr(err)
	}
}
