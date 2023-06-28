package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"http/config"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func main() {
	Viper := InitConfig()
	port := Viper.GetString("port")
	fmt.Println("HTTP服务启动，监听端口：" + port)
	mux := &SecretDetectionHttpStruct{}
	http.ListenAndServe(":"+port, mux)
}

// 新建HTTP的 mux 结构体，用于进行 http.ListenAndServe() 作为第二个参数传入
type SecretDetectionHttpStruct struct {
}

// 用于实现 mux 的ServeHTTP 成员方法
func (mux *SecretDetectionHttpStruct) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	fmt.Println("接收到HTTP连接，来自 " + r.RemoteAddr)

	// 在此处进行手动路由处理
	switch r.URL.Path {
	case "/static_zip_scanAction":
		// 处理传来的zip源代码包
		static_zip_scanAction(w, r)
		return
	case "/get_descriptions_0":
		// 获取规则，已废弃
		get_descriptions_0(w, r)
		return
	case "/get_descriptions_1":
		// 获取规则
		get_descriptions_1(w, r)
		return
	default:
		// 默认路由，无用
		RootAction(w, r)
		return
	}
}

// 路由: / , 仅响应一串文字
func RootAction(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	ret := r.URL.String() + "\n" + string(body)
	w.Write([]byte(ret))
}

// 路由: /git_scan ，接收 post文本传参 的 git clone凭证，用来进行gitclone
func get_descriptions_0(w http.ResponseWriter, r *http.Request) {
	data, err := config.Asset("config/default.toml")
	resJson, err := config.RuleJson(data)
	if err != nil {
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, string(resJson))
}

// 路由: /git_scan ，接收 post文本传参 的 git clone凭证，用来进行gitclone
func get_descriptions_1(w http.ResponseWriter, r *http.Request) {
	data, err := config.Asset("config/default.toml")
	resJson, err := config.RuleJson(data)
	if err != nil {
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, string(resJson))

}

// 路由: /static_zip_scan ，接收 post表单传参 数据
func static_zip_scanAction(w http.ResponseWriter, r *http.Request) {

	//我这里设置 256MByte，注意，256MByte == (256*8) << 20Mbit
	//我这里设置 256MByte，注意，2KByte == (2*8) << 10
	var back_url, scan_mode, ScanSourceMode string
	r.ParseMultipartForm((1 * 8) << 10)
	if r.MultipartForm != nil {
		//这个只能处理 form-data 传参中的文本传参，不能处理文件类型
		values := r.MultipartForm.Value

		for formName, formValue := range values {
			for _, value := range formValue {
				if formName == "back_url" {
					back_url = value
					fmt.Println("接收到back_url", back_url)
				}
				if formName == "scan_mode" {
					scan_mode = value
					fmt.Println("接收到scan_mode", scan_mode)
				}
			}
		}
	}
	fmt.Println("接收到参数: 扫描模式-" + scan_mode + " 回调地址-" + back_url)

	formFile, header, err := r.FormFile("file")
	if err != nil {
		fmt.Print(err)
	}
	defer formFile.Close()
	fmt.Println("正在接收文件")

	// 获取zip的目标路径
	ZipDestFileDir, err := GenerateZipDestFileDir()
	if err != nil {
		fmt.Print(err)
	}

	// 获取zip的文件路径及名字
	ZipDestFilePath := fmt.Sprintf("%s/%s", ZipDestFileDir, header.Filename)
	fmt.Println("接收文件完毕，正在复制至" + ZipDestFilePath)

	// 创建zip的文件目录
	destFile, err := os.Create(ZipDestFilePath)
	if err != nil {
		fmt.Printf("Create failed: %s\n", err.Error())
	}

	// 用于SDM ->  Docker 下发任务后 的响应代码，返回json，成功和失败的json结构体
	type JsonReceived struct {
		ReceivedCode int
		JsonErrDes   string
	}

	// 将原本的zip文件复制到目标目录 ZipDestFilePath 中
	_, err = io.Copy(destFile, formFile)
	if err != nil {
		fmt.Print(err)

		DetailRec := JsonReceived{0, err.Error()}
		JSRec, _ := json.Marshal(DetailRec)
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "application/json")
		w.Write(JSRec)

		return
	}

	destFile.Close()
	fmt.Println("复制文件完毕，至 " + ZipDestFilePath)

	go func() {
		// 此时响应代码断开连接

		DetailRec := JsonReceived{1, "success received"}
		JSRec, _ := json.Marshal(DetailRec)
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "application/json")
		//w.Write(JSRec)
		err = json.NewEncoder(w).Encode(&DetailRec)
		if err != nil {
			fmt.Print(err)
		}
		fmt.Println("对下发请求HTTP进行响应", string(JSRec))
	}()

	//进行解压缩
	_, err = Unzip(ZipDestFilePath, ZipDestFileDir)
	if err != nil {
		fmt.Print(err)
	}
	fmt.Println("解压完毕 ")

	//	删除zip包
	err = os.Remove(ZipDestFilePath)
	if err != nil {
		fmt.Print(err)
	}
	fmt.Println("压缩包删除完毕 ")

	// 加载规则文件
	Viper := InitConfig()
	SecretDetectionEXE := Viper.GetString("SecretDetection_exe_path")
	DetectReportFile := Viper.GetString("SecretDetection_report_file")
	var TomlRule string
	TomlRule1 := Viper.GetString("TomlRule1")
	TomlRule2 := Viper.GetString("TomlRule2")
	ExitCode := Viper.GetString("exit-code")
	// 0业务模式，1安全模式
	if scan_mode == "0" {
		TomlRule = TomlRule1
	} else if scan_mode == "1" {
		TomlRule = TomlRule2
	}

	var ErrFlag bool
	ErrFlag = false

	fmt.Println("ZipDestFileDir： ", ZipDestFileDir)

	// 这里需要看压缩包解压后，是不是把所有文件又放在新建的文件夹的顶级目录
	// 因为对一个目录压缩后，再进行解压，会有两种情况（无法从其他特征判断）：
	// 1. 解压后一堆文件就在当前目录
	// 2. 解压后，进一下解压时的新建目录，才会看到一堆文件
	// 这里根据解压情况调整 GitPath
	// 如果有.git，那么GitPath就在.git目录
	// 如果没有.git，那么GitPath
	var gitExistBool bool
	_, err = os.Stat(filepath.Join(ZipDestFileDir, ".git"))
	var GitPath string
	if os.IsNotExist(err) {
		fmt.Println("直接目录中没有.git目录，进行二层处理")
		files, _ := ioutil.ReadDir(ZipDestFileDir)
		if len(files) == 1 {
			_, err := os.Stat(filepath.Join(ZipDestFileDir, files[0].Name(), ".git"))
			if err != nil {
				if os.IsNotExist(err) {
					gitExistBool = false
					fmt.Println("直接目录中没有.git目录，二层也没有.git目录")
					GitPath = ZipDestFileDir
				}
			} else {
				gitExistBool = true
				fmt.Println("直接目录中没有.git目录，二层存在.git目录")
				GitPath = filepath.Join(ZipDestFileDir, files[0].Name())
			}

		} else {
			gitExistBool = false
			fmt.Println("非打包.git的压缩包，进行--no-git扫描。直接目录中没有.git目录，且二层目录数量不为1，即非.git非压缩多一层目录导致")
			GitPath = ZipDestFileDir
		}
	} else {
		gitExistBool = true
		fmt.Println("直接目录存在.git目录")
		GitPath = ZipDestFileDir
		//fmt.Println(".git目录位置: ", dstUnzipDir)
	}
	// 【GitPath】 判断完毕

	fmt.Println("确认 -s 扫描路径 GitPath: ", GitPath)
	fmt.Println("确认扫描目录:", GitPath)
	fmt.Println("确认输出json文件: ", filepath.Join(ZipDestFileDir, DetectReportFile))
	if gitExistBool == true {
		fmt.Println("检测到 .git 目录")
	} else {
		fmt.Println("未检测到 .git 目录")
	}

	// 如果是git项目，依次进行 no-git -> git 扫描
	// 如果是非git项目，只进行 no-git 扫描
	if gitExistBool == true {
		// 【进行 no-git 扫描】
		fmt.Println("【再进行 no-git 扫描】")
		SDNogitJsonFilePath := filepath.Join(ZipDestFileDir, ".SDNogit.json")
		cmdNoGit := exec.Command(SecretDetectionEXE, "detect", "--no-git", "-f", "json", "-r", SDNogitJsonFilePath, "-v", "-s", GitPath, "-c", TomlRule, "--exit-code", ExitCode)
		var stdoutNoGit, stderrNoGit bytes.Buffer
		cmdNoGit.Stdout = &stdoutNoGit
		cmdNoGit.Stderr = &stderrNoGit
		fmt.Println("启动命令行扫描")
		err = cmdNoGit.Run()
		outStrNoGit, errStrNoGit := string(stdoutNoGit.Bytes()), string(stderrNoGit.Bytes())
		fmt.Println("错误输出：")
		fmt.Println(errStrNoGit)
		fmt.Println("错误输出结束")
		fmt.Println("标准输出：")
		fmt.Println(outStrNoGit)
		fmt.Println("标准输出结束")

		_, err = os.Stat(filepath.Join(ZipDestFileDir, ".SDNogit.json"))
		if os.IsNotExist(err) {
			fmt.Println("未获取no-git扫描结果文件 .SDNogit.json")
		}

		// 【进行 git log 扫描】
		fmt.Println("【先进行 git log 扫描】")
		SDgitJsonFilePath := filepath.Join(ZipDestFileDir, ".SDgit.json")
		cmdGit := exec.Command(SecretDetectionEXE, "detect", "-f", "json", "-r", SDgitJsonFilePath, "-v", "-s", GitPath, "-c", TomlRule, "--exit-code", ExitCode)
		var stdoutGit, stderrGit bytes.Buffer
		cmdGit.Stdout = &stdoutGit
		cmdGit.Stderr = &stderrGit
		fmt.Println("启动命令行扫描")
		err = cmdGit.Run()
		outStrGit, errStrGit := string(stdoutGit.Bytes()), string(stderrGit.Bytes())
		fmt.Println("错误输出：")
		fmt.Println(errStrGit)
		fmt.Println("错误输出结束")
		fmt.Println("标准输出：")
		fmt.Println(outStrGit)
		fmt.Println("标准输出结束")

		_, err = os.Stat(filepath.Join(ZipDestFileDir, ".SDgit.json"))
		if os.IsNotExist(err) {
			fmt.Println("未获取git扫描结果文件 .SDgit.json")
		}

		// ultimateJson就是经过处理后的最终结果
		var resGitJson, resNoGitJson, ultimateJson Resjson
		resGitJsonFile, _ := ioutil.ReadFile(SDgitJsonFilePath)
		json.Unmarshal(resGitJsonFile, &resGitJson)
		resNoGitJsonFile, _ := ioutil.ReadFile(SDNogitJsonFilePath)
		json.Unmarshal(resNoGitJsonFile, &resNoGitJson)

		// 进行贝总遍历
		// 因为最终根据nogit结果确认最终扫描。故外层nogit，内层git，然后根据nogit的找git中的数据。
		// 此处手动赋值 GitScan 是因为进行了nogit和git两轮结果合并，而后面nogit没有赋值扫描模式是因为被调用的程序自己会写localscan
		ultimateJson.ScanSourceMode = "GitScan"
		for _, singleNoGitFinding := range resNoGitJson.Res {
			for _, singleGitFinding := range resGitJson.Res {
				if singleNoGitFinding.File == singleGitFinding.File && (singleNoGitFinding.StartLine == singleGitFinding.StartLine || singleNoGitFinding.EndLine == singleGitFinding.EndLine) {
					ultimateJson.Res = append(ultimateJson.Res, singleGitFinding)
					// 根据nogit找到git标识就跳出，继续找下个nogit数据
					break
				}
			}
		}

		fmt.Println("\n\n【最终json数据】", ultimateJson)
		fmt.Println("\n\n【最终json数量】", len(ultimateJson.Res))

		// 将结果写入.SD.json
		ultimateJsonFile, _ := os.OpenFile(filepath.Join(ZipDestFileDir, DetectReportFile), os.O_RDWR|os.O_CREATE, 0755)
		defer ultimateJsonFile.Close()
		ultimateJsonByte, _ := json.Marshal(ultimateJson)
		_, err = ultimateJsonFile.Write(ultimateJsonByte)

	} else if gitExistBool == false {
		//	进行 无.git 的扫描检测
		fmt.Println("【no-git 扫描】")
		// 此处 -r 直接生成.SD.json文件
		cmd := exec.Command(SecretDetectionEXE, "detect", "--no-git", "-f", "json", "-r", filepath.Join(ZipDestFileDir, DetectReportFile), "-v", "-s", GitPath, "-c", TomlRule, "--exit-code", ExitCode)
		// ./SecretDetection detect -f json -r test_tmp.json -v -s -c --exit-code 0
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		fmt.Println("启动命令行扫描")
		err = cmd.Run()
		outStr, errStr := string(stdout.Bytes()), string(stderr.Bytes())

		fmt.Println("标准输出：")
		fmt.Println(outStr)
		fmt.Println("标准输出结束")
		fmt.Println("错误输出：")
		fmt.Println(errStr)
		fmt.Println("错误输出结束")

		if err != nil {
			log.Fatalf("cmd.Run() failed with %s\n", err)
		}
	}

	// 加载.SD.json获取结果数据
	_, err = os.Stat(filepath.Join(ZipDestFileDir, DetectReportFile))

	if os.IsNotExist(err) {
		fmt.Println("获取json结果失败，未生成结果文件")
	}

	type JsonErr struct {
		ErrCode    int
		JsonErrDes string
	}

	if ErrFlag {
		fmt.Println("扫描结果json文件获取失败")
		DetailErr := fmt.Sprintf("%v", "扫描结果json文件获取失败")
		fmt.Println(DetailErr)
		jsonErr := JsonErr{1, DetailErr}
		js, err := json.Marshal(jsonErr)
		if err != nil {
			fmt.Print(err)
		}
		go ResponseToSDM(js, back_url, ScanSourceMode)
	} else {
		fmt.Println("扫描结果json文件获取成功")
		ResJsonData, err := ioutil.ReadFile(filepath.Join(ZipDestFileDir, DetectReportFile))
		if err != nil {
			fmt.Print(err)
		}
		go ResponseToSDM(ResJsonData, back_url, ScanSourceMode)

	}

	// 最后删除上传者的目录
	os.RemoveAll(ZipDestFileDir)
	fmt.Println("压缩包删除完毕")

}

func ResponseToSDM(jsonstr []byte, back_url, ScanSourceMode string) {
	//Viper := InitConfig()
	//SDM_uri := Viper.GetString("sdm_uri")

	SDM_uri := back_url

	req, err := http.NewRequest("POST", SDM_uri, bytes.NewBuffer(jsonstr))

	if err != nil {
		fmt.Print(err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}

	fmt.Println("[#] 回连back_url进行响应", SDM_uri)

	//reqBody, _ := io.ReadAll(req.Body)
	//fmt.Println(string(reqBody))
	//fmt.Println(req.)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Print(err)
		return
	}

	fmt.Println("[#] Header")
	fmt.Println(resp.Header)
	b, err := io.ReadAll(resp.Body)
	fmt.Println("[#] resp Body")
	fmt.Println(string(b))
	fmt.Println("[#] resp.Request")
	fmt.Println(resp.Request)

	defer resp.Body.Close()

}

func Unzip(src, dst string) (string, error) {
	zr, err := zip.OpenReader(src)
	defer zr.Close()
	if err != nil {
		fmt.Println(err)
	}
	flag := false
	var retDirName string
	for _, file := range zr.File {
		path := filepath.Join(dst, file.Name)
		if flag == false {
			retDirName = file.Name
		}
		flag = true

		// 如果是目录，就创建目录
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(path, file.Mode()); err != nil {
				fmt.Println(err)
			}
			// 因为是目录，跳过当前循环，因为后面都是文件的处理
			continue
		}

		// 获取到 Reader
		fr, err := file.Open()
		if err != nil {
			fmt.Println(err)
		}

		// 创建要写出的文件对应的 Write
		fw, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, file.Mode())
		if err != nil {
			fmt.Println(err)
		}

		io.Copy(fw, fr)

		fw.Close()
		fr.Close()
	}
	return retDirName, nil
}

func GenerateZipDestFileDir() (string, error) {
	Viper := InitConfig()

	//时间戳 加 uuid 创建目录名字， 避免gotoutine会把同时上传的zip文件放在相同目录中
	SandBoxDirName := time.Now().Format("20060102150405") + "-" + uuid.New().String()
	ZipDestFileDir := Viper.GetString("save_to_local_path") + SandBoxDirName
	err := os.Mkdir(ZipDestFileDir, os.ModePerm)
	if err != nil {
		return "", err
	}
	return ZipDestFileDir, nil
}

func InitConfig() *viper.Viper {
	// 从config/local_config.yaml中读取配置
	config := viper.New()
	config.AddConfigPath("./config/")
	config.SetConfigName("local_config")
	config.SetConfigType("yaml")
	if err := config.ReadInConfig(); err != nil {
		panic(err)
	}
	return config
}

type Resjson struct {
	ScanSourceMode string    `json:"ScanSource"`
	Res            []Finding `json:"ScanRes"`
}

type Finding struct {
	Description string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int

	Match string

	// Secret contains the full content of what is matched in
	// the tree-sitter query.
	Secret string

	// File is the name of the file containing the finding
	File string

	Commit string

	// Entropy is the shannon entropy of Value
	Entropy float32

	Author  string
	Email   string
	Date    string
	Message string
	Tags    []string

	// Rule is the name of the rule that was matched
	RuleID string

	// unique identifer
	Fingerprint string
}
