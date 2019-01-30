package TBLogger

import (
	"bytes"
	//"clap/staging/db"
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Logger interface {
	Debug(debugMsg ...interface{})
	Info(infoMsg ...interface{})
	Warn(warnMsg ...interface{})
	Error(errorMsg ...interface{})
}

var TbLogger *TBLogger

type TBLogger struct {
	//记录Logger信息的文件名 默认为Logger
	FileName string

	//Logger文件路径
	LoggerFilePath string

	//数据库配置数据
	DbConfig *DBOutPut

	//Logger
	innerLogger *log.Logger

	//是否将数据写入数据库,默认为false
	LogDataBase bool

	//是否记录调用文件的长路径
	LogFilePath bool

	//是否记录调用的函数
	LogFunc bool

	//文件路径深度，设定适当的值，否则文件路径不正确
	RunTimeCaller int

	//缓存信息管道
	MsgQueue chan string

	//同步信号
	syncReq chan struct{}

	//今天的日期，根据该日期判断是否更换文件
	TodayDate string

	//写入文件句柄
	CurFile *os.File

	//缓存数量
	CacheNum int

	//设定周期时间，到期写入,单位秒
	PeriodTime int

	//互斥锁
	sync.Mutex

	//计时器
	Ticker *time.Ticker

	//关闭Logger
	Closed bool
}

func init() {
	NewTBLogger(true, true, 10, 20, nil)
	TbLogger.Info("创建TbLogger成功!")
}

func NewTBLogger(logFunc bool, logFilePath bool, cacheNum int, periodTime int, db *sql.DB) {
	TbLogger = new(TBLogger)

	if cacheNum <= 0 {
		cacheNum = 10
		fmt.Println("cacheNum <=0;set default value 10")
	}

	if periodTime <= 0 {
		periodTime = 10
		fmt.Println("periodTime <=0;set default value 10")
	}

	TbLogger.LogFunc = logFunc
	TbLogger.LogFilePath = logFilePath
	TbLogger.CacheNum = cacheNum
	TbLogger.PeriodTime = periodTime
	TbLogger.RunTimeCaller = 2
	TbLogger.DbConfig = NewDbOutPut(db)
	TbLogger.MsgQueue = make(chan string, TbLogger.CacheNum)
	TbLogger.syncReq = make(chan struct{})
	TbLogger.TodayDate = time.Now().Format("2006-01-02")
	TbLogger.FileName = "Logger.txt"

	var multi io.Writer

	binPath, err := GetProDir()
	if err != nil {
		panic("get binPath failed " + err.Error())
		return
	}

	TbLogger.LoggerFilePath = binPath + "/log/"

	err = mkdirProDir(binPath + "/log")
	if err != nil {
		panic("mkdirProDir failed " + err.Error())
	}

	logFile, err := os.OpenFile(TbLogger.LoggerFilePath+TbLogger.FileName,
		os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic("OpenFile fail")
	}
	TbLogger.CurFile = logFile

	if TbLogger.DbConfig != nil {
		multi = io.MultiWriter(logFile, TbLogger.DbConfig)
	} else {
		multi = io.MultiWriter(logFile)
	}

	TbLogger.innerLogger = log.New(multi, "", 0)

	//go TbLogger.SyncRequest()
	go TbLogger.ListenTimeOut()
}

func (tbl *TBLogger) GetFormat(level string) string {
	var buf bytes.Buffer

	//时间信息
	buf.WriteString(time.Now().Format("2006-01-02 15:04:05 "))

	buf.WriteString(level)

	funcName, file, line, ok := runtime.Caller(tbl.RunTimeCaller)
	if ok {
		if tbl.LogFilePath {
			buf.WriteString(filepath.Base(file))
			buf.WriteString(":")
			buf.WriteString(strconv.Itoa(line))
			buf.WriteString(" ")
		}
		if tbl.LogFunc {
			buf.WriteString(runtime.FuncForPC(funcName).Name())
			buf.WriteString(" ")
		}
	}
	return buf.String()
}

func (tbl *TBLogger) GetAllStack() string {
	var buf bytes.Buffer
	bufallstack := make([]byte, 1<<20)
	runtime.Stack(bufallstack, false)
	buf.Write(bufallstack)
	return buf.String()
}

func (tbl *TBLogger) Debug(msg ...interface{}) {
	format := tbl.GetFormat("DEBUG ")
	tbl.outPutMsg(format, msg...)
}

func (tbl *TBLogger) Info(msg ...interface{}) {
	format := tbl.GetFormat("INFO ")
	tbl.outPutMsg(format, msg...)
}

func (tbl *TBLogger) Warn(msg ...interface{}) {
	format := tbl.GetFormat("WARN ")
	tbl.outPutMsg(format, msg...)
}

func (tbl *TBLogger) Error(msg ...interface{}) {
	format := tbl.GetFormat("ERROR ")
	tbl.outPutMsg(format, msg...)
}

//定时器，没经过TBLogger.PeriodTime 秒就请求写入一次
func (tbl *TBLogger) ListenTimeOut() {
	tbl.Ticker = time.NewTicker(time.Duration(tbl.PeriodTime) * time.Second)
	for {
		select {
		case <-tbl.Ticker.C:
			tbl.Write()
		}
	}
}

//日期变化，新创文件，并更改原来log文件名称
func (tbl *TBLogger) ChangeDateFile() {

	var buf bytes.Buffer

	if tbl.CurFile == nil {
		buf.Reset()
		buf.WriteString("ChangeDateFile--CurFile nil")
		tbl.DbConfig.Write(buf.Bytes())
		return
	}

	preFile := tbl.CurFile

	_, err := preFile.Stat()
	if err != nil {
		buf.Reset()
		buf.WriteString("ChangeDateFile--preFile.Stat() Fail")
		tbl.DbConfig.Write(buf.Bytes())
		return
	}

	filePath := tbl.LoggerFilePath + tbl.FileName

	err = preFile.Close()
	if err != nil {
		buf.Reset()
		buf.WriteString("ChangeDateFile--preFile.Close() Fail")
		tbl.DbConfig.Write(buf.Bytes())
	}

	//重新命名，在旧的文件名上加上日期
	nowTime := time.Now()
	time1dAgo := nowTime.Add(-1 * time.Hour * 24)
	err = os.Rename(filePath, tbl.LoggerFilePath+time1dAgo.Format("2006-01-02 ")+tbl.FileName)
	if err != nil {
		buf.Reset()
		buf.WriteString("ChangeDateFile--os.Rename Fail" + err.Error())
		tbl.DbConfig.Write(buf.Bytes())
	}

	//创建新文件
	NextFile, err := os.OpenFile(filePath,
		os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		buf.Reset()
		buf.WriteString("ChangeDateFile--Open NextFile Fail")
		tbl.DbConfig.Write(buf.Bytes())
		return
	}

	//重新设置输出
	multi := io.MultiWriter(NextFile, tbl.DbConfig)
	tbl.innerLogger.SetOutput(multi)
	tbl.CurFile = NextFile
	tbl.TodayDate = nowTime.Format("2006-01-02")
}

//关闭TBLogger
func (tbl *TBLogger) Close() {
	var buf bytes.Buffer
	err := tbl.CurFile.Close()
	if err != nil {
		buf.Reset()
		buf.WriteString("Close() CurFile.Close() Fail")
		tbl.DbConfig.Write(buf.Bytes())
	}
	tbl.Ticker.Stop()
	tbl.Write()
	tbl.Lock()
	close(tbl.MsgQueue)
	tbl.Unlock()
	close(tbl.syncReq)
	tbl.Closed = true
}

//将消息输出到控制台并加入到管道队列中
func (tbl *TBLogger) outPutMsg(format string, msg ...interface{}) {
	fmt.Println(append([]interface{}{format}, msg...)...)
	select {
	case tbl.MsgQueue <- fmt.Sprintln(append([]interface{}{format}, msg...)...):
	default:
		tbl.Write()
		tbl.MsgQueue <- fmt.Sprintln(append([]interface{}{format}, msg...)...)
	}
}

// 写入到数据库和Log文件
func (tbl *TBLogger) Write() {
	tbl.Lock()
	defer tbl.Unlock()
	nowDate := time.Now().Format("2006-01-02")
	if nowDate != tbl.TodayDate {
		tbl.ChangeDateFile()
	}
	if tbl.Closed == false {
		for {
			select {
			case msg := <-tbl.MsgQueue:
				tbl.innerLogger.Println(msg)
			default:
				return
			}
		}
	}

}

func GetProDir() (string, error) {
	file, err := exec.LookPath(os.Args[0])
	if err != nil {
		return "", err
	}
	path, err := filepath.Abs(file)
	if err != nil {
		return "", err
	}
	path = filepath.Dir(path)
	return strings.Replace(path, "\\", "/", -1), nil
}

func mkdirProDir(logDir string) error {
	//创建log目录在项目目录下
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		os.Mkdir(logDir, 0770)
	} else {
		return err
	}
	return nil
}
