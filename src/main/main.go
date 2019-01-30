package main

import (
	"fmt"
	"MockWeChatLogin/src/TBCache"
	"net/http"
	"github.com/skip2/go-qrcode"
	"io/ioutil"
	"MockWeChatLogin/src/TBLogger"
	"math/rand"
	"time"
	"errors"
	"github.com/gorilla/mux"
	"log"
	"encoding/json"
)

var (
	cache *TBCache.TBCache
	urlBase string
	api = "http://localhost:8083"
	MockCode = "MockCode"
)

type UserLogin struct {
	AppId string
	Sid string
	QRPng []byte
	RedirectUrl string
	ResponseType string
	Scope string
	State string
	scan   chan bool
}

type AuthorizationInfo struct {
	AccessToken 	string	`json:"access_token"`
	ExpiresIn 	 	int		`json:"expires_in"`
	RefreshToken 	string	`json:"refresh_token"`
	OpenId 			string	`json:"openid"`
	Scope			string	`json:"scope"`
	UnionId			string	`json:"unionid"`
}

type WeChatUserInfo struct {
	Openid 		string 		`json:"openid"`
	NickName 	string 		`json:"nickname"`
	Sex 		int 		`json:"sex"`
	Language 	string 		`json:"language"`
	City 		string 		`json:"city"`
	Province 	string 		`json:"province"`
	Country 	string 		`json:"country"`
	HeadImgUrl	string	 	`json:"headimgurl"`
	Privilege 	[]string 	`json:"privilege"`
	Unionid 	string		`json:"unionid"`
}

func initServer() {
	cache = TBCache.NewCache(1000,3600000,3600000)
}

func predefineUser() {

}

func Index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	binPath, err := TBLogger.GetProDir()
	if err!=nil{
		return
	}
	dat, err := ioutil.ReadFile(binPath+"/main/login.html")
	if err != nil {
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte("Not Implemented."))
		return
	}
	qrcode.WriteFile("asdfasdfas", qrcode.Medium, 256, "./src/main/qrcode2.png")

	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	w.Header().Add("Uuid","asdi23645asdzx")
	//w.Header().Set("Content-Length", string(len(dat)))
	w.Header().Set("Cache-Control","no-cache")
	w.Write(dat)
}

//获取二维码
func Qrcode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	var err error
	defer func() {
		if err != nil {
			w.WriteHeader(500)
			return
		}
	}()

	val := r.URL.Query()
	appid := val["appid"]
	if appid[0] == ""{
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No addid"))
		return
	}

	qrc:=cache.GetValue(appid[0])
	if qrc ==nil {
		err = errors.New("no this sid cache")
		return
	}

	ul ,ok := qrc.(*UserLogin)
	if !ok{
		TBLogger.TbLogger.Error("assert fail")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(ul.QRPng)))
	w.Write(ul.QRPng)
}

//生成sid并根据sid生成appid的二维码
func GetSid(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Access-Control-Allow-Origin", "*")
	var sid string
	sid = GetRandomString(20)

	val := r.URL.Query()
	appid := val["appid"]
	if appid[0] == ""{
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No addid"))
		return
	}

	ul:=cache.GetValue(appid[0])
	if ul ==nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("no this sid cache"+appid[0]))
		TBLogger.TbLogger.Error("no this sid cache")
		return
	}

	userLogin ,ok := ul.(*UserLogin)
	if !ok{
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("assert fail"))
		TBLogger.TbLogger.Error("assert fail")
		return
	}
	userLogin.Sid = sid

	q, err := qrcode.New(api+"/authorize?sid="+sid+"&appid="+userLogin.AppId, qrcode.Medium)
	if err!=nil{
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("get qrcode fail"))
		return
	}

	png, err := q.PNG(256)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("get qrcode fail"))
		return
	}

	userLogin.QRPng = png

	cache.InsertCache(userLogin.AppId,userLogin)
	w.Write([]byte(sid))

}

//等待被扫码.扫描成功之后跳转url
func Redirect(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Access-Control-Allow-Origin", "*")
	var err error
	defer func() {
		if err != nil {
			w.WriteHeader(500)
			return
		}
	}()

	val := r.URL.Query()
	appid := val["appid"]
	if appid[0] == ""{
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No addid"))
		return
	}

	ul:=cache.GetValue(appid[0])
	if ul ==nil {
		err = errors.New("no this sid cache")
		return
	}

	userLogin ,ok := ul.(*UserLogin)
	if !ok{
		err = errors.New("assert fail")
		return
	}

	select {
	case <- userLogin.scan:
		w.Write([]byte(fmt.Sprintf("%s?code=%s&state=%s",userLogin.RedirectUrl,MockCode,userLogin.State))) //重定向地址
		return
	}

}

//扫码进入
func Authorize(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Access-Control-Allow-Origin", "*")
	var err error
	defer func() {
		if err != nil {
			w.WriteHeader(500)
			return
		}
	}()

	val := r.URL.Query()
	appid := val["appid"]
	if appid[0] == ""{
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No addid"))
		return
	}

	qrc:=cache.GetValue(appid[0])
	if qrc ==nil {
		err = errors.New("no this sid cache")
		return
		}

	qrcinfo ,ok := qrc.(*UserLogin)
	if !ok{
		err = errors.New("assert fail")
		return
	}

	qrcinfo.scan<-true
	w.WriteHeader(http.StatusOK)
	return
}

//请求微信登录
func Qrconnect(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Access-Control-Allow-Origin", "*")
	val := r.URL.Query()
	appid := val["appid"]
	if appid[0] == ""{
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No addid"))
		return
	}

	redirectUrl := val["redirect_uri"]
	if redirectUrl[0] == ""{
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No redirectUrl"))
		return
	}

	responseType := val["response_type"]
	Scope := val["scope"]
	State := val["state"]
	ul := &UserLogin{
		AppId:appid[0],
		RedirectUrl:redirectUrl[0],
		ResponseType:responseType[0],
		Scope:Scope[0],
		State:State[0],
		scan:make(chan bool),
	}

	cache.InsertCache(ul.AppId,ul)

	binPath, err := TBLogger.GetProDir()
	if err!=nil{
		return
	}
	dat, err := ioutil.ReadFile(binPath+"/main/res/index.html")
	if err != nil {
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte("Not Implemented."))
		return
	}
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	w.Header().Set("Cache-Control","no-cache")
	w.Write(dat)
}

func GenerateAccessToken(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Access-Control-Allow-Origin", "*")
	val := r.URL.Query()
	appid := val["appid"]
	if appid[0] == ""{
		w.WriteHeader(http.StatusBadRequest)
		TBLogger.TbLogger.Error("No appid")
		w.Write([]byte("No appid"))
		return
	}

	secret := val["secret"]
	if secret[0] == ""{
		w.WriteHeader(http.StatusBadRequest)
		TBLogger.TbLogger.Error("No secret")
		w.Write([]byte("No secret"))
		return
	}

	code := val["code"]
	if code[0] == ""{
		w.WriteHeader(http.StatusBadRequest)
		TBLogger.TbLogger.Error("No code")
		w.Write([]byte("No code"))
		return
	}

	if code[0] != MockCode{
		w.WriteHeader(http.StatusBadRequest)
		TBLogger.TbLogger.Error("code err")
		w.Write([]byte("code err"))
		return
	}

	authinfo := &AuthorizationInfo{
		AccessToken:GetRandomString(13),
		ExpiresIn:7200,
		RefreshToken:GetRandomString(16),
		OpenId:GetRandomString(14),
		Scope:"snsapi_login",
		UnionId:GetRandomString(12),
	}

	WeChatUser := &WeChatUserInfo{
		Openid:authinfo.OpenId,
		NickName:GetRandomString(5),
		Sex:1,
		Language:"zh_CN",
		Country:"广州",
		HeadImgUrl:"http://mockHeadimgUrl",
		Unionid:authinfo.UnionId,
	}

	aib ,err := json.Marshal(authinfo)
	if err!=nil{
		TBLogger.TbLogger.Error(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("json marshal err"))
	}

	cache.InsertCache(WeChatUser.Openid,WeChatUser)

	w.Write(aib)
}

func GetUserInfo(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Access-Control-Allow-Origin", "*")
	val := r.URL.Query()
	accessToken := val["access_token"]
	if accessToken[0] == ""{
		w.WriteHeader(http.StatusBadRequest)
		TBLogger.TbLogger.Error("No accessToken")
		w.Write([]byte("No accessToken"))
		return
	}

	OpenId := val["openid"]
	if OpenId[0] == ""{
		w.WriteHeader(http.StatusBadRequest)
		TBLogger.TbLogger.Error("No OpenId")
		w.Write([]byte("No OpenId"))
		return
	}

	Val := cache.GetValue(OpenId[0])
	if Val == nil{
		w.WriteHeader(http.StatusBadRequest)
		TBLogger.TbLogger.Error("No User")
		w.Write([]byte("No User"))
		return
	}

	User ,ok := Val.(*WeChatUserInfo)
	if !ok{
		w.WriteHeader(http.StatusBadRequest)
		TBLogger.TbLogger.Error("assert fail")
		w.Write([]byte("assert fail"))
		return
	}

	jsonUser,err := json.Marshal(User)
	if err!=nil{
		w.WriteHeader(http.StatusBadRequest)
		TBLogger.TbLogger.Error("json user  fail")
		w.Write([]byte("json user fail"))
		return
	}

	w.Write(jsonUser)

}

func main()  {
	initServer()
	predefineUser()
	r := mux.NewRouter()
	r.HandleFunc("/index",Index)
	r.HandleFunc("/qrcode", Qrcode)
	r.HandleFunc("/getsid",GetSid)
	r.HandleFunc("/redirect",Redirect)
	r.HandleFunc("/authorize", Authorize)
	r.HandleFunc("/sns/oauth2/access_token",GenerateAccessToken)
	r.HandleFunc("/sns/userinfo",GetUserInfo)
	SrcPath, err := TBLogger.GetProDir()
	r.HandleFunc("/qrconnect", Qrconnect)
	r.PathPrefix("/").Handler(http.StripPrefix("/", http.FileServer(http.Dir(SrcPath+"/main/res"))))
	TBLogger.TbLogger.Info("MockServe begin:8083")
	http.Handle("/", r)
	err = http.ListenAndServe(":8083", nil)
	if err != nil {
		log.Fatal("ListenAndServer: ", err)
	}

}

func  GetRandomString(l int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyz"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}
