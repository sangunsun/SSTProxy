/*加密传输的proxy，采用RC4加密，
 */
package main

import (
	"bufio"
	"crypto/rc4"
	"flag"
	"fmt"
	"github.com/buger/jsonparser"
	"time"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type Rc4 struct {
	C *rc4.Cipher
}

var pwd string = "helloworld"
var ffilename = flag.String("f", "config.json", "配置文件名")
var port string
var fileName string
var httpLen int = 4096

func init() {

	flag.Parse()
	fileName = *ffilename
}

func main() {
	f, err := os.Open(getProcessDir() + fileName)
	if err != nil {
		f, err = os.Open(fileName)
		if err != nil {
			fmt.Println("打开配置文件失败")
			return
		}
	}
	var jsondata []byte
	var buf = make([]byte, 1)
	for n, err := f.Read(buf); err == nil && n > 0; n, err = f.Read(buf) {
		jsondata = append(jsondata, buf[0])
	}
	port, err = jsonparser.GetString(jsondata, "localPort")
	if err != nil {
		fmt.Println("配置文件中无服务端口号", port, err)
		return
	}
	port = ":" + port
	pwd, err = jsonparser.GetString(jsondata, "password")
	if err != nil {
		fmt.Println("配置文件中无密码", err)
		return
	}
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	tcpaddr, err := net.ResolveTCPAddr("tcp4", port)
	if err != nil {
		fmt.Println("侦听地址错", tcpaddr, err)
		return
	}
	tcplisten, err := net.ListenTCP("tcp", tcpaddr)
	if err != nil {
		fmt.Println("开始tcp侦听出错", err)
	}
	fmt.Println("hps服务运行于", port)
	for {
		client, err := tcplisten.AcceptTCP()
		if err != nil {
			log.Println("当前协程数量：", runtime.NumGoroutine())
			log.Panic(err)
		}

		log.Println("当前协程数量：", runtime.NumGoroutine())
		go handleAServerConn(client)
	}
}
func handleAServerConn(client *net.TCPConn) {

	defer client.Close()
	c1, _ := rc4.NewCipher([]byte(pwd))
	c2, _ := rc4.NewCipher([]byte(pwd))

	pcTos := &Rc4{c1} //从client端收到的是密文，这里的作用是解密
	psToc := &Rc4{c2} //web服务器传过来的是明文，这里的作用是加密

	if client == nil {
		return
	}
	//对客户端传来的密文进行解密，得到http报头, 得到web服务器的ip、端口等信息
	byteHeader := deCodereadSplitString(client, pcTos, []byte("\r\n\r\n"))
	fmt.Println("原始报头信息：", string(byteHeader))

	//取报头字节流后解析为结构化报头，方便获取想要的信息
	bfr := bufio.NewReader(strings.NewReader(string(byteHeader)))
	req, err := http.ReadRequest(bfr)
	if err != nil {
		log.Println("转换request失败", err)
		return
	}
	var method, host, address string
	method = req.Method
	host = req.Host
	//hostPortURL, err := url.Parse(host)
	fmt.Println("取request信息m:", method, "host:", host) //, "hostPortURL:", hostPortURL)
	if err != nil {
		log.Println(err)
		return
	}
	//取服务器域名（或IP）和端口号以便tcp拨号服务器
	hostPort := strings.Split(host, ":")
	if len(hostPort) < 2 {
		address = hostPort[0] + ":80"
	} else {
		address = host
	}

	fmt.Println("获得服务器地址address:", address)
	//获得了请求的host和port，就开始拨号吧
	tcpaddr, err := net.ResolveTCPAddr("tcp4", address)
	if err != nil {
		log.Println("tcp地址错误", address, err)
		return
	}
	server, err := net.DialTCP("tcp", nil, tcpaddr)
	if err != nil {
		log.Println(err)
		return
	}
	if method == "CONNECT" {
		bufTemp := []byte("HTTP/1.1 200 Connection established\r\n\r\n")
		psToc.C.XORKeyStream(bufTemp, bufTemp)
		client.Write(bufTemp)
	} else {
		server.Write(byteHeader[0:len(byteHeader)]) //最始的报头信息已经解密了，这里直接转发给web
	}
	//接下来得到的都是还没有解密的信息，进行解密转发
	go pcTos.encryptCopy(server, client) //服务端收到的是密文，编码后就成了明文并传给web
	psToc.encryptCopy(client, server)    //web发过来的是明文，编码后就成了密文，并传给客户端
	server.Close()  //这句倒是否是必要的？？？？
}

func deCodereadSplitString(r *net.TCPConn, coder *Rc4, delim []byte) []byte {
	var rs []byte
	lenth := len(delim)
	curByte := make([]byte, 1)

	//先读取分隔符长度-1个字节，以避免在下面循环中每次都要判断是否读够分隔符长度的字节。
	for k := 0; k < lenth-1; k++ {
		r.Read(curByte)
		coder.C.XORKeyStream(curByte, curByte) //把密文转成明文
		rs = append(rs, curByte[0])
		if len(rs) > httpLen {
			return rs
		}
	}

	//继续读后面的字节并开始进行查找是否已经接收到报头正文分隔符
	for n, err := r.Read(curByte); err == nil && n > 0; n, err = r.Read(curByte) {
		coder.C.XORKeyStream(curByte, curByte)
		rs = append(rs, curByte[0])
		if len(rs) > httpLen {
			return rs
		}
		var m int
		//从后向前逐个字节比较已读字节的最后几位是否和分隔符相同
		for m = 0; m < lenth; m++ {
			tt := len(rs)
			if rs[tt-1-m] != delim[lenth-1-m] {
				break
			}
		}
		if m == lenth {
			return rs
		}
	}
	return rs
}
  func (c *Rc4) encryptCopy(dst *net.TCPConn, src *net.TCPConn) {
      defer dst.Close()
      defer src.Close()
      buf := make([]byte, 4096)
      var err error
      n := 0
      for n, err = src.Read(buf); err == nil && n > 0; n, err = src.Read(buf) {
          //5秒无数据传输就断掉连接
          dst.SetDeadline(time.Now().Add(time.Second * 5))
          src.SetDeadline(time.Now().Add(time.Second * 5))
          c.C.XORKeyStream(buf[:n], buf[:n])

          dst.Write(buf[:n])
      }

  }
func getProcessDir() string {
	file, _ := exec.LookPath(os.Args[0])

	path, _ := filepath.Abs(file)

	if runtime.GOOS == "windows" {
		path = strings.Replace(path, "\\", "/", -1)
	}

	i := strings.LastIndex(path, "/")
	return string(path[0 : i+1])
}
