package main

import (
	"./protocol"
	"io"
	"log"
	"net"
	"sync"
)

var logLocker *sync.Mutex

func main() {
	logLocker = new(sync.Mutex)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	listener, err := net.Listen("tcp", "0.0.0.0:443")
	if err != nil {
		log.Fatal(err)
	}

	//路由, 决定某个域名要转发到哪个后端ip
	routeMap := make(map[string]string)
	routeMap["c4code.cn"]="38.147.166.167:443"
	routeMap["www.x2code.cn"]="38.147.166.167:443"
	routeMap["blog.iqoo.moe"]="38.147.166.167:443"

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
			break
		}
		go func() {
			defer conn.Close()

			clientHello, err := protocol.ReadClientHello(conn)
			if err != nil {
				log.Print(err)
				return
			}

			log.Println("ClientHelloStruct->", clientHello)
			log.Println("ClientHelloStructRaw->", clientHello.ClientHelloRaw)

			//路由tcp转发
			sni := string(clientHello.Extensions[protocol.ExtensionServerName][5:])
			log.Println("SNI->", sni)

			ip := routeMap[sni]

			if len(ip)>0 {
				log.Println(conn.RemoteAddr(), "->", conn.LocalAddr(), "->", ip, "  开始转发Application Data")
				forward(conn, ip, clientHello.ClientHelloRaw)
				log.Println(conn.RemoteAddr(), "->", conn.LocalAddr(), "->", ip, "  连接关闭")
			} else {
				log.Println("SNI->", sni, "的路由不存在")
			}
		}()
	}
}

//tcp连接转发
func forward(sconn net.Conn, ip string, client_hello []byte) {
	defer sconn.Close()
	dconn, err := net.Dial("tcp", ip)
	if err != nil {
		log.Printf("连接%v失败:%v\n", ip, err)
		return
	}
	dconn.(*net.TCPConn).SetKeepAlive(true)
	dconn.Write(client_hello)
	ExitChan := make(chan bool, 1)
	go func(sconn net.Conn, dconn net.Conn, Exit chan bool) {
		io.Copy(dconn, sconn)
		ExitChan <- true
	}(sconn, dconn, ExitChan)
	go func(sconn net.Conn, dconn net.Conn, Exit chan bool) {
		io.Copy(sconn, dconn)
		ExitChan <- true
	}(sconn, dconn, ExitChan)
	<-ExitChan
	dconn.Close()
}


