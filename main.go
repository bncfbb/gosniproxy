package main

import (
	"bytes"
	"encoding/binary"
	"github.com/kataras/iris/core/errors"
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

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
			break
		}
		go func() {

			//---------------------------Parse TLS Handshark Header------------------------
			buff, err := ReadFromConn(conn, 5)
			if err != nil {
				return
			}

			client_hello_packet := bytes.NewBuffer(buff)

			msgtype := buff[0]
			version := int16(buff[1])<<8 | int16(buff[2])
			length := int16(buff[3])<<8 | int16(buff[4])

			logLocker.Lock()
			log.Println("-----------------------SSL Handshark START--------------------")
			log.Println("Type->", msgtype)
			log.Println("Version->", version)
			log.Println("Length->", length)
			log.Println("-----------------------SSL Handshark END--------------------")
			logLocker.Unlock()

			buff, err = ReadFromConn(conn, int(length))
			if err != nil {
				return
			}
			client_hello_packet.Write(buff)

			//---------------------------Parse TLS Client Hello------------------------


			reader := bytes.NewReader(buff)

			var hello_msgtype             byte
			var hello_length              uint16
			var hello_tls_version         uint16
			var hello_random              [32]byte
			var hello_sessionid_len       byte
			var hello_sessionid           []byte
			var hello_cipher_suites_len   uint16
			var hello_cipher_suites       []byte
			var hello_compress_method_len byte
			var hello_compress_method     []byte
			var hello_extension_len       uint16
			//var hello_extension           map[uint16]

			hello_msgtype, _ = reader.ReadByte()

			reader.UnreadByte()

			binary.Read(reader, binary.BigEndian, &hello_length)
			binary.Read(reader, binary.BigEndian, &hello_length)
			binary.Read(reader, binary.BigEndian, &hello_tls_version)
			binary.Read(reader, binary.BigEndian, &hello_random)

			hello_sessionid_len, _ = reader.ReadByte()
			hello_sessionid = make([]byte, hello_sessionid_len)
			binary.Read(reader, binary.BigEndian, &hello_sessionid)


			binary.Read(reader, binary.BigEndian, &hello_cipher_suites_len)
			hello_cipher_suites = make([]byte, hello_cipher_suites_len)
			binary.Read(reader, binary.BigEndian, &hello_cipher_suites)


			hello_compress_method_len, _ = reader.ReadByte()
			hello_compress_method = make([]byte, hello_compress_method_len)
			binary.Read(reader, binary.BigEndian, &hello_compress_method)

			binary.Read(reader, binary.BigEndian, &hello_extension_len)


			logLocker.Lock()
			log.Println("-----------------------TLS Client Hello START--------------------")
			log.Println("Type->", hello_msgtype)
			log.Println("TLS Version->", hello_tls_version)
			log.Println("Length->", hello_length)
			log.Println("Random->", hello_random)
			log.Println("Sessionid->", hello_sessionid)
			log.Println("Cipher Suites->", hello_cipher_suites)
			log.Println("Compress Methods->", hello_compress_method)

			log.Println("Extensions Length->", hello_extension_len)

			var extension_type  uint16
			var extension_length  uint16
			var extension  []byte
			var num uint16

			var hello_sni string

			for {
				binary.Read(reader, binary.BigEndian, &extension_type)
				binary.Read(reader, binary.BigEndian, &extension_length)
				extension = make([]byte, extension_length)
				binary.Read(reader, binary.BigEndian, &extension)

				if extension_type==0 {
					log.Println("Extension SNI->", string(extension[5:]))
					hello_sni = string(extension[5:])
					//break
				} else {
					log.Println("Extension type->", extension_type, "   data->", extension)
				}

				num += 4 + extension_length
				if num >= hello_extension_len {
					break
				}
			}

			log.Println("-----------------------TLS Client Hello END--------------------")
			logLocker.Unlock()

			//路由tcp转发
			ip := routeMap[hello_sni]
			if len(ip)>0 {
				forward(conn, ip, client_hello_packet.Bytes())
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
		_, err := io.Copy(dconn, sconn)
		log.Printf("往%v发送数据失败:%v\n", ip, err)
		ExitChan <- true
	}(sconn, dconn, ExitChan)
	go func(sconn net.Conn, dconn net.Conn, Exit chan bool) {
		_, err := io.Copy(sconn, dconn)
		log.Printf("从%v接收数据失败:%v\n", ip, err)
		ExitChan <- true
	}(sconn, dconn, ExitChan)
	<-ExitChan
	dconn.Close()
}

//从conn中读取特定长的的数据
func ReadFromConn(conn net.Conn, length int) ([]byte, error) {
	buff := make([]byte, length)
	l, err := conn.Read(buff)
	if err != nil {
		return nil, err
	}
	if l!=length {
		return nil, errors.New("unexpected read length!")
	}
	return buff, nil
}
