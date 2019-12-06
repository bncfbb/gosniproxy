package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
)

func ReadClientHello(conn net.Conn) (*ClientHelloMsg, error) {
	//---------------------------Parse TLS Handshark Header------------------------
	buff, err := ReadFromConn(conn, 5)
	if err != nil {
		return nil, err
	}
	clientHelloRaw := bytes.NewBuffer(buff)

	msgtype := buff[0]
	if msgtype!=recordTypeHandshake {
		return nil, errors.New("not TLS protocol")
	}

	//version := int16(buff[1])<<8 | int16(buff[2])
	length := int16(buff[3])<<8 | int16(buff[4])

	/*self.logLocker.Lock()
	log.Println("-----------------------SSL Handshark START--------------------")
	log.Println("Type->", msgtype)
	log.Println("Version->", version)
	log.Println("Length->", length)
	log.Println("-----------------------SSL Handshark END--------------------")
	self.logLocker.Unlock()*/

	buff, err = ReadFromConn(conn, int(length))
	if err != nil {
		return nil, err
	}
	clientHelloRaw.Write(buff)
	//---------------------------Parse TLS Client Hello------------------------
	reader := bytes.NewReader(buff)

	var helloMsgType            byte
	var helloLength              uint16
	var helloSessionLen       byte
	var helloCipherSuitesLen   uint16
	var helloCompressMethodLen byte
	var helloExtensionLen       uint16
	//var hello_extension           map[uint16]

	helloMsgType, _ = reader.ReadByte()
	if helloMsgType!=typeClientHello {
		return nil, errors.New("not TLS protocol")
	}

	ClientHello := &ClientHelloMsg{
		Extensions: make(map[uint16][]byte),
		ClientHelloRaw: clientHelloRaw.Bytes(),
	}

	reader.UnreadByte()

	binary.Read(reader, binary.BigEndian, &helloLength)
	binary.Read(reader, binary.BigEndian, &helloLength)
	binary.Read(reader, binary.BigEndian, &ClientHello.TlsVersion)
	binary.Read(reader, binary.BigEndian, &ClientHello.Random)

	helloSessionLen, _ = reader.ReadByte()
	ClientHello.SessionId = make([]byte, helloSessionLen)
	binary.Read(reader, binary.BigEndian, &ClientHello.SessionId)


	binary.Read(reader, binary.BigEndian, &helloCipherSuitesLen)
	ClientHello.CipherSuites = make([]byte, helloCipherSuitesLen)
	binary.Read(reader, binary.BigEndian, &ClientHello.CipherSuites)

	helloCompressMethodLen, _ = reader.ReadByte()
	ClientHello.CompressMethod = make([]byte, helloCompressMethodLen)
	binary.Read(reader, binary.BigEndian, &ClientHello.CompressMethod)

	binary.Read(reader, binary.BigEndian, &helloExtensionLen)

	/*logLocker.Lock()
	log.Println("-----------------------TLS Client Hello START--------------------")
	log.Println("Type->", helloMsgType)
	log.Println("TLS Version->", self.ClientHello.TlsVersion)
	log.Println("Length->", helloLength)
	log.Println("Random->", self.ClientHello.Random)
	log.Println("Sessionid->", self.ClientHello.SessionId)
	log.Println("Cipher Suites->", self.ClientHello.CipherSuites)
	log.Println("Compress Methods->", self.ClientHello.CompressMethod)

	log.Println("Extensions Length->", helloExtensionLen)
	 */

	var extensionType  uint16
	var extensionLength  uint16
	var extension  []byte
	var num uint16


	for {
		binary.Read(reader, binary.BigEndian, &extensionType)
		binary.Read(reader, binary.BigEndian, &extensionLength)
		extension = make([]byte, extensionLength)
		binary.Read(reader, binary.BigEndian, &extension)

		ClientHello.Extensions[extensionType]=extension

		/*if extension_type==0 {
			log.Println("Extension SNI->", string(extension[5:]))
			hello_sni = string(extension[5:])
			//break
		} else {
			log.Println("Extension type->", extension_type, "   data->", extension)
		}*/

		num += 4 + extensionLength
		if num >= helloExtensionLen {
			break
		}
	}
	return ClientHello, nil
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

/*func NewClientHello(conn net.Conn, logLocker *sync.Mutex) (*ClientHello) {
	hello := &ClientHello{
		conn: conn,
		logLocker: logLocker,
	}
	hello.unmarshel()
	return hello
}*/
