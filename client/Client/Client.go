package Client

import (
	"bufio"
	cryRand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
)

type Client struct {
	serverAddr string
	serverPort string
	pubKey     string
	Username   string
}

func parseConfig(path string) map[string]string {
	config := make(map[string]string)

	f, err := os.Open(path)
	defer f.Close()
	if err != nil {
		panic(err)
	}

	r := bufio.NewReader(f)
	for {
		b, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}
		s := strings.TrimSpace(string(b))
		index := strings.Index(s, "=")
		if index < 0 {
			continue
		}
		config[strings.TrimSpace(s[:index])] = strings.TrimSpace(s[index+1:])
	}

	return config
}

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Int63()%int64(len(letters))]
	}
	return string(b)
}

func (client *Client) Init(configPath string) {
	config := parseConfig(configPath)
	client.serverAddr = config["server.addr"]
	client.serverPort = config["server.port"]
	client.pubKey = config["pub-key"]
	client.Username = config["user"]
}

func (client *Client) Connect() (net.Conn, string) {
	conn, err := net.Dial("tcp", client.serverAddr+":"+client.serverPort)
	if err != nil {
		panic(err)
	}
	conn.Write([]byte(client.Username + "\n"))
	reader := bufio.NewReader(conn)
	temp, err := reader.ReadString('\n')
	if err != nil || temp != "Deliver\n" {
		panic(err)
	}
	aesKey := randStr(16)
	f, err := os.Open(client.pubKey)
	defer f.Close()
	fInfo, err := os.Stat(client.pubKey)
	b := make([]byte, fInfo.Size())
	f.Read(b)

	bb, _ := pem.Decode(b)
	pub, err := x509.ParsePKIXPublicKey(bb.Bytes)
	data, err := rsa.EncryptPKCS1v15(cryRand.Reader, pub.(*rsa.PublicKey), []byte(aesKey))
	conn.Write(data)

	temp, err = reader.ReadString('\n')
	if temp == "OK\n" {
		return conn, aesKey
	} else {
		panic(err)
	}
}
