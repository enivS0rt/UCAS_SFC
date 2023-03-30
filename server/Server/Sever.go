package Server

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type Server struct {
	addr      string
	port      string
	secKeyDir string
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

func checkUser(userPath string) bool {
	_, err := os.Stat(userPath)
	if err == nil {
		return true
	}
	return false
}

func decodeKey(c []byte, userPath string) (string, error) {
	f, err := os.Open(userPath)
	defer f.Close()
	if err != nil {
		return "", err
	}

	fInfo, err := os.Stat(userPath)
	b := make([]byte, fInfo.Size())
	f.Read(b)

	bb, _ := pem.Decode(b)
	sec, err := x509.ParsePKCS1PrivateKey(bb.Bytes)
	res, err := rsa.DecryptPKCS1v15(rand.Reader, sec, c)
	return string(res), err
}

func listFile(username string) []string {
	h := md5.Sum([]byte(username))
	hash := hex.EncodeToString(h[:])
	hash = "./uploads/" + hash
	res := make([]string, 0)
	_, err := os.Stat(hash)
	if err != nil {
		os.MkdirAll(hash, os.ModePerm)
	}
	err = filepath.Walk(hash, func(path string, info fs.FileInfo, err error) error {
		res = append(res, path)
		return nil
	})

	if err != nil {
		panic(err)
	}

	return res[1:]
}

func packList(files []string) []byte {
	res := ""
	splitChar := string(0xff)
	for _, value := range files {
		res = res + path.Base(value) + splitChar
	}
	res = res + "\n"
	return []byte(res)
}

func handleConnect(con net.Conn, secKeyDir string) {
	defer con.Close()
	remote := "[" + con.RemoteAddr().String() + "]"
	fmt.Println("Got connection from " + con.RemoteAddr().String())
	fmt.Println(remote + "checking user")
	reader := bufio.NewReader(con)

	username, err := reader.ReadString('\n')
	username = strings.TrimSuffix(username, "\n")
	if err != nil {
		fmt.Println(remote + "Encountered some error! Closing connection")
		return
	}
	userPath := secKeyDir + username + ".sec"
	if !checkUser(userPath) {
		fmt.Println(remote + "No such user! Closing connection")
		return
	}
	fmt.Println(remote + "User exist! Delivering Secret Key")
	code := "Deliver\n"
	_, err = con.Write([]byte(code))
	if err != nil {
		fmt.Println(remote + "Encountered some error! Closing connection")
		return
	}

	c := make([]byte, 256)
	con.Read(c[:])

	if err != nil {
		fmt.Println(remote + "Encountered some error! Closing connection")
		return
	}
	key, err := decodeKey(c, userPath)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(remote + "Connection Established")
	con.Write([]byte("OK\n"))
	for {
		data, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				continue
			} else {
				fmt.Println(err)
				return
			}
		}
		temp := strings.TrimSuffix(data, "\n")
		if temp == "Exit" {
			fmt.Println(remote + "Received Exit message! Closing connection")
			return
		}
		if temp == "Upload" {
			// open new tcp connection to handle file upload
			addr, _ := net.ResolveTCPAddr("tcp", "localhost:0")
			listen, err := net.ListenTCP("tcp", addr)
			em := "[" + username + "]"
			if err != nil {
				fmt.Println(em + "error while uploading")
				panic(err)
			}
			a := strings.Split(listen.Addr().String(), ":")
			port := a[1]
			con.Write([]byte(port + "\n"))
			go handleUpload(username, key, listen)
		}
		if temp == "List" {
			fmt.Println(remote + "Listing file")
			files := listFile(username)
			fl := packList(files)
			_, err = con.Write(fl)
			if err != nil {
				fmt.Println(remote + "Encountered some error! Closing connection")
				return
			}
		}
	}
}

func handleUpload(username string, key string, listen *net.TCPListener) {
	defer listen.Close()
	em := "[" + username + "]"
	for {
		con, err := listen.Accept()
		if err != nil {
			continue
		}
		reader := bufio.NewReader(con)
		filename, err := reader.ReadString('\n')
		filename = strings.TrimSuffix(filename, "\n")
		if err != nil || filename == "" {
			panic(err)
		}
		h := md5.Sum([]byte(username))
		hash := hex.EncodeToString(h[:])
		hash = "./uploads/" + hash
		_, err = os.Stat(hash)
		if err != nil {
			os.MkdirAll(hash, os.ModePerm)
		}
		fp := hash + "/" + filename
		con.Write([]byte("FileData\n"))
		fdb := make([]byte, 64)
		fde := make([]byte, 0)
		for {
			n, err := con.Read(fdb[:])
			endChar := string(0xff)
			if string(fdb[n-2:n]) == endChar {
				fde = append(fde, fdb[:n-2]...)
				break
			}
			if err != nil {
				fmt.Println(em + "error while uploading")
				panic(err)
			}
			fde = append(fde, fdb[:n]...)
		}

		// aes decode
		c, err := aes.NewCipher([]byte(key))
		if err != nil {
			fmt.Println(err)
		}
		gcm, err := cipher.NewGCM(c)
		if err != nil {
			fmt.Println(err)
		}
		nonceS := gcm.NonceSize()
		if err != nil {
			fmt.Println(err)
		}
		nonce, ciphertext := fde[:nonceS], fde[nonceS:]
		fd, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			fmt.Println(err)
		}

		// write file
		err = os.WriteFile(fp, fd, 0666)
		if err != nil {
			fmt.Println(em + "error while uploading")
			panic(err)
		}
		con.Write([]byte("END\n"))
		con.Close()
		break
	}
}

func (server *Server) Init(path string) {
	config := parseConfig(path)
	server.addr = config["server.addr"]
	server.port = config["server.port"]
	server.secKeyDir = config["secKey-dir"]
}

func (server *Server) Start() {
	listen, err := net.Listen("tcp", server.addr+":"+server.port)
	if err != nil {
		panic(err)
	}
	fmt.Println("Server running at " + server.addr + ":" + server.port)
	for {
		con, err := listen.Accept()
		if err != nil {
			fmt.Print(err)
			continue
		}
		go handleConnect(con, server.secKeyDir)
	}
}
