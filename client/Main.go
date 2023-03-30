package main

import (
	"UCAS_SFC/client/Client"
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"io"
	"io/ioutil"
	"net"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	app := app.NewWithID("UCAS_SFC")
	window := app.NewWindow("UCAS_SFC")

	client := new(Client.Client)
	client.Init("./config.ini")
	conn, aesKey := client.Connect()
	defer func() {
		conn.Write([]byte("Exit\n"))
		conn.Close()
	}()

	windowC := windowContent(aesKey, conn, window, client.Username)
	window.SetContent(windowC)

	window.Resize(fyne.NewSize(640*1.4, 640))
	window.SetMaster()
	window.ShowAndRun()
}

func unpackList(files string) []string {
	splitChar := string(0xff)
	return strings.Split(files, splitChar)
}

func getFileList(con net.Conn) []string {
	con.Write([]byte("List\n"))
	packedFileList, err := bufio.NewReader(con).ReadString('\n')
	if err != nil {
		panic(err)
	}
	return unpackList(strings.TrimSuffix(packedFileList, "\n"))
}

func handleUpload(key string, data []byte, con net.Conn, filename string) error {
	con.Write([]byte("Upload\n"))
	port, err := bufio.NewReader(con).ReadString('\n')
	if err != nil {
		return err
	}
	port = strings.TrimSuffix(port, "\n")
	uploadA := strings.Split(con.RemoteAddr().String(), ":")
	uploadAddr := uploadA[0] + ":" + port
	uploadCon, err := net.Dial("tcp", uploadAddr)
	if err != nil {
		return err
	}
	uploadCon.Write([]byte(filename + "\n"))
	message, err := bufio.NewReader(uploadCon).ReadString('\n')
	if err != nil {
		return err
	}
	if message == "FileData\n" {
		c, err := aes.NewCipher([]byte(key))
		if err != nil {
			return err
		}
		gcm, err := cipher.NewGCM(c)
		if err != nil {
			return err
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			return err
		}
		fileData := gcm.Seal(nonce, nonce, data, nil)
		endChar := string(0xff)
		fileData = []byte(string(fileData) + endChar)
		_, err = uploadCon.Write(fileData)
		if err != nil {
			return err
		}
	} else {
		return io.ErrNoProgress
	}
	for {
		message, err := bufio.NewReader(uploadCon).ReadString('\n')
		if err != nil {
			if err == io.EOF {
				continue
			} else {
				return err
			}
		}
		if message == "END\n" {
			break
		}
	}
	return nil
}

func windowContent(aesKey string, con net.Conn, w fyne.Window, username string) fyne.CanvasObject {
	success := widget.NewLabel("Successfully Connected to " + con.RemoteAddr().String() + " as " + username)
	var fileList []string
	fileList = getFileList(con)
	head := container.NewGridWithColumns(1, widget.NewLabel("Files"))

	showFileList := widget.NewList(func() int { return len(fileList) }, func() fyne.CanvasObject {
		gc := container.NewGridWithColumns(1)
		gc.Add(widget.NewLabel("Field 1"))
		return gc
	}, func(id widget.ListItemID, object fyne.CanvasObject) {
		gc := object.(*fyne.Container)
		lb0 := gc.Objects[0].(*widget.Label)
		lb0.SetText(fileList[id])
	})

	go func() {
		for range time.Tick(30 * time.Second) {
			fileList = getFileList(con)
			showFileList.Refresh()
		}
	}()
	uploadButton := widget.NewButton("Upload", func() {
		fileSelector := dialog.NewFileOpen(func(closer fyne.URIReadCloser, e error) {
			if closer == nil {
				return
			}
			data, _ := ioutil.ReadAll(closer)
			err := handleUpload(aesKey, data, con, filepath.Base(closer.URI().String()))
			if err == nil {
				dialog.ShowInformation("Message", "upload success!", w)
				fileList = getFileList(con)
				showFileList.Refresh()
			} else {
				fmt.Print(err)
				dialog.ShowInformation("Message", "Something Wrong!", w)
			}
		}, w)
		fileSelector.Show()
	})

	ss := container.NewBorder(head, nil, nil, nil, showFileList)
	vs := container.NewVSplit(success, uploadButton)
	return container.NewVSplit(vs, ss)
}
