package main

import (
	"UCAS_SFC/server/Server"
)

func main() {
	configPath := "./config.ini"

	server := new(Server.Server)
	server.Init(configPath)
	server.Start()
}
