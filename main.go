package main

import (
	"fmt"
	"ss5server/socks"
	"ss5server/user"
)

func main() {
	ss5server()
}

func ss5server() {
	ssc := &socks.SocksServerConfig{
		MaxConnections:     1000,
		ConnectTimeout:     60,
		ListenIP:           "0.0.0.0",
		ListenPort:         1188,
		RequiredAuth:       true,
		UserAuthentication: user.NewAuth(),
	}

	server, err := socks.NewServer(ssc)
	if err != nil {
		fmt.Println(err)
		return
	}

	server.Run()
}
