package main

import (
	"log"

	"abap34-server/internal/chat"
	"abap34-server/internal/db"

	"github.com/gliderlabs/ssh"
)

func main() {
	db.Init()

	ssh.Handle(chat.HandleSession)

	port := "2222"
	log.Printf("abap34's server starting on port %s...", port)

	if err := ssh.ListenAndServe(":"+port, nil, ssh.HostKeyFile("/data/ssh_host_key")); err != nil {
		log.Fatal(err)
	}
}
