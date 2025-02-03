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

	publicKeyOption := ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
		return true 
	})

	if err := ssh.ListenAndServe(":"+port, nil, publicKeyOption); err != nil {
		log.Fatal(err)
	}
}
