package main

import (
	"log"

	"github.com/username/tcp-chat/internal/config"
	"github.com/username/tcp-chat/internal/server"
)

func main() {
	cfg := config.Load()
	if err := server.Run(cfg); err != nil {
		log.Fatal(err)
	}
}
