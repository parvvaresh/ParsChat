package server

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/username/tcp-chat/internal/config"
	"github.com/username/tcp-chat/internal/controllers"
	"github.com/username/tcp-chat/internal/routes"
	"github.com/username/tcp-chat/internal/services"
)

func Run(cfg config.Config) error {
	logger := log.New(os.Stdout, "[parschat] ", log.LstdFlags)

	service, err := services.NewChatService(cfg.DBPath, cfg.JWTSecret, logger)
	if err != nil {
		return err
	}

	controller := controllers.NewController(service)
	mux := http.NewServeMux()

	routes.Register(mux, controller)
	mux.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("./uploads"))))

	frontendRoot := "./public"
	frontendCandidates := []string{"./frontend/dist", "../frontend/dist", "./public"}
	for _, candidate := range frontendCandidates {
		if stat, statErr := os.Stat(candidate); statErr == nil && stat.IsDir() {
			frontendRoot = candidate
			break
		}
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}

		filePath := frontendRoot + path
		if _, err := os.Stat(filePath); err == nil {
			http.ServeFile(w, r, filePath)
			return
		}

		http.ServeFile(w, r, frontendRoot+"/index.html")
	})

	addr := fmt.Sprintf(":%s", cfg.Port)
	logger.Println("========================================")
	logger.Println("Chat Server Started!")
	logger.Printf("http://localhost:%s\n", cfg.Port)
	logger.Println("========================================")

	return http.ListenAndServe(addr, mux)
}
