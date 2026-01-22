package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Message is the JSON structure exchanged between client and server
type Message struct {
	Type      string `json:"type"`
	First     string `json:"first,omitempty"`
	Last      string `json:"last,omitempty"`
	Text      string `json:"text,omitempty"`
	URL       string `json:"url,omitempty"`
	MediaType string `json:"mediaType,omitempty"`
}

// Store connected clients with their display name
var clients = make(map[net.Conn]string)

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// default name until registration
	clients[conn] = conn.RemoteAddr().String()
	fmt.Fprintf(conn, "{\"type\":\"info\",\"text\":\"Connected. Send a register message with type=register, first and last.\"}\n")

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Bytes()
		var msg Message
		if err := json.Unmarshal(line, &msg); err != nil {
			// ignore invalid JSON
			continue
		}

		switch msg.Type {
		case "register":
			name := strings.TrimSpace(msg.First + " " + msg.Last)
			if name == "" {
				name = conn.RemoteAddr().String()
			}
			clients[conn] = name
			// confirm to this client
			resp := Message{Type: "info", Text: "Registered as: " + name}
			sendJSON(conn, resp)
		case "text", "media":
			// attach sender name and broadcast
			broadcastMsg := Message{
				Type:      msg.Type,
				First:     clients[conn],
				Text:      msg.Text,
				URL:       msg.URL,
				MediaType: msg.MediaType,
			}
			broadcast(conn, broadcastMsg)
		default:
			// unknown type - ignore
		}
	}

	delete(clients, conn)
}

func sendJSON(conn net.Conn, msg Message) {
	b, _ := json.Marshal(msg)
	fmt.Fprint(conn, string(b)+"\n")
}

// Broadcast a message to all clients except the sender
func broadcast(sender net.Conn, message Message) {
	for client := range clients {
		if client != sender {
			sendJSON(client, message)
		}
	}
}

// uploadHandler accepts multipart form file field "file" and saves it under ./uploads
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(50 << 20) // 50MB
	if err != nil {
		http.Error(w, "failed to parse multipart form", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file field is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if _, err := os.Stat("uploads"); os.IsNotExist(err) {
		os.Mkdir("uploads", 0755)
	}

	ext := filepath.Ext(header.Filename)
	safeName := fmt.Sprintf("%d%s", time.Now().UnixNano(), ext)
	dstPath := filepath.Join("uploads", safeName)
	dst, err := os.Create(dstPath)
	if err != nil {
		http.Error(w, "failed to save file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "failed to save file", http.StatusInternalServerError)
		return
	}

	// build file URL using the request Host
	fileURL := fmt.Sprintf("http://%s/uploads/%s", r.Host, safeName)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"url": fileURL})
}

func main() {
	// Start HTTP server for uploads and static files on 8081
	http.HandleFunc("/upload", uploadHandler)
	fs := http.FileServer(http.Dir("uploads"))
	http.Handle("/uploads/", http.StripPrefix("/uploads/", fs))
	go func() {
		fmt.Println("HTTP upload server running on :8081 (uploads at /uploads/)")
		if err := http.ListenAndServe(":8081", nil); err != nil {
			fmt.Println("HTTP server error:", err)
			os.Exit(1)
		}
	}()

	// Start TCP server on port 8080
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("Error starting server:", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Println("TCP chat server is running on port 8080...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go handleConnection(conn)
	}
}
