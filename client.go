package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type Message struct {
	Type      string `json:"type"`
	First     string `json:"first,omitempty"`
	Last      string `json:"last,omitempty"`
	Text      string `json:"text,omitempty"`
	URL       string `json:"url,omitempty"`
	MediaType string `json:"mediaType,omitempty"`
}

func uploadFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	fw, err := w.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(fw, file); err != nil {
		return "", err
	}
	w.Close()

	resp, err := http.Post("http://localhost:8081/upload", w.FormDataContentType(), &b)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var data map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	return data["url"], nil
}

func detectMediaType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp":
		return "image"
	case ".mp4", ".mov", ".webm", ".mkv":
		return "video"
	default:
		return "file"
	}
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("First name: ")
	first, _ := reader.ReadString('\n')
	fmt.Print("Last name: ")
	last, _ := reader.ReadString('\n')
	first = strings.TrimSpace(first)
	last = strings.TrimSpace(last)

	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}
	defer conn.Close()

	// send register message
	reg := Message{Type: "register", First: first, Last: last}
	b, _ := json.Marshal(reg)
	fmt.Fprintln(conn, string(b))

	// listen for messages
	go func() {
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			var msg Message
			if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
				fmt.Println(string(scanner.Bytes()))
				continue
			}
			switch msg.Type {
			case "info":
				fmt.Println(msg.Text)
			case "text":
				fmt.Printf("[%s]: %s\n", msg.First, msg.Text)
			case "media":
				fmt.Printf("[%s] sent %s: %s\n", msg.First, msg.MediaType, msg.URL)
			default:
				fmt.Println(scanner.Text())
			}
		}
	}()

	input := bufio.NewScanner(os.Stdin)
	for input.Scan() {
		line := strings.TrimSpace(input.Text())
		if strings.HasPrefix(line, "/upload ") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "/upload "))
			if path == "" {
				fmt.Println("usage: /upload <file-path>")
				continue
			}
			url, err := uploadFile(path)
			if err != nil {
				fmt.Println("upload failed:", err)
				continue
			}
			mediaType := detectMediaType(path)
			msg := Message{Type: "media", URL: url, MediaType: mediaType}
			jb, _ := json.Marshal(msg)
			fmt.Fprintln(conn, string(jb))
		} else {
			msg := Message{Type: "text", Text: line}
			jb, _ := json.Marshal(msg)
			fmt.Fprintln(conn, string(jb))
		}
	}
}
