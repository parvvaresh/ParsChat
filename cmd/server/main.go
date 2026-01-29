package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	db      *sql.DB
	clients = make(map[int]*Client)
	mu      sync.RWMutex
)

// Client represents a connected user
type Client struct {
	ID       int
	Username string
	Messages chan []byte
	Done     chan bool
}

// User represents a user in the database
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	FullName string `json:"fullName"`
}

// Message represents a chat message
type Message struct {
	Type      string `json:"type"`
	Content   string `json:"content,omitempty"`
	From      int    `json:"from,omitempty"`
	To        int    `json:"to,omitempty"`
	GroupID   int    `json:"groupId,omitempty"`
	MediaURL  string `json:"mediaUrl,omitempty"`
	MediaType string `json:"mediaType,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
}

// Group represents a chat group
type Group struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Creator int    `json:"creator"`
}

// initDB initializes the SQLite database and creates tables
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./chat.db")
	if err != nil {
		log.Fatal(err)
	}

	// Create users table
	db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		full_name TEXT NOT NULL,
		password TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)

	// Create groups table
	db.Exec(`CREATE TABLE IF NOT EXISTS groups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		creator_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)

	// Create group members table
	db.Exec(`CREATE TABLE IF NOT EXISTS group_members (
		group_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY(group_id, user_id)
	)`)

	// Create messages table
	db.Exec(`CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		from_user INTEGER NOT NULL,
		to_user INTEGER,
		group_id INTEGER,
		content TEXT,
		media_url TEXT,
		media_type TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)

	log.Println("[OK] Database initialized")
}

// hashPassword creates a SHA256 hash of the password
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password + "chat_salt_2024"))
	return hex.EncodeToString(hash[:])
}

// enableCORS sets CORS headers for cross-origin requests
func enableCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

// registerHandler handles user registration
func registerHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	var req struct {
		Username string `json:"username"`
		FullName string `json:"fullName"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	hash := hashPassword(req.Password)

	result, err := db.Exec("INSERT INTO users (username, full_name, password) VALUES (?, ?, ?)",
		req.Username, req.FullName, hash)
	if err != nil {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	id, _ := result.LastInsertId()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       id,
		"username": req.Username,
		"fullName": req.FullName,
	})
}

// loginHandler handles user authentication
func loginHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var user User
	var storedHash string
	err := db.QueryRow("SELECT id, username, full_name, password FROM users WHERE username = ?",
		req.Username).Scan(&user.ID, &user.Username, &user.FullName, &storedHash)

	if err != nil || hashPassword(req.Password) != storedHash {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
		"fullName": user.FullName,
	})
}

// getUsersHandler returns list of all users
func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	rows, err := db.Query("SELECT id, username, full_name FROM users ORDER BY username")
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.FullName)
		users = append(users, u)
	}

	if users == nil {
		users = []User{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// createGroupHandler creates a new chat group
func createGroupHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	var req struct {
		Name      string `json:"name"`
		CreatorID int    `json:"creatorId"`
		MemberIDs []int  `json:"memberIds"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	tx, _ := db.Begin()
	result, err := tx.Exec("INSERT INTO groups (name, creator_id) VALUES (?, ?)",
		req.Name, req.CreatorID)
	if err != nil {
		tx.Rollback()
		http.Error(w, "Failed to create group", http.StatusInternalServerError)
		return
	}

	groupID, _ := result.LastInsertId()

	// Add creator as member
	tx.Exec("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)",
		groupID, req.CreatorID)

	// Add other members
	for _, memberID := range req.MemberIDs {
		tx.Exec("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)",
			groupID, memberID)
	}

	tx.Commit()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":   groupID,
		"name": req.Name,
	})
}

// getGroupsHandler returns groups for a specific user
func getGroupsHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	userID := r.URL.Query().Get("userId")
	rows, err := db.Query(`
		SELECT DISTINCT g.id, g.name, g.creator_id 
		FROM groups g 
		JOIN group_members gm ON g.id = gm.group_id 
		WHERE gm.user_id = ?
		ORDER BY g.name`, userID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var g Group
		rows.Scan(&g.ID, &g.Name, &g.Creator)
		groups = append(groups, g)
	}

	if groups == nil {
		groups = []Group{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(groups)
}

// getMessagesHandler returns messages for private or group chat
func getMessagesHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	userID, _ := strconv.Atoi(r.URL.Query().Get("userId"))
	contactID, _ := strconv.Atoi(r.URL.Query().Get("contactId"))
	groupID, _ := strconv.Atoi(r.URL.Query().Get("groupId"))

	var rows *sql.Rows
	var err error

	if groupID > 0 {
		// Get group messages
		rows, err = db.Query(`
			SELECT id, from_user, to_user, group_id, content, media_url, media_type, 
			       strftime('%s', timestamp) as ts
			FROM messages 
			WHERE group_id = ?
			ORDER BY timestamp ASC
			LIMIT 100`, groupID)
	} else {
		// Get private messages between two users
		rows, err = db.Query(`
			SELECT id, from_user, to_user, group_id, content, media_url, media_type,
			       strftime('%s', timestamp) as ts
			FROM messages 
			WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)
			ORDER BY timestamp ASC
			LIMIT 100`, userID, contactID, contactID, userID)
	}

	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var m Message
		var id int
		var toUser, groupIDVal sql.NullInt64
		var content, mediaURL, mediaType sql.NullString
		rows.Scan(&id, &m.From, &toUser, &groupIDVal, &content, &mediaURL, &mediaType, &m.Timestamp)
		if toUser.Valid {
			m.To = int(toUser.Int64)
		}
		if groupIDVal.Valid {
			m.GroupID = int(groupIDVal.Int64)
		}
		if content.Valid {
			m.Content = content.String
		}
		if mediaURL.Valid {
			m.MediaURL = mediaURL.String
		}
		if mediaType.Valid {
			m.MediaType = mediaType.String
		}
		m.Type = "message"
		messages = append(messages, m)
	}

	if messages == nil {
		messages = []Message{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

// uploadHandler handles file uploads
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	err := r.ParseMultipartForm(50 << 20) // 50MB max
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "File field required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Create uploads directory if not exists
	os.MkdirAll("uploads", 0755)

	// Generate unique filename
	ext := filepath.Ext(header.Filename)
	filename := fmt.Sprintf("%d%s", time.Now().UnixNano(), ext)
	dst, err := os.Create(filepath.Join("uploads", filename))
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	io.Copy(dst, file)

	url := fmt.Sprintf("/uploads/%s", filename)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"url": url})
}

// sseHandler handles Server-Sent Events for real-time messaging
func sseHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.Atoi(r.URL.Query().Get("userId"))
	if userID == 0 {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Create client
	client := &Client{
		ID:       userID,
		Messages: make(chan []byte, 100),
		Done:     make(chan bool),
	}

	// Register client
	mu.Lock()
	clients[userID] = client
	mu.Unlock()

	// Cleanup on disconnect
	defer func() {
		mu.Lock()
		delete(clients, userID)
		mu.Unlock()
	}()

	// Send initial connection message
	fmt.Fprintf(w, "data: {\"type\":\"connected\"}\n\n")
	flusher.Flush()

	// Listen for messages
	for {
		select {
		case msg := <-client.Messages:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-r.Context().Done():
			return
		case <-client.Done:
			return
		}
	}
}

// sendMessageHandler handles sending messages
func sendMessageHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	var msg Message
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	msg.Timestamp = time.Now().Unix()

	// Save message to database
	if msg.GroupID > 0 {
		// Group message
		db.Exec("INSERT INTO messages (from_user, group_id, content, media_url, media_type) VALUES (?, ?, ?, ?, ?)",
			msg.From, msg.GroupID, msg.Content, msg.MediaURL, msg.MediaType)

		// Send to all group members
		rows, _ := db.Query("SELECT user_id FROM group_members WHERE group_id = ?", msg.GroupID)
		for rows.Next() {
			var memberID int
			rows.Scan(&memberID)
			if memberID != msg.From {
				mu.RLock()
				if client, ok := clients[memberID]; ok {
					data, _ := json.Marshal(msg)
					select {
					case client.Messages <- data:
					default:
					}
				}
				mu.RUnlock()
			}
		}
		rows.Close()
	} else {
		// Private message
		db.Exec("INSERT INTO messages (from_user, to_user, content, media_url, media_type) VALUES (?, ?, ?, ?, ?)",
			msg.From, msg.To, msg.Content, msg.MediaURL, msg.MediaType)

		// Send to recipient
		mu.RLock()
		if client, ok := clients[msg.To]; ok {
			data, _ := json.Marshal(msg)
			select {
			case client.Messages <- data:
			default:
			}
		}
		mu.RUnlock()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// typingHandler handles typing indicator notifications
func typingHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	var msg struct {
		From int `json:"from"`
		To   int `json:"to"`
	}

	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Forward typing indicator to recipient
	mu.RLock()
	if client, ok := clients[msg.To]; ok {
		data, _ := json.Marshal(map[string]interface{}{
			"type": "typing",
			"from": msg.From,
		})
		select {
		case client.Messages <- data:
		default:
		}
	}
	mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func main() {
	initDB()

	// API routes
	http.HandleFunc("/api/register", registerHandler)
	http.HandleFunc("/api/login", loginHandler)
	http.HandleFunc("/api/users", getUsersHandler)
	http.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			createGroupHandler(w, r)
		} else {
			getGroupsHandler(w, r)
		}
	})
	http.HandleFunc("/api/messages", getMessagesHandler)
	http.HandleFunc("/api/send", sendMessageHandler)
	http.HandleFunc("/api/typing", typingHandler)
	http.HandleFunc("/api/upload", uploadHandler)
	http.HandleFunc("/events", sseHandler)

	// Serve uploaded files
	http.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("./uploads"))))

	// Serve frontend files
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}

		filePath := "./public" + path
		if _, err := os.Stat(filePath); err == nil {
			http.ServeFile(w, r, filePath)
		} else {
			http.ServeFile(w, r, "./public/index.html")
		}
	})

	fmt.Println("========================================")
	fmt.Println("Chat Server Started!")
	fmt.Println("http://localhost:8080")
	fmt.Println("========================================")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
