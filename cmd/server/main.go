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
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

var (
	db        *sql.DB
	clients   = make(map[int]*Client)
	mu        sync.RWMutex
	jwtSecret = []byte("your-secret-key-change-in-production-12345")
)

// Claims represents JWT claims
type Claims struct {
	UserID   int    `json:"userId"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

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
	ID        int        `json:"id,omitempty"`
	Type      string     `json:"type"`
	Content   string     `json:"content,omitempty"`
	From      int        `json:"from,omitempty"`
	To        int        `json:"to,omitempty"`
	GroupID   int        `json:"groupId,omitempty"`
	MediaURL  string     `json:"mediaUrl,omitempty"`
	MediaType string     `json:"mediaType,omitempty"`
	Latitude  *float64   `json:"latitude,omitempty"`
	Longitude *float64   `json:"longitude,omitempty"`
	Timestamp int64      `json:"timestamp,omitempty"`
	IsRead    bool       `json:"isRead,omitempty"`
	Reactions []Reaction `json:"reactions,omitempty"`
}

// Reaction represents emoji reaction on a message
type Reaction struct {
	ID        int    `json:"id"`
	MessageID int    `json:"messageId"`
	UserID    int    `json:"userId"`
	Emoji     string `json:"emoji"`
	UserName  string `json:"userName,omitempty"`
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
		latitude REAL,
		longitude REAL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)

	// Create message reads table for read receipts
	db.Exec(`CREATE TABLE IF NOT EXISTS message_reads (
		message_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY(message_id, user_id)
	)`)

	// Create message reactions table
	db.Exec(`CREATE TABLE IF NOT EXISTS message_reactions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		message_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		emoji TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(message_id, user_id, emoji)
	)`)

	// Create blocked users table
	db.Exec(`CREATE TABLE IF NOT EXISTS blocked_users (
		blocker_id INTEGER NOT NULL,
		blocked_id INTEGER NOT NULL,
		blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY(blocker_id, blocked_id)
	)`)

	// Create user encryption keys table for E2E encryption
	db.Exec(`CREATE TABLE IF NOT EXISTS user_keys (
		user_id INTEGER PRIMARY KEY,
		public_key TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)

	log.Println("[OK] Database initialized")
}

// hashPassword creates a SHA256 hash of the password
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password + "chat_salt_2024"))
	return hex.EncodeToString(hash[:])
}

// generateJWT creates a new JWT token for user
func generateJWT(userID int, username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// validateJWT validates the JWT token and returns claims
func validateJWT(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// authMiddleware validates JWT from Authorization header
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w)
		if r.Method == "OPTIONS" {
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		_, err := validateJWT(parts[1])
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// enableCORS sets CORS headers for cross-origin requests
func enableCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
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

	// Generate JWT token
	token, err := generateJWT(user.ID, user.Username)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
		"fullName": user.FullName,
		"token":    token,
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
			       latitude, longitude, strftime('%s', timestamp) as ts
			FROM messages 
			WHERE group_id = ?
			ORDER BY timestamp ASC
			LIMIT 100`, groupID)
	} else {
		// Get private messages between two users
		rows, err = db.Query(`
			SELECT id, from_user, to_user, group_id, content, media_url, media_type,
			       latitude, longitude, strftime('%s', timestamp) as ts
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
		var latitude, longitude sql.NullFloat64
		rows.Scan(&id, &m.From, &toUser, &groupIDVal, &content, &mediaURL, &mediaType, &latitude, &longitude, &m.Timestamp)
		m.ID = id
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
		if latitude.Valid {
			lat := latitude.Float64
			m.Latitude = &lat
		}
		if longitude.Valid {
			lon := longitude.Float64
			m.Longitude = &lon
		}
		m.Type = "message"

		// Load reactions for this message
		reactRows, _ := db.Query(`
			SELECT r.id, r.message_id, r.user_id, r.emoji, u.full_name
			FROM message_reactions r
			JOIN users u ON r.user_id = u.id
			WHERE r.message_id = ?
			ORDER BY r.created_at ASC`, id)

		var reactions []Reaction
		for reactRows.Next() {
			var r Reaction
			reactRows.Scan(&r.ID, &r.MessageID, &r.UserID, &r.Emoji, &r.UserName)
			reactions = append(reactions, r)
		}
		reactRows.Close()

		if reactions != nil {
			m.Reactions = reactions
		}

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
	var result sql.Result
	if msg.GroupID > 0 {
		// Group message
		result, _ = db.Exec("INSERT INTO messages (from_user, group_id, content, media_url, media_type, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?, ?)",
			msg.From, msg.GroupID, msg.Content, msg.MediaURL, msg.MediaType, msg.Latitude, msg.Longitude)

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
		// Check if sender is blocked by recipient
		var blockCount int
		db.QueryRow("SELECT COUNT(*) FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?",
			msg.To, msg.From).Scan(&blockCount)

		if blockCount > 0 {
			// User is blocked, don't send message
			http.Error(w, "User has blocked you", http.StatusForbidden)
			return
		}

		// Private message
		result, _ = db.Exec("INSERT INTO messages (from_user, to_user, content, media_url, media_type, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?, ?)",
			msg.From, msg.To, msg.Content, msg.MediaURL, msg.MediaType, msg.Latitude, msg.Longitude)

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

	// Get the message ID
	messageID, _ := result.LastInsertId()
	msg.ID = int(messageID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"messageId": messageID,
	})
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

// onlineUsersHandler returns list of online user IDs
func onlineUsersHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	mu.RLock()
	onlineIDs := make([]int, 0, len(clients))
	for userID := range clients {
		onlineIDs = append(onlineIDs, userID)
	}
	mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(onlineIDs)
}

// blockUserHandler handles blocking a user
func blockUserHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	var req struct {
		BlockerID int `json:"blockerId"`
		BlockedID int `json:"blockedId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("INSERT OR IGNORE INTO blocked_users (blocker_id, blocked_id) VALUES (?, ?)",
		req.BlockerID, req.BlockedID)
	if err != nil {
		http.Error(w, "Failed to block user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "blocked"})
}

// unblockUserHandler handles unblocking a user
func unblockUserHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	var req struct {
		BlockerID int `json:"blockerId"`
		BlockedID int `json:"blockedId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("DELETE FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?",
		req.BlockerID, req.BlockedID)
	if err != nil {
		http.Error(w, "Failed to unblock user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "unblocked"})
}

// getBlockedUsersHandler returns list of blocked users for a user
func getBlockedUsersHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	userID := r.URL.Query().Get("userId")

	rows, err := db.Query("SELECT blocked_id FROM blocked_users WHERE blocker_id = ?", userID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var blockedIDs []int
	for rows.Next() {
		var id int
		rows.Scan(&id)
		blockedIDs = append(blockedIDs, id)
	}

	if blockedIDs == nil {
		blockedIDs = []int{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(blockedIDs)
}

// markMessageReadHandler marks a message as read
func markMessageReadHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	var req struct {
		MessageID int `json:"messageId"`
		UserID    int `json:"userId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("INSERT OR IGNORE INTO message_reads (message_id, user_id) VALUES (?, ?)",
		req.MessageID, req.UserID)
	if err != nil {
		http.Error(w, "Failed to mark as read", http.StatusInternalServerError)
		return
	}

	// Get message details to notify sender
	var fromUser, toUser sql.NullInt64
	db.QueryRow("SELECT from_user, to_user FROM messages WHERE id = ?", req.MessageID).
		Scan(&fromUser, &toUser)

	// Send read receipt notification to message sender
	if fromUser.Valid && int(fromUser.Int64) != req.UserID {
		readNotification := map[string]interface{}{
			"type":      "read_receipt",
			"messageId": req.MessageID,
			"userId":    req.UserID,
		}
		data, _ := json.Marshal(readNotification)

		mu.RLock()
		if client, ok := clients[int(fromUser.Int64)]; ok {
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

// addReactionHandler adds emoji reaction to a message
func addReactionHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	var req struct {
		MessageID int    `json:"messageId"`
		UserID    int    `json:"userId"`
		Emoji     string `json:"emoji"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	result, err := db.Exec("INSERT OR IGNORE INTO message_reactions (message_id, user_id, emoji) VALUES (?, ?, ?)",
		req.MessageID, req.UserID, req.Emoji)
	if err != nil {
		http.Error(w, "Failed to add reaction", http.StatusInternalServerError)
		return
	}

	// Get message details to find recipients
	var fromUser, toUser sql.NullInt64
	var groupID sql.NullInt64
	db.QueryRow("SELECT from_user, to_user, group_id FROM messages WHERE id = ?", req.MessageID).
		Scan(&fromUser, &toUser, &groupID)

	// Broadcast reaction update to relevant users
	reactionUpdate := map[string]interface{}{
		"type":      "reaction",
		"action":    "add",
		"messageId": req.MessageID,
		"userId":    req.UserID,
		"emoji":     req.Emoji,
	}
	data, _ := json.Marshal(reactionUpdate)

	mu.RLock()
	if groupID.Valid {
		// Send to all group members
		rows, _ := db.Query("SELECT user_id FROM group_members WHERE group_id = ?", groupID.Int64)
		for rows.Next() {
			var memberID int
			rows.Scan(&memberID)
			if memberID != req.UserID {
				if client, ok := clients[memberID]; ok {
					select {
					case client.Messages <- data:
					default:
					}
				}
			}
		}
		rows.Close()
	} else if toUser.Valid && fromUser.Valid {
		// Send to both sender and receiver in private chat
		for _, recipientID := range []int{int(fromUser.Int64), int(toUser.Int64)} {
			if recipientID != req.UserID {
				if client, ok := clients[recipientID]; ok {
					select {
					case client.Messages <- data:
					default:
					}
				}
			}
		}
	}
	mu.RUnlock()

	id, _ := result.LastInsertId()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":     id,
		"status": "ok",
	})
}

// removeReactionHandler removes emoji reaction from a message
func removeReactionHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	var req struct {
		MessageID int    `json:"messageId"`
		UserID    int    `json:"userId"`
		Emoji     string `json:"emoji"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("DELETE FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?",
		req.MessageID, req.UserID, req.Emoji)
	if err != nil {
		http.Error(w, "Failed to remove reaction", http.StatusInternalServerError)
		return
	}

	// Get message details to find recipients
	var fromUser, toUser sql.NullInt64
	var groupID sql.NullInt64
	db.QueryRow("SELECT from_user, to_user, group_id FROM messages WHERE id = ?", req.MessageID).
		Scan(&fromUser, &toUser, &groupID)

	// Broadcast reaction update to relevant users
	reactionUpdate := map[string]interface{}{
		"type":      "reaction",
		"action":    "remove",
		"messageId": req.MessageID,
		"userId":    req.UserID,
		"emoji":     req.Emoji,
	}
	data, _ := json.Marshal(reactionUpdate)

	mu.RLock()
	if groupID.Valid {
		// Send to all group members
		rows, _ := db.Query("SELECT user_id FROM group_members WHERE group_id = ?", groupID.Int64)
		for rows.Next() {
			var memberID int
			rows.Scan(&memberID)
			if memberID != req.UserID {
				if client, ok := clients[memberID]; ok {
					select {
					case client.Messages <- data:
					default:
					}
				}
			}
		}
		rows.Close()
	} else if toUser.Valid && fromUser.Valid {
		// Send to both sender and receiver in private chat
		for _, recipientID := range []int{int(fromUser.Int64), int(toUser.Int64)} {
			if recipientID != req.UserID {
				if client, ok := clients[recipientID]; ok {
					select {
					case client.Messages <- data:
					default:
					}
				}
			}
		}
	}
	mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// getMessageReactionsHandler gets all reactions for a message
func getMessageReactionsHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	messageID := r.URL.Query().Get("messageId")

	rows, err := db.Query(`
		SELECT r.id, r.message_id, r.user_id, r.emoji, u.full_name
		FROM message_reactions r
		JOIN users u ON r.user_id = u.id
		WHERE r.message_id = ?
		ORDER BY r.created_at ASC`, messageID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var reactions []Reaction
	for rows.Next() {
		var r Reaction
		rows.Scan(&r.ID, &r.MessageID, &r.UserID, &r.Emoji, &r.UserName)
		reactions = append(reactions, r)
	}

	if reactions == nil {
		reactions = []Reaction{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reactions)
}

// leaveGroupHandler handles user leaving a group
func leaveGroupHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	var req struct {
		GroupID int `json:"groupId"`
		UserID  int `json:"userId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
		req.GroupID, req.UserID)
	if err != nil {
		http.Error(w, "Failed to leave group", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "left"})
}

// removeGroupMemberHandler handles removing a member from group
func removeGroupMemberHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	var req struct {
		GroupID   int `json:"groupId"`
		UserID    int `json:"userId"`
		RemoverID int `json:"removerId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Check if remover is the group creator
	var creatorID int
	err := db.QueryRow("SELECT creator_id FROM groups WHERE id = ?", req.GroupID).Scan(&creatorID)
	if err != nil || creatorID != req.RemoverID {
		http.Error(w, "Only group creator can remove members", http.StatusForbidden)
		return
	}

	_, err = db.Exec("DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
		req.GroupID, req.UserID)
	if err != nil {
		http.Error(w, "Failed to remove member", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "removed"})
}

// getGroupMembersHandler returns members of a group
func getGroupMembersHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	groupID := r.URL.Query().Get("groupId")

	rows, err := db.Query(`
		SELECT u.id, u.username, u.full_name 
		FROM users u 
		JOIN group_members gm ON u.id = gm.user_id 
		WHERE gm.group_id = ?
		ORDER BY u.full_name`, groupID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var members []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.FullName)
		members = append(members, u)
	}

	if members == nil {
		members = []User{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(members)
}

// savePublicKeyHandler saves user's public key for E2E encryption
func savePublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	var req struct {
		UserID    int    `json:"userId"`
		PublicKey string `json:"publicKey"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	_, err := db.Exec(`INSERT INTO user_keys (user_id, public_key, updated_at) 
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id) DO UPDATE SET public_key = ?, updated_at = CURRENT_TIMESTAMP`,
		req.UserID, req.PublicKey, req.PublicKey)
	if err != nil {
		http.Error(w, "Failed to save key", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// getPublicKeyHandler retrieves user's public key
func getPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	userID := r.URL.Query().Get("userId")

	var publicKey string
	err := db.QueryRow("SELECT public_key FROM user_keys WHERE user_id = ?", userID).Scan(&publicKey)
	if err != nil {
		http.Error(w, "Key not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"publicKey": publicKey})
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
	http.HandleFunc("/api/online", onlineUsersHandler)
	http.HandleFunc("/api/block", blockUserHandler)
	http.HandleFunc("/api/unblock", unblockUserHandler)
	http.HandleFunc("/api/blocked", getBlockedUsersHandler)
	http.HandleFunc("/api/group/leave", leaveGroupHandler)
	http.HandleFunc("/api/group/remove", removeGroupMemberHandler)
	http.HandleFunc("/api/group/members", getGroupMembersHandler)
	http.HandleFunc("/api/messages/read", markMessageReadHandler)
	http.HandleFunc("/api/reactions/add", addReactionHandler)
	http.HandleFunc("/api/reactions/remove", removeReactionHandler)
	http.HandleFunc("/api/reactions", getMessageReactionsHandler)
	http.HandleFunc("/api/keys/save", savePublicKeyHandler)
	http.HandleFunc("/api/keys/get", getPublicKeyHandler)
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
